"""Tests for GPO scope ("blast radius") resolution.

The inheritance rules are the subtle part and the easiest thing to get quietly
wrong, so they are tested against a hand-built directory rather than a live one:

  * a link with status bit 1 is disabled and must not apply,
  * a link with status bit 2 is enforced and must survive a block-inheritance
    boundary that stops everything else,
  * `gPOptions` bit 0 blocks inherited non-enforced links,
  * containers that cannot hold a link (e.g. `CN=Computers`) must still inherit,
    which is where the tool this feature was modelled on goes wrong,
  * security filtering must be detected from the Apply Group Policy right,
  * site links must be reported as unresolved rather than guessed at.
"""

import pytest

from group3rpy.ad.gpo import GPO, GPOAttributes
from group3rpy.ad.scope import (
    APPLY_GROUP_POLICY_GUID,
    GpoScope,
    ScopeResolver,
    apply_group_policy_principals,
    dn_depth,
    is_domain_root,
    parent_dn,
    parse_gplink,
)
from group3rpy.sddl.sddl import Sddl, SecurableObjectType

DOMAIN = "DC=corp,DC=local"


def gplink(*entries) -> str:
    """Build a gPLink value from (guid, status) pairs."""
    return "".join(
        f"[LDAP://cn={guid},cn=policies,cn=system,{DOMAIN};{status}]"
        for guid, status in entries
    )


class FakeEntry:
    def __init__(self, attributes):
        self._attributes = attributes
        self.distinguished_name = attributes.get("distinguishedName", "")

    def get_property(self, name):
        for key, value in self._attributes.items():
            if key.lower() == name.lower():
                return value
        return None

    def get_property_as_array(self, name):
        value = self.get_property(name)
        return [value] if value else []

    def get_sid(self):
        return self.get_property("objectSid")


class FakeSearch:
    """Minimal stand-in for DirectorySearch, driven by canned result sets."""

    def __init__(self, containers=None, computers=None, users=None, sites=None):
        self.base_dn = DOMAIN
        self.containers = containers or []
        self.computers = computers or []
        self.users = users or []
        self.sites = sites or []

    def query_ldap(self, ldap_filter, attributes, search_base=None, **kwargs):
        if "objectClass=site" in ldap_filter:
            return [FakeEntry(entry) for entry in self.sites]
        if "organizationalUnit" in ldap_filter:
            return [FakeEntry(entry) for entry in self.containers]
        if "objectCategory=computer" in ldap_filter:
            return [FakeEntry(entry) for entry in self.computers]
        if "objectCategory=person" in ldap_filter:
            return [FakeEntry(entry) for entry in self.users]
        return []


def make_gpo(guid, name="GPO", computer=True, user=True, sddl=None):
    gpo = GPO()
    gpo.attributes = GPOAttributes(
        uid=guid,
        display_name=name,
        computer_policy_enabled=computer,
        user_policy_enabled=user,
        nt_security_descriptor_sddl=sddl,
    )
    return gpo


# ------------------------------------------------------------------- DN helpers


def test_dn_helpers():
    assert parent_dn("CN=A,OU=B,DC=corp,DC=local") == "OU=B,DC=corp,DC=local"
    assert parent_dn("DC=local") is None
    assert dn_depth("CN=A,OU=B,DC=corp,DC=local") == 4
    assert is_domain_root("DC=corp,DC=local")
    assert not is_domain_root("OU=X,DC=corp,DC=local")
    # Escaped commas inside an RDN must not split the DN.
    assert parent_dn("CN=Smith\\, Bob,OU=B,DC=corp,DC=local") == "OU=B,DC=corp,DC=local"


# ---------------------------------------------------------------- gPLink parsing


def test_parse_gplink_status_bits():
    value = gplink(("{AAAAAAAA-0000-0000-0000-000000000001}", 0),
                   ("{AAAAAAAA-0000-0000-0000-000000000002}", 1),
                   ("{AAAAAAAA-0000-0000-0000-000000000003}", 2),
                   ("{AAAAAAAA-0000-0000-0000-000000000004}", 3))
    links = parse_gplink(value, "OU=X," + DOMAIN, "ou")
    assert [l.gpo_guid[-3:-1] for l in links] == ["01", "02", "03", "04"]
    assert [(l.disabled, l.enforced) for l in links] == [
        (False, False),  # 0 = enabled, unenforced
        (True, False),   # 1 = disabled
        (False, True),   # 2 = enforced
        (True, True),    # 3 = disabled and enforced
    ]
    assert links[0].status_text == "Enabled, Unenforced"
    assert links[2].status_text == "Enabled, Enforced"


def test_parse_gplink_tolerates_junk():
    assert parse_gplink(None, "OU=X", "ou") == []
    assert parse_gplink("", "OU=X", "ou") == []
    # No GUID in the DN -> skipped rather than crashing.
    assert parse_gplink("[LDAP://cn=nonsense;0]", "OU=X", "ou") == []


# ------------------------------------------------------------------ inheritance


GUID_DOMAIN = "{11111111-1111-1111-1111-111111111111}"
GUID_OU = "{22222222-2222-2222-2222-222222222222}"
GUID_ENFORCED = "{33333333-3333-3333-3333-333333333333}"
GUID_DISABLED = "{44444444-4444-4444-4444-444444444444}"


@pytest.fixture
def resolved():
    """A small directory exercising every inheritance rule at once.

    DC=corp,DC=local          links GUID_DOMAIN (normal) + GUID_ENFORCED (enforced)
      OU=Normal               no links, inherits both
      OU=Blocked              gPOptions=1, so only the enforced one survives
      OU=Links                links GUID_OU, plus GUID_DISABLED (disabled)
      CN=Computers            a plain container: cannot hold a link, must inherit
    """
    containers = [
        {
            "distinguishedName": DOMAIN,
            "gPLink": gplink((GUID_DOMAIN, 0), (GUID_ENFORCED, 2)),
            "gPOptions": "0",
        },
        {"distinguishedName": f"OU=Normal,{DOMAIN}", "gPLink": "", "gPOptions": "0"},
        {"distinguishedName": f"OU=Blocked,{DOMAIN}", "gPLink": "", "gPOptions": "1"},
        {
            "distinguishedName": f"OU=Links,{DOMAIN}",
            "gPLink": gplink((GUID_OU, 0), (GUID_DISABLED, 1)),
            "gPOptions": "0",
        },
    ]
    computers = [
        {"distinguishedName": f"CN=N1,OU=Normal,{DOMAIN}"},
        {"distinguishedName": f"CN=B1,OU=Blocked,{DOMAIN}"},
        {"distinguishedName": f"CN=L1,OU=Links,{DOMAIN}"},
        # Deliberately in a container that has no gPLink of its own.
        {"distinguishedName": f"CN=C1,CN=Computers,{DOMAIN}"},
    ]
    search = FakeSearch(containers=containers, computers=computers)
    resolver = ScopeResolver(search)
    resolver.collect()
    gpos = [
        make_gpo(GUID_DOMAIN, "Domain policy"),
        make_gpo(GUID_OU, "OU policy"),
        make_gpo(GUID_ENFORCED, "Enforced policy"),
        make_gpo(GUID_DISABLED, "Disabled link policy"),
    ]
    return resolver.resolve(gpos)


def test_domain_linked_gpo_reaches_unblocked_machines(resolved):
    scope = resolved[GUID_DOMAIN]
    names = {dn.split(",")[0] for dn in scope.affected_computers}
    assert "CN=N1" in names
    assert "CN=L1" in names
    # CN=Computers cannot hold a link but must still inherit the domain policy.
    assert "CN=C1" in names, (
        "a machine in a link-free container must still inherit domain policy"
    )
    # Blocked OU stops non-enforced inheritance.
    assert "CN=B1" not in names


def test_enforced_gpo_pierces_block_inheritance(resolved):
    scope = resolved[GUID_ENFORCED]
    names = {dn.split(",")[0] for dn in scope.affected_computers}
    assert names == {"CN=N1", "CN=B1", "CN=L1", "CN=C1"}, (
        "an enforced link must apply even where inheritance is blocked"
    )
    assert scope.enforced_anywhere


def test_ou_linked_gpo_only_reaches_that_ou(resolved):
    scope = resolved[GUID_OU]
    assert [dn.split(",")[0] for dn in scope.affected_computers] == ["CN=L1"]


def test_disabled_link_applies_to_nothing(resolved):
    scope = resolved[GUID_DISABLED]
    assert scope.affected_computers == []
    assert scope.all_links_disabled
    assert any("link" in note.lower() for note in scope.notes)


def test_orphaned_gpo_is_flagged():
    search = FakeSearch(
        containers=[{"distinguishedName": DOMAIN, "gPLink": "", "gPOptions": "0"}],
        computers=[{"distinguishedName": f"CN=X,{DOMAIN}"}],
    )
    resolver = ScopeResolver(search)
    resolver.collect()
    scopes = resolver.resolve([make_gpo("{99999999-9999-9999-9999-999999999999}")])
    scope = scopes["{99999999-9999-9999-9999-999999999999}"]
    assert scope.is_orphaned
    assert not scope.is_linked
    assert scope.affected_computers == []
    assert any("not linked" in note.lower() for note in scope.notes)


def test_computer_policy_disabled_means_no_computers():
    search = FakeSearch(
        containers=[{"distinguishedName": DOMAIN, "gPLink": gplink((GUID_DOMAIN, 0)), "gPOptions": "0"}],
        computers=[{"distinguishedName": f"CN=X,{DOMAIN}"}],
    )
    resolver = ScopeResolver(search)
    resolver.collect()
    scopes = resolver.resolve([make_gpo(GUID_DOMAIN, computer=False)])
    scope = scopes[GUID_DOMAIN]
    assert scope.affected_computers == []
    assert any("computer policy is disabled" in n.lower() for n in scope.notes)


def test_users_are_only_enumerated_on_request():
    containers = [{"distinguishedName": DOMAIN, "gPLink": gplink((GUID_DOMAIN, 0)), "gPOptions": "0"}]
    users = [{"distinguishedName": f"CN=U1,{DOMAIN}"}]
    search = FakeSearch(containers=containers, users=users)

    off = ScopeResolver(search, include_users=False)
    off.collect()
    assert off.resolve([make_gpo(GUID_DOMAIN)])[GUID_DOMAIN].affected_users == []

    on = ScopeResolver(search, include_users=True)
    on.collect()
    assert on.resolve([make_gpo(GUID_DOMAIN)])[GUID_DOMAIN].affected_users == [
        f"CN=U1,{DOMAIN}"
    ]


def test_site_links_are_reported_as_unresolved():
    site_dn = f"CN=HQ,CN=Sites,CN=Configuration,{DOMAIN}"
    search = FakeSearch(
        containers=[{"distinguishedName": DOMAIN, "gPLink": "", "gPOptions": "0"}],
        computers=[{"distinguishedName": f"CN=X,{DOMAIN}"}],
        sites=[{"distinguishedName": site_dn, "gPLink": gplink((GUID_DOMAIN, 0))}],
    )
    resolver = ScopeResolver(search)
    resolver.collect()
    scope = resolver.resolve([make_gpo(GUID_DOMAIN)])[GUID_DOMAIN]
    assert scope.site_links == [site_dn]
    assert scope.has_unresolved_scope
    # A site link must not silently claim machines.
    assert scope.affected_computers == []
    assert any("site" in note.lower() for note in scope.notes)


# ------------------------------------------------------------ security filtering


def test_apply_group_policy_default_is_not_narrowed():
    sddl = Sddl(
        f"O:BAG:BAD:(OA;CI;CR;{APPLY_GROUP_POLICY_GUID};;S-1-5-11)",
        SecurableObjectType.DirectoryServiceObject,
    )
    principals = apply_group_policy_principals(sddl)
    assert [t.sid for t in principals] == ["S-1-5-11"]

    scope = GpoScope(guid="{x}", security_filter_principals=principals)
    assert not scope.security_filtering_narrowed


def test_apply_group_policy_restricted_to_a_group_is_narrowed():
    sddl = Sddl(
        f"O:BAG:BAD:(OA;CI;CR;{APPLY_GROUP_POLICY_GUID};;S-1-5-21-1-2-3-1105)",
        SecurableObjectType.DirectoryServiceObject,
    )
    principals = apply_group_policy_principals(sddl)
    assert [t.sid for t in principals] == ["S-1-5-21-1-2-3-1105"]
    assert GpoScope(guid="{x}", security_filter_principals=principals).security_filtering_narrowed


def test_full_control_implies_apply_group_policy():
    """GENERIC_ALL confers every extended right, so it must count."""
    sddl = Sddl("O:BAG:BAD:(A;;GA;;;S-1-5-11)", SecurableObjectType.DirectoryServiceObject)
    principals = apply_group_policy_principals(sddl)
    assert "S-1-5-11" in [t.sid for t in principals]


def test_read_without_apply_group_policy_does_not_count():
    sddl = Sddl("O:BAG:BAD:(A;;RPLCLORC;;;S-1-5-11)", SecurableObjectType.DirectoryServiceObject)
    assert apply_group_policy_principals(sddl) == []


def test_no_descriptor_is_not_treated_as_narrowed():
    scope = GpoScope(guid="{x}", security_filter_principals=[])
    assert not scope.security_filtering_narrowed


def test_narrowed_filter_is_noted_but_still_reports_link_scope():
    sddl = Sddl(
        f"O:BAG:BAD:(OA;CI;CR;{APPLY_GROUP_POLICY_GUID};;S-1-5-21-1-2-3-1105)",
        SecurableObjectType.DirectoryServiceObject,
    )
    search = FakeSearch(
        containers=[{"distinguishedName": DOMAIN, "gPLink": gplink((GUID_DOMAIN, 0)), "gPOptions": "0"}],
        computers=[{"distinguishedName": f"CN=X{i},{DOMAIN}"} for i in range(3)],
    )
    resolver = ScopeResolver(search)
    resolver.collect()
    scope = resolver.resolve([make_gpo(GUID_DOMAIN, sddl=sddl)])[GUID_DOMAIN]
    # The link scope is still reported -- narrowing is surfaced as a caveat, not
    # as a silent removal, because we cannot resolve group membership here.
    assert len(scope.affected_computers) == 3
    assert scope.security_filtering_narrowed
    assert any("security filtering" in note.lower() for note in scope.notes)


def test_summary_is_human_readable():
    assert "not linked" in GpoScope(guid="{x}").summary()
