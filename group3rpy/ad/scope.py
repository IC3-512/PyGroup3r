"""GPO scope ("blast radius") resolution.

ADDITION: not part of the original Group3r, which collects a GPO's `gPLink`
values and prints them as raw link paths without ever resolving them to affected
machines. Group3r even requests `gPOptions` in its link query and then discards it,
so block-inheritance is fetched and thrown away.

Knowing the blast radius changes triage completely: a Black finding on an unlinked
GPO is noise, while the same finding on a GPO reaching every server is the whole
engagement. Nothing here feeds the `nice` or `json` printers -- they stay
byte-identical to the original -- it is consumed by the HTML report and the
BloodHound export.

What is resolved
----------------
* `gPLink` parsing, including the per-link status bits (1 = link disabled,
  2 = enforced).
* `gPOptions` block-inheritance on each container.
* Enforced links, which flow past a block-inheritance boundary.
* The full container tree, including plain `container` objects such as
  `CN=Computers` that cannot have a GPO linked but still inherit one. (gpoParser
  misses these because it only builds objects for containers that have a gPLink,
  so machines in `CN=Computers` or in a link-free OU appear to have no policy.)
* Security filtering: a GPO only applies to principals granted the Apply Group
  Policy extended right, so a GPO filtered to one group does not really hit every
  machine under its link.
* WMI filters, reported as "scope may be narrower" rather than silently ignored.
* Site links, reported as unresolved -- mapping machines to sites needs the
  subnet-to-site table, so claiming a machine list there would be a guess.

What is deliberately NOT claimed
--------------------------------
Precedence. Which GPO *wins* when two set the same value depends on link order
semantics plus container depth; this module records each link's index and flags
without asserting a winner, because blast radius only needs set membership and an
unverified precedence claim would be worse than none.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .trustee import Trustee

# The Apply-Group-Policy control access right. A GPO applies to a principal only
# when the principal is granted this extended right (plus read) on the GPO object.
APPLY_GROUP_POLICY_GUID = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"

# Principals that mean "no meaningful security filtering" -- the out-of-the-box
# state. Anything else narrows the scope below what the link implies.
DEFAULT_FILTER_PRINCIPALS = {
    "S-1-5-11",  # Authenticated Users
    "S-1-1-0",  # Everyone
}

# gPLink is a concatenation of [LDAP://<dn>;<status>] entries.
_GPLINK = re.compile(r"\[LDAP://(?P<dn>[^;\]]+);(?P<status>\d+)\]", re.IGNORECASE)
_GUID_IN_DN = re.compile(r"\{[0-9A-Fa-f-]{36}\}")

LINK_DISABLED = 1
LINK_ENFORCED = 2


@dataclass
class GpoLinkRef:
    """One link between a container and a GPO."""

    gpo_guid: str
    container_dn: str
    container_kind: str
    link_index: int
    disabled: bool
    enforced: bool

    @property
    def status_text(self) -> str:
        """The same wording Group3r's printer uses for LinkEnforced."""
        state = "Disabled" if self.disabled else "Enabled"
        enforcement = "Enforced" if self.enforced else "Unenforced"
        return f"{state}, {enforcement}"


@dataclass
class Container:
    """A domain, OU, generic container, or site."""

    dn: str
    kind: str = "container"
    block_inheritance: bool = False
    own_links: List[GpoLinkRef] = field(default_factory=list)
    computers: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    # Links in effect here, own plus inherited.
    effective_links: List[GpoLinkRef] = field(default_factory=list)

    @property
    def parent_dn(self) -> Optional[str]:
        return parent_dn(self.dn)


@dataclass
class GpoScope:
    """Everything known about where one GPO lands."""

    guid: str
    display_name: Optional[str] = None
    links: List[GpoLinkRef] = field(default_factory=list)
    computer_policy_enabled: bool = True
    user_policy_enabled: bool = True
    wmi_filter: Optional[str] = None
    security_filter_principals: List[Trustee] = field(default_factory=list)
    affected_computers: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    site_links: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def is_linked(self) -> bool:
        return bool(self.links)

    @property
    def is_orphaned(self) -> bool:
        """Linked nowhere, so it cannot apply to anything."""
        return not self.links

    @property
    def all_links_disabled(self) -> bool:
        return bool(self.links) and all(link.disabled for link in self.links)

    @property
    def enforced_anywhere(self) -> bool:
        return any(link.enforced and not link.disabled for link in self.links)

    @property
    def security_filtering_narrowed(self) -> bool:
        """True when Apply Group Policy is restricted below the default."""
        if not self.security_filter_principals:
            # Nothing granted Apply Group Policy at all, or no descriptor read.
            return False
        sids = {
            (trustee.sid or "").upper()
            for trustee in self.security_filter_principals
            if trustee.sid
        }
        if not sids:
            return False
        return not (sids & {s.upper() for s in DEFAULT_FILTER_PRINCIPALS})

    @property
    def affected_computer_count(self) -> int:
        return len(self.affected_computers)

    @property
    def has_unresolved_scope(self) -> bool:
        """True when the real reach may be wider or narrower than computed."""
        return bool(self.site_links) or self.wmi_filter is not None

    def summary(self) -> str:
        if self.is_orphaned:
            return "not linked to any container"
        if self.all_links_disabled:
            return f"all {len(self.links)} link(s) disabled"
        parts = [f"{self.affected_computer_count} computer(s)"]
        if self.affected_users:
            parts.append(f"{len(self.affected_users)} user(s)")
        if self.enforced_anywhere:
            parts.append("enforced")
        if self.security_filtering_narrowed:
            parts.append("security-filtered")
        if self.wmi_filter:
            parts.append("WMI-filtered")
        if self.site_links:
            parts.append(f"{len(self.site_links)} site link(s) unresolved")
        return ", ".join(parts)


# ----------------------------------------------------------------- DN utilities


def split_dn(dn: str) -> List[str]:
    """Split a DN on unescaped commas."""
    return re.split(r"(?<!\\),", dn)


def parent_dn(dn: str) -> Optional[str]:
    parts = split_dn(dn)
    return ",".join(parts[1:]) if len(parts) > 1 else None


def dn_depth(dn: str) -> int:
    return len(split_dn(dn))


def is_domain_root(dn: str) -> bool:
    return all(part.strip().upper().startswith("DC=") for part in split_dn(dn))


def parse_gplink(gplink: Optional[str], container_dn: str, kind: str) -> List[GpoLinkRef]:
    """Parse a `gPLink` attribute into link records.

    Status bit 1 means the link is disabled, bit 2 means enforced.
    """
    links: List[GpoLinkRef] = []
    if not gplink:
        return links
    for index, match in enumerate(_GPLINK.finditer(gplink)):
        guid_match = _GUID_IN_DN.search(match.group("dn"))
        if guid_match is None:
            continue
        try:
            status = int(match.group("status"))
        except ValueError:
            status = 0
        links.append(
            GpoLinkRef(
                gpo_guid=guid_match.group(0).upper(),
                container_dn=container_dn,
                container_kind=kind,
                link_index=index,
                disabled=bool(status & LINK_DISABLED),
                enforced=bool(status & LINK_ENFORCED),
            )
        )
    return links


# ------------------------------------------------------------- security filters


def apply_group_policy_principals(parsed_sddl, resolver=None) -> List[Trustee]:
    """Principals granted the Apply Group Policy extended right on a GPO.

    Matches allow ACEs whose object GUID is the Apply-Group-Policy right. An ACE
    granting broad control (GENERIC_ALL / ALL_ACCESS, i.e. no object GUID) also
    confers it, so those count too.
    """
    principals: List[Trustee] = []
    if parsed_sddl is None:
        return principals

    dacl = getattr(parsed_sddl, "dacl", None)
    aces = getattr(dacl, "aces", None) if dacl is not None else None
    if not aces:
        return principals

    seen: Set[str] = set()
    for ace in aces:
        if ace.ace_type not in ("ACCESS_ALLOWED", "OBJECT_ACCESS_ALLOWED"):
            continue
        rights = set(ace.rights or [])
        guid = (ace.object_guid or "").lower()

        grants = False
        if guid == APPLY_GROUP_POLICY_GUID and "CONTROL_ACCESS" in rights:
            grants = True
        elif not guid and rights & {"GENERIC_ALL", "ALL_ACCESS"}:
            # Full control implies every extended right.
            grants = True
        if not grants:
            continue

        sid = getattr(ace.ace_sid, "raw", None)
        alias = getattr(ace.ace_sid, "alias", None)
        key = (sid or alias or "").upper()
        if key in seen:
            continue
        seen.add(key)
        principals.append(Trustee(sid=sid, display_name=alias))

    return principals


# -------------------------------------------------------------------- resolver


class ScopeResolver:
    """Builds the container tree and resolves each GPO's reach."""

    def __init__(self, directory_search, logger=None, include_users: bool = False):
        self._search = directory_search
        self.mq = logger
        self.include_users = include_users
        self.containers: Dict[str, Container] = {}

    # -- logging shims --------------------------------------------------------

    def _trace(self, message: str) -> None:
        if self.mq is not None:
            self.mq.trace(message)

    def _degub(self, message: str) -> None:
        if self.mq is not None:
            self.mq.degub(message)

    def _error(self, message: str) -> None:
        if self.mq is not None:
            self.mq.error(message)

    # -- collection -----------------------------------------------------------

    def collect(self) -> None:
        """Query containers, sites and objects, then build the tree."""
        self._collect_containers()
        self._collect_sites()
        self._collect_objects()
        self._build_tree()

    def _ensure(self, dn: str, kind: Optional[str] = None) -> Container:
        key = dn.upper()
        container = self.containers.get(key)
        if container is None:
            container = Container(dn=dn, kind=kind or "container")
            self.containers[key] = container
        elif kind is not None and container.kind == "container":
            container.kind = kind
        return container

    def _collect_containers(self) -> None:
        ldap_filter = (
            "(|(objectClass=organizationalUnit)(objectClass=domainDNS)(objectClass=domain))"
        )
        entries = self._search.query_ldap(
            ldap_filter, ["distinguishedName", "gPLink", "gPOptions"]
        )
        self._trace(f"{len(entries)} containers found for scope resolution.")
        for entry in entries:
            dn = entry.get_property("distinguishedName")
            if not dn:
                continue
            kind = "domain" if is_domain_root(dn) else "ou"
            container = self._ensure(dn, kind)
            gpoptions = entry.get_property("gPOptions")
            # gPOptions bit 0 set means "block policy inheritance".
            try:
                container.block_inheritance = bool(int(gpoptions or 0) & 1)
            except ValueError:
                container.block_inheritance = False
            container.own_links = parse_gplink(entry.get_property("gPLink"), dn, kind)

    def _collect_sites(self) -> None:
        """Site links live in the Configuration NC, under CN=Sites."""
        base = getattr(self._search, "base_dn", "") or ""
        if not base:
            return
        config_base = f"CN=Sites,CN=Configuration,{base}"
        try:
            entries = self._search.query_ldap(
                "(objectClass=site)",
                ["distinguishedName", "gPLink", "gPOptions"],
                search_base=config_base,
            )
        except Exception as exc:
            self._degub(f"Could not enumerate sites for scope resolution: {exc}")
            return

        for entry in entries:
            dn = entry.get_property("distinguishedName")
            if not dn:
                continue
            container = self._ensure(dn, "site")
            container.own_links = parse_gplink(entry.get_property("gPLink"), dn, "site")

    def _collect_objects(self) -> None:
        computers = self._search.query_ldap(
            "(objectCategory=computer)", ["distinguishedName"]
        )
        self._trace(f"{len(computers)} computers found for scope resolution.")
        for entry in computers:
            dn = entry.get_property("distinguishedName")
            if not dn:
                continue
            holder = parent_dn(dn)
            if holder:
                self._ensure(holder).computers.append(dn)

        if not self.include_users:
            return
        users = self._search.query_ldap(
            "(&(objectCategory=person)(objectClass=user))", ["distinguishedName"]
        )
        self._trace(f"{len(users)} users found for scope resolution.")
        for entry in users:
            dn = entry.get_property("distinguishedName")
            if not dn:
                continue
            holder = parent_dn(dn)
            if holder:
                self._ensure(holder).users.append(dn)

    def _build_tree(self) -> None:
        """Create any missing ancestors, then propagate links down the tree."""
        # Synthesise ancestors so that e.g. CN=Computers,DC=x inherits the domain.
        for dn in list(self.containers):
            current = self.containers[dn].dn
            while True:
                parent = parent_dn(current)
                if not parent or parent.upper() in self.containers:
                    break
                if not parent.upper().startswith(("OU=", "CN=", "DC=")):
                    break
                self._ensure(parent, "domain" if is_domain_root(parent) else "container")
                current = parent

        # Root-down pass, so a parent's effective set is final before its children.
        ordered = sorted(self.containers.values(), key=lambda c: dn_depth(c.dn))
        for container in ordered:
            if container.kind == "site":
                # Sites are not part of the DN hierarchy; their links are handled
                # separately because machine membership is not derivable here.
                container.effective_links = list(container.own_links)
                continue

            inherited: List[GpoLinkRef] = []
            parent_key = (container.parent_dn or "").upper()
            parent = self.containers.get(parent_key)
            if parent is not None and parent.kind != "site":
                if container.block_inheritance:
                    # Only enforced links survive a block-inheritance boundary.
                    inherited = [
                        link for link in parent.effective_links if link.enforced
                    ]
                else:
                    inherited = list(parent.effective_links)

            own = [link for link in container.own_links if not link.disabled]
            container.effective_links = own + inherited

    # -- resolution -----------------------------------------------------------

    def resolve(self, gpos: Iterable, sid_resolver=None) -> Dict[str, GpoScope]:
        """Produce a GpoScope per GPO.

        `gpos` is an iterable of objects exposing `.attributes` (a GPOAttributes),
        i.e. the GPO list the rest of Group3r already works with.
        """
        scopes: Dict[str, GpoScope] = {}

        # Index links and machines by GPO guid.
        links_by_gpo: Dict[str, List[GpoLinkRef]] = {}
        computers_by_gpo: Dict[str, Set[str]] = {}
        users_by_gpo: Dict[str, Set[str]] = {}
        sites_by_gpo: Dict[str, List[str]] = {}

        for container in self.containers.values():
            for link in container.own_links:
                links_by_gpo.setdefault(link.gpo_guid, []).append(link)
                if container.kind == "site":
                    sites_by_gpo.setdefault(link.gpo_guid, []).append(container.dn)
            for link in container.effective_links:
                if container.kind == "site":
                    continue
                if container.computers:
                    computers_by_gpo.setdefault(link.gpo_guid, set()).update(
                        container.computers
                    )
                if container.users:
                    users_by_gpo.setdefault(link.gpo_guid, set()).update(container.users)

        for gpo in gpos:
            attributes = gpo.attributes
            guid = (attributes.uid or "").upper()
            if not guid:
                continue

            scope = GpoScope(
                guid=guid,
                display_name=attributes.display_name,
                links=sorted(
                    links_by_gpo.get(guid, []),
                    key=lambda link: (dn_depth(link.container_dn), link.link_index),
                ),
                computer_policy_enabled=attributes.computer_policy_enabled,
                user_policy_enabled=attributes.user_policy_enabled,
                site_links=sites_by_gpo.get(guid, []),
            )

            scope.security_filter_principals = apply_group_policy_principals(
                attributes.nt_security_descriptor_sddl, sid_resolver
            )

            if attributes.computer_policy_enabled:
                scope.affected_computers = sorted(computers_by_gpo.get(guid, set()))
            else:
                scope.notes.append(
                    "Computer policy is disabled on this GPO, so its computer "
                    "settings do not apply."
                )
            if attributes.user_policy_enabled:
                scope.affected_users = sorted(users_by_gpo.get(guid, set()))
            elif self.include_users:
                scope.notes.append(
                    "User policy is disabled on this GPO, so its user settings do "
                    "not apply."
                )

            if scope.is_orphaned:
                scope.notes.append(
                    "This GPO is not linked to any container, so it currently "
                    "applies to nothing."
                )
            elif scope.all_links_disabled:
                scope.notes.append(
                    "Every link to this GPO is disabled, so it currently applies to "
                    "nothing."
                )
            if scope.security_filtering_narrowed:
                names = ", ".join(
                    t.display_name or t.sid or "?"
                    for t in scope.security_filter_principals
                )
                scope.notes.append(
                    "Security filtering restricts this GPO to: "
                    + names
                    + ". The affected list above is the link scope and may be wider "
                    "than what actually applies."
                )
            if scope.site_links:
                scope.notes.append(
                    "Linked to "
                    + str(len(scope.site_links))
                    + " site(s); machines in a site cannot be enumerated without the "
                    "subnet-to-site mapping, so those are not counted."
                )
            if not self.include_users:
                scope.notes.append(
                    "User scope was not enumerated (use --scope-users)."
                )

            scopes[guid] = scope

        return scopes

    def attach_wmi_filters(self, scopes: Dict[str, GpoScope], gpos: Iterable) -> None:
        """Record `gPCWQLFilter` so a narrowed scope is visible, not silent."""
        for gpo in gpos:
            guid = (gpo.attributes.uid or "").upper()
            scope = scopes.get(guid)
            if scope is None:
                continue
            wmi = getattr(gpo.attributes, "wmi_filter", None)
            if wmi:
                scope.wmi_filter = wmi
                scope.notes.append(
                    "A WMI filter is attached, so this GPO may apply to fewer "
                    "machines than listed."
                )
