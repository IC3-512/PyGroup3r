"""Pins the corrected `gPLink` status decoding -- DIVERGENCES.md section 1.11.

This is the one deliberate behavioural divergence from upstream Group3r. The
`gPLink` status field is a bitmask (bit 0 = link disabled, bit 1 = enforced), but
`LibSnaffle/ActiveDirectory/ActiveDirectory.cs:280-294` swaps the
enabled/disabled half of statuses 2 and 3. Because `NiceGpoPrinter` gates
`-e/--enabled` on `"Enabled" in link_enforced`, upstream's mapping hides a GPO
whose link is genuinely enabled *and* enforced.

Found against a live GOAD domain on 2026-09-28: `essos.local`'s `ansible-laps`
GPO is linked with status `2` and vanished from `-e` output.
"""

import pytest

from group3rpy.ad.active_directory import ActiveDirectory
from group3rpy.ad.gpo import GPO
from group3rpy.ad.ldap_search import SearchResultEntry

POLICY_DN = "CN={1690CD71-AB54-43CC-A163-7335F4AA7EBD},CN=Policies,CN=System,DC=essos,DC=local"
CONTAINER_DN = "OU=Laps,DC=essos,DC=local"


class _FakeSearch:
    """Stands in for DirectorySearch, returning one container with one gPLink."""

    def __init__(self, gplink: str):
        self._gplink = gplink

    def query_ldap(self, ldap_filter, attributes, **kwargs):
        return [
            SearchResultEntry(
                CONTAINER_DN,
                {"gPLink": [self._gplink.encode()]},
            )
        ]


def _link_label_for(status: str) -> str:
    """Run the real link enumeration for one `gPLink` status and return its label."""
    gpo = GPO()
    gpo.attributes.distinguished_name = POLICY_DN

    ad = ActiveDirectory(_FakeSearch(f"[LDAP://{POLICY_DN};{status}]"))
    ad.gpos = [gpo]
    ad.enumerate_domain_gpo_links()

    assert len(gpo.attributes.gpo_links) == 1, f"status {status} produced no link"
    assert gpo.attributes.gpo_links[0].link_path == CONTAINER_DN
    return gpo.attributes.gpo_links[0].link_enforced


@pytest.mark.parametrize(
    "status, expected",
    [
        ("0", "Enabled, Unenforced"),
        ("1", "Disabled, Unenforced"),
        # The two upstream gets backwards.
        ("2", "Enabled, Enforced"),
        ("3", "Disabled, Enforced"),
    ],
)
def test_gplink_status_decodes_as_a_bitmask(status, expected):
    assert _link_label_for(status) == expected, (
        f"gPLink status {status} must decode as a bitmask (bit 0 = disabled, "
        f"bit 1 = enforced). Upstream swaps 2 and 3; see DIVERGENCES.md 1.11."
    )


def test_enforced_link_survives_the_enabled_filter():
    """The reason the fix matters: `-e/--enabled` keys off the word "Enabled".

    `NiceGpoPrinter` keeps a GPO only when some link label contains "Enabled"
    (`view/nice_gpo_printer.py:137`). Under upstream's mapping a status 2 link
    reads "Disabled, Enforced", so a GPO that really is enabled and enforced is
    suppressed entirely.
    """
    assert "Enabled" in _link_label_for("2")
    assert "Enabled" not in _link_label_for("3")
