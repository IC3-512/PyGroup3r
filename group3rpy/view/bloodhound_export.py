"""BloodHound attack-path export: a JSON payload plus reviewable Cypher.

This is an ADDITION to Group3r, not a port -- the `nice` and `json` printers stay
byte-identical to the original. It turns parsed GPO settings plus the resolved
blast radius (`group3rpy/ad/scope.py`) into attack-path edges an operator can feed
into BloodHound.

Why files and not a Neo4j connection
------------------------------------
The obvious design (and what synacktiv/gpoParser does) is to open a bolt session
and run `CREATE`. That is rejected here for three reasons:

* `CREATE` is not idempotent, so a second run silently doubles every edge;
* it mutates the client's BloodHound database with no undo;
* once inside, injected edges are indistinguishable from collected ones, so the
  operator can no longer tell a derived claim from a measured fact.

So this module writes two artefacts and stops:

* `<prefix>.json`   -- machine-readable, for ingest tooling.
* `<prefix>.cypher` -- human-readable, `MERGE`-only, provenance-stamped, with a
  commented-out rollback query at the top. The operator reads it, then runs it.

Cypher safety properties (deliberate, please keep them)
------------------------------------------------------
* **No node is ever created.** Every statement is `MATCH` on both endpoints and
  `MERGE` only on the relationship, so a principal or computer that BloodHound
  never collected produces zero rows instead of a phantom node.
* **`MERGE`, never `CREATE`**, so re-running the file is a no-op.
* **Provenance on creation only.** A relationship we create gets
  `r.source = 'group3rpy'` plus the GPO guid, GPO display name and the sysvol path
  the setting came from. If `MERGE` instead *matches* an edge BloodHound already
  collected, the provenance is **not** written to it -- only a `r.group3rpySeen`
  marker is added. Otherwise the rollback query below would delete genuine
  collected edges, which would be far worse than emitting nothing.
* **Everything is escaped.** A GPO display name can contain quotes and
  backslashes; `_cypher_string` escapes `\\`, `'`, `"`, and the CR/LF/tab trio.
* Relationship kinds are checked against an identifier regex before being
  interpolated as a label, because a label cannot be escaped.

Honesty rules baked into the derivation
---------------------------------------
* **A GPO that cannot apply produces no edges.** Orphaned, every link disabled,
  or computer policy disabled -> nothing, whatever the setting says.
* **Security filtering and WMI filters do not silence an edge, they qualify it.**
  Those edges carry `uncertain: true` and a `reason`, because the real scope is
  narrower than the link scope and this module cannot say by how much.
* **Unidentifiable principals are dropped, not guessed.** No name and no SID, a
  GPP variable such as `%LogonUser%`, or the `SID Resolution Failed` placeholder
  with no SID beside it -> skipped and counted.
* **User-branch settings are skipped**, because a GPP Groups.xml under `\\User\\`
  applies wherever its users log on, and that machine set is not derivable from
  the link scope. Counted as `user_scoped_setting`.
* Privilege rights are classified from `group3rpy/options/priv_rights.py`
  (`local_privesc` / `grants_remote_access`), not from a list invented here; a
  right that is in neither category, or is absent from that table, produces
  nothing.

OpenGraph schema assumptions -- UNVERIFIED, CHECK AGAINST YOUR BLOODHOUND
------------------------------------------------------------------------
The JSON is shaped like BloodHound CE's OpenGraph generic-ingest payload as
understood at the time of writing. These are assumptions, not verified facts:

1. Top-level keys are `metadata`, `nodes`, `edges`. (CE has also been documented
   nesting `nodes`/`edges` under a `graph` object; if your version wants that,
   `write_json` is the single place to change.)
2. A node is `{"id": str, "kinds": [str], "properties": {...}}`, `kinds[0]`
   being the primary kind, with `Base` appended so generic queries match.
3. An edge is `{"start": str, "end": str, "kind": str, "properties": {...}}`
   where `start`/`end` are node `id` values. Some CE builds expect
   `{"value": ..., "match_by": ...}` objects here instead.
4. `id` is the objectid/SID where known, else the distinguishedName, else the
   bare principal name. Because that is ambiguous for an ingester, every node
   also carries `group3rpyMatchBy` saying which property the id should be
   matched against (`objectid`, `distinguishedname`, or `name`) -- that is what
   the Cypher writer uses.
5. Custom kinds (`GPOLocalGroupMember`, `GPOGrantsPrivilege`, `GPOServiceAccount`,
   `GPOScheduledTaskPrincipal`) need registering in BloodHound before they render
   with an icon; they are emitted regardless, rather than being mislabelled as
   `AdminTo`.

Every writer is one small function (`write_json`, `write_cypher`) precisely so
that adjusting to a different schema is a local edit.
"""

import datetime
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..ad.gpo import PolicyType, SettingAction
from ..options.priv_rights import load_priv_rights
from ..settings import (
    GroupSetting,
    NtServiceSetting,
    PrivRightSetting,
    SchedTaskSetting,
)

# Stamped on every relationship this tool creates, and the hook the rollback
# query in the Cypher header keys off.
SOURCE_TAG = "group3rpy"

# Marker put on a relationship that already existed in BloodHound. Kept separate
# from SOURCE_TAG so that rolling back never deletes a collected edge.
SEEN_PROPERTY = "group3rpySeen"
SEEN_GPO_PROPERTY = "group3rpyGpo"

# Which property of a BloodHound node a node id should be matched against.
MATCH_BY_PROPERTY = "group3rpyMatchBy"

# BloodHound's own edge kinds, used only where the semantics really match.
EDGE_ADMIN_TO = "AdminTo"
EDGE_CAN_RDP = "CanRDP"
EDGE_CAN_PSREMOTE = "CanPSRemote"

# Custom kinds. A Backup Operator is not an administrator, and a privilege grant
# is not a group membership, so these get their own kinds rather than being
# flattened into AdminTo.
EDGE_LOCAL_GROUP_MEMBER = "GPOLocalGroupMember"
EDGE_GRANTS_PRIVILEGE = "GPOGrantsPrivilege"
EDGE_SERVICE_ACCOUNT = "GPOServiceAccount"
EDGE_SCHED_TASK_PRINCIPAL = "GPOScheduledTaskPrincipal"

ALL_EDGE_KINDS = (
    EDGE_ADMIN_TO,
    EDGE_CAN_RDP,
    EDGE_CAN_PSREMOTE,
    EDGE_LOCAL_GROUP_MEMBER,
    EDGE_GRANTS_PRIVILEGE,
    EDGE_SERVICE_ACCOUNT,
    EDGE_SCHED_TASK_PRINCIPAL,
)

# Privileged local groups, by SID, mapped to the edge kind membership implies.
# The three native kinds are the ones BloodHound itself models; everything else
# lands on GPOLocalGroupMember with the group name in the edge properties.
PRIVILEGED_LOCAL_GROUPS: Dict[str, Tuple[str, str]] = {
    "S-1-5-32-544": (EDGE_ADMIN_TO, "Administrators"),
    "S-1-5-32-555": (EDGE_CAN_RDP, "Remote Desktop Users"),
    "S-1-5-32-580": (EDGE_CAN_PSREMOTE, "Remote Management Users"),
    "S-1-5-32-551": (EDGE_LOCAL_GROUP_MEMBER, "Backup Operators"),
    "S-1-5-32-550": (EDGE_LOCAL_GROUP_MEMBER, "Print Operators"),
    "S-1-5-32-549": (EDGE_LOCAL_GROUP_MEMBER, "Server Operators"),
    "S-1-5-32-548": (EDGE_LOCAL_GROUP_MEMBER, "Account Operators"),
    "S-1-5-32-562": (EDGE_LOCAL_GROUP_MEMBER, "Distributed COM Users"),
}

# GptTmpl.inf resolves a group SID to its well-known display name before the
# setting reaches us, and GPP Groups.xml often carries only a name, so the name
# index has to work on its own. Both the bare and BUILTIN\-prefixed forms occur
# in group3rpy/options/trustees.py, and `_normalise_group_name` folds them.
GROUP_NAME_TO_SID: Dict[str, str] = {
    name.lower(): sid for sid, (_kind, name) in PRIVILEGED_LOCAL_GROUPS.items()
}

# Service/task logon accounts that are machine-local pseudo-principals. They are
# not AD objects, so an edge from them would never match a BloodHound node and
# would only inflate the edge count.
BUILTIN_SERVICE_ACCOUNTS = {
    "localsystem",
    "system",
    "nt authority\\system",
    "local service",
    "localservice",
    "nt authority\\local service",
    "nt authority\\localservice",
    "network service",
    "networkservice",
    "nt authority\\network service",
    "nt authority\\networkservice",
    "s-1-5-18",
    "s-1-5-19",
    "s-1-5-20",
}

# The inf parser writes this literal into a member's name when SID resolution
# fails; it is a placeholder, not a principal.
SID_RESOLUTION_FAILED = "SID Resolution Failed"

# Distinct provenance values for one deduplicated edge are joined with this.
MERGE_SEPARATOR = " | "

# A relationship kind becomes a Cypher label, which cannot be escaped, so it is
# validated rather than quoted.
_KIND_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]*\Z")

_DC_RE = re.compile(r"\ADC=(?P<value>.+)\Z", re.IGNORECASE)
_CN_RE = re.compile(r"\A(?:CN|OU)=(?P<value>.+)\Z", re.IGNORECASE)

_CYPHER_ESCAPES = {
    "\\": "\\\\",
    "'": "\\'",
    '"': '\\"',
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


# --------------------------------------------------------------------- graph

@dataclass
class Node:
    """One BloodHound node we expect to already exist."""

    id: str
    kinds: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)


class EdgeGraph:
    """Nodes and edges, deduplicated on the way in.

    An edge is keyed on `(start, end, kind)`, as required: two GPOs granting the
    same principal local Administrators on the same box is one edge, with both
    GPOs' provenance merged into it.
    """

    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def add_node(self, node: Node) -> str:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node.id
        # Same id seen twice: keep the richer description, Base last.
        for kind in node.kinds:
            if kind not in existing.kinds:
                existing.kinds.append(kind)
        if "Base" in existing.kinds:
            existing.kinds = [
                kind for kind in existing.kinds if kind != "Base"
            ] + ["Base"]
        for key, value in node.properties.items():
            if value is not None and not existing.properties.get(key):
                existing.properties[key] = value
        return existing.id

    def add_edge(self, start: str, end: str, kind: str, properties: Dict[str, Any]) -> bool:
        """Returns True when this is a new (start, end, kind) triple."""
        key = (start, end, kind)
        existing = self.edges.get(key)
        if existing is None:
            self.edges[key] = {
                name: value for name, value in properties.items() if value is not None
            }
            return False
        merge_properties(existing, properties)
        return True


def merge_properties(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    """Fold `incoming` into `target` without losing provenance.

    Booleans OR together, so `uncertain` stays true if any contributing GPO was
    uncertain. Differing scalars are joined rather than overwritten, so an edge
    derived from two GPOs still names both.
    """
    for key, value in incoming.items():
        if value is None:
            continue
        if key not in target or target[key] is None:
            target[key] = value
            continue
        current = target[key]
        if current == value:
            continue
        if isinstance(current, bool) or isinstance(value, bool):
            target[key] = bool(current) or bool(value)
            continue
        parts = str(current).split(MERGE_SEPARATOR)
        if str(value) not in parts:
            parts.append(str(value))
        target[key] = MERGE_SEPARATOR.join(parts)


# ---------------------------------------------------------------- node makers

def _normalise_group_name(name: Optional[str]) -> str:
    """Fold `BUILTIN\\Administrators` and `administrators` onto one key."""
    text = (name or "").strip()
    if "\\" in text:
        prefix, _, remainder = text.partition("\\")
        if prefix.upper() in ("BUILTIN", "BUILT-IN"):
            text = remainder
    return text.lower()


def _dn_parts(dn: str) -> List[str]:
    """Split a DN on unescaped commas (same rule as ad/scope.py)."""
    return re.split(r"(?<!\\),", dn)


def _fqdn_from_dn(dn: str) -> Optional[str]:
    """Best-effort `HOST.DOMAIN.TLD` from a computer DN.

    Only a convenience property: the node id stays the DN, because a name built
    from a DN is a derivation and matching on it could hit the wrong object.
    """
    parts = [part.strip() for part in _dn_parts(dn)]
    if not parts:
        return None
    host = _CN_RE.match(parts[0])
    if host is None:
        return None
    domain = [
        match.group("value")
        for match in (_DC_RE.match(part) for part in parts[1:])
        if match is not None
    ]
    if not domain:
        return None
    return (host.group("value") + "." + ".".join(domain)).upper()


def computer_node(dn: str) -> Node:
    """A computer, identified by DN because scope resolution has no SIDs."""
    identifier = dn.strip()
    properties: Dict[str, Any] = {
        "distinguishedname": identifier.upper(),
        MATCH_BY_PROPERTY: "distinguishedname",
    }
    fqdn = _fqdn_from_dn(identifier)
    if fqdn is not None:
        properties["name"] = fqdn
    return Node(id=identifier.upper(), kinds=["Computer", "Base"], properties=properties)


def principal_node(name: Optional[str], sid: Optional[str]) -> Optional[Node]:
    """A trustee, by SID when we have one, otherwise by name.

    Returns None when neither is usable, which is the "skip rather than guess"
    path: an unresolvable GPP variable such as `%LogonUser%`, the inf parser's
    `SID Resolution Failed` placeholder with no SID beside it, or nothing at all.
    """
    clean_sid = (sid or "").strip()
    clean_name = (name or "").strip()
    if clean_name == SID_RESOLUTION_FAILED:
        clean_name = ""
    if "%" in clean_name:
        # A GPP variable, expanded at apply time on the client. Not resolvable.
        clean_name = ""
    if clean_name.startswith("S-1-") and not clean_sid:
        clean_sid = clean_name
        clean_name = ""

    if clean_sid.startswith("S-1-"):
        properties: Dict[str, Any] = {
            "objectid": clean_sid.upper(),
            MATCH_BY_PROPERTY: "objectid",
        }
        if clean_name:
            properties["name"] = clean_name.upper()
        return Node(id=clean_sid.upper(), kinds=["Base"], properties=properties)

    if clean_name:
        properties = {"name": clean_name.upper(), MATCH_BY_PROPERTY: "name"}
        # A GPO names a principal `NETBIOS\sam`, while BloodHound stores
        # `SAM@DOMAIN.FQDN`, so the sam part is kept separately to give the Cypher
        # writer something that can actually match.
        netbios, separator, sam = clean_name.partition("\\")
        if separator and sam and "\\" not in sam and netbios.upper() != "BUILTIN":
            properties["samaccountname"] = sam.upper()
            properties["group3rpyNetbios"] = netbios.upper()
        return Node(id=clean_name.upper(), kinds=["Base"], properties=properties)
    return None


# ------------------------------------------------------------------ matching

def match_local_group(setting: GroupSetting) -> Optional[Tuple[str, str, Optional[str]]]:
    """Identify the privileged local group a GroupSetting targets.

    Same matching approach as `assessment/analysers/group.py`: a SID in `name`,
    then `group_sid`, then the display name, all case-insensitive. The analyser
    uses if/elif and stops at the first branch that applies; here all three are
    tried, so a GPP group carrying a recognised `groupSid` alongside a localised
    (and therefore unmatchable) `name` is still identified. Both agree on every
    case the analyser matches.

    Returns `(edge_kind, group_display_name, group_sid)` or None.
    """
    for candidate in ((setting.name or ""), (setting.group_sid or "")):
        candidate = candidate.strip()
        if not candidate.startswith("S-"):
            continue
        hit = PRIVILEGED_LOCAL_GROUPS.get(candidate.upper())
        if hit is not None:
            return hit[0], hit[1], candidate.upper()

    sid = GROUP_NAME_TO_SID.get(_normalise_group_name(setting.name))
    if sid is None:
        return None
    return PRIVILEGED_LOCAL_GROUPS[sid][0], PRIVILEGED_LOCAL_GROUPS[sid][1], sid


def _priv_right_index() -> Dict[str, Any]:
    """Name -> PrivRightOption, from the ported classification table."""
    return {
        (option.priv_right_name or "").lower(): option
        for option in load_priv_rights()
        if option.priv_right_name
    }


# ---------------------------------------------------------------- uncertainty

def scope_uncertainty(scope) -> Tuple[bool, Optional[str]]:
    """Why an edge from this GPO may reach fewer machines than we claim.

    Security filtering and WMI filters are evaluated on the client, so the link
    scope is an upper bound. That does not justify dropping the edge, but it does
    have to be said out loud on every edge derived from such a GPO.
    """
    reasons: List[str] = []
    if scope.security_filtering_narrowed:
        names = ", ".join(
            trustee.display_name or trustee.sid or "?"
            for trustee in scope.security_filter_principals
        )
        reasons.append(
            "Security filtering restricts this GPO to: "
            + names
            + "; the affected computer list is the link scope and may be wider."
        )
    if scope.wmi_filter:
        reasons.append(
            "A WMI filter is attached, so this GPO may apply to fewer machines "
            "than listed."
        )
    if not reasons:
        return False, None
    return True, " ".join(reasons)


# ------------------------------------------------------------------ writers

def _cypher_string(value: Any) -> str:
    """A single-quoted Cypher string literal, escaped character by character.

    Escaping per character sidesteps the ordering bug that a chain of
    `str.replace` calls has (replacing `\\` after `'` would double-escape the
    backslash the quote escape just introduced).
    """
    text = "" if value is None else str(value)
    return "'" + "".join(_CYPHER_ESCAPES.get(char, char) for char in text) + "'"


def _cypher_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    return _cypher_string(value)


def _match_clause(variable: str, node: Node) -> str:
    """MATCH on an existing node -- never MERGE, so nothing is ever created."""
    match_by = node.properties.get(MATCH_BY_PROPERTY)
    if match_by == "objectid":
        return (
            f"MATCH ({variable}) WHERE {variable}.objectid = "
            f"{_cypher_string(node.id)}"
        )
    if match_by == "distinguishedname":
        return (
            f"MATCH ({variable}) WHERE toUpper({variable}.distinguishedname) = "
            f"{_cypher_string(node.id.upper())}"
        )
    # Name matching, the weakest case. BloodHound's `name` is `SAM@DOMAIN.FQDN`
    # while the GPO carried `NETBIOS\sam`, so all three plausible forms are
    # offered; the header warns that this can match in more than one domain.
    clauses = [f"toUpper({variable}.name) = {_cypher_string(node.id.upper())}"]
    sam = node.properties.get("samaccountname")
    if sam:
        clauses.append(f"toUpper({variable}.samaccountname) = {_cypher_string(sam)}")
        clauses.append(
            f"toUpper({variable}.name) STARTS WITH {_cypher_string(sam + '@')}"
        )
    return f"MATCH ({variable}) WHERE " + " OR ".join(clauses)


def write_json(path: str, nodes: List[Node], edges: List[Tuple[Tuple[str, str, str], Dict[str, Any]]], metadata: Dict[str, Any]) -> None:
    """Write the OpenGraph-shaped payload.

    Kept deliberately tiny: the exact shape is an assumption (see the module
    docstring), so this is the one function to edit when checking it against a
    specific BloodHound version.
    """
    document = {
        "metadata": metadata,
        "nodes": [
            {"id": node.id, "kinds": list(node.kinds), "properties": dict(node.properties)}
            for node in nodes
        ],
        "edges": [
            {"start": start, "end": end, "kind": kind, "properties": dict(properties)}
            for (start, end, kind), properties in edges
        ],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")


def write_cypher(path: str, nodes: Dict[str, Node], edges: List[Tuple[Tuple[str, str, str], Dict[str, Any]]], metadata: Dict[str, Any]) -> None:
    """Write idempotent, provenance-stamped, rollback-documented Cypher."""
    lines: List[str] = []
    lines.append("// BloodHound edges derived from Group Policy by group3rpy.")
    lines.append("// Generated: " + str(metadata.get("generated")))
    if metadata.get("domain"):
        lines.append("// Domain: " + str(metadata["domain"]))
    lines.append("// Relationships: " + str(len(edges)))
    lines.append("//")
    lines.append("// READ THIS BEFORE RUNNING.")
    lines.append("// * Every statement MATCHes both endpoints and MERGEs only the")
    lines.append("//   relationship, so no node is ever created: an endpoint BloodHound")
    lines.append("//   never collected simply matches nothing.")
    lines.append("// * MERGE, never CREATE, so re-running this file changes nothing.")
    lines.append(
        "// * A relationship we create is stamped r.source = '" + SOURCE_TAG + "'."
    )
    lines.append("//   A relationship that already existed is NOT stamped with that")
    lines.append(
        "//   (it only gets r." + SEEN_PROPERTY + "), so the rollback below cannot"
    )
    lines.append("//   delete an edge BloodHound collected itself.")
    lines.append("// * Edges with uncertain = true come from a GPO whose real scope is")
    lines.append("//   narrower than its link scope; see r.reason.")
    lines.append("// * A principal the GPO named only as NETBIOS\\SAM is matched on name,")
    lines.append("//   samaccountname or SAM@..., because BloodHound stores")
    lines.append("//   SAM@DOMAIN.FQDN. In a multi-domain forest that can match more")
    lines.append("//   than one object, so check those statements before running.")
    lines.append("//")
    lines.append("// ROLLBACK -- uncomment and run these two statements to undo:")
    lines.append(
        "// MATCH ()-[r]->() WHERE r.source = '" + SOURCE_TAG + "' DELETE r;"
    )
    lines.append(
        "// MATCH ()-[r]->() WHERE r."
        + SEEN_PROPERTY
        + " IS NOT NULL REMOVE r."
        + SEEN_PROPERTY
        + ", r."
        + SEEN_GPO_PROPERTY
        + ";"
    )
    lines.append("")

    for (start, end, kind), properties in edges:
        if not _KIND_RE.match(kind):
            # A kind becomes a label, and a label cannot be escaped.
            raise ValueError(f"Refusing to emit unsafe relationship kind: {kind!r}")
        start_node = nodes[start]
        end_node = nodes[end]
        lines.append(
            "// "
            + kind
            + ": "
            + (start_node.properties.get("name") or start_node.id)
            + " -> "
            + (end_node.properties.get("name") or end_node.id)
        )
        lines.append(_match_clause("s", start_node))
        lines.append(_match_clause("t", end_node))
        lines.append(f"MERGE (s)-[r:{kind}]->(t)")
        assignments = ", ".join(
            f"r.{name} = {_cypher_value(value)}" for name, value in properties.items()
        )
        lines.append("ON CREATE SET " + assignments)
        # Do not overwrite anything on an edge BloodHound already knows about.
        lines.append(
            "ON MATCH SET r."
            + SEEN_PROPERTY
            + " = true, r."
            + SEEN_GPO_PROPERTY
            + " = "
            + _cypher_value(properties.get("gpo"))
            + ";"
        )
        lines.append("")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


# ---------------------------------------------------------------- derivation

class _Deriver:
    """Walks settings and adds edges. Counts everything it refuses to emit."""

    def __init__(self):
        self.graph = EdgeGraph()
        self.skipped_gpos: Dict[str, int] = {}
        self.skipped_settings: Dict[str, int] = {}
        self.duplicate_edges = 0
        self.priv_rights = _priv_right_index()

    # -- counters ------------------------------------------------------------

    def _skip_gpo(self, reason: str) -> None:
        self.skipped_gpos[reason] = self.skipped_gpos.get(reason, 0) + 1

    def _skip_setting(self, reason: str) -> None:
        self.skipped_settings[reason] = self.skipped_settings.get(reason, 0) + 1

    # -- helpers -------------------------------------------------------------

    def _emit(
        self,
        principal: Node,
        scope,
        kind: str,
        properties: Dict[str, Any],
    ) -> None:
        """One edge per affected computer, from `principal`."""
        start = self.graph.add_node(principal)
        for computer_dn in scope.affected_computers:
            end = self.graph.add_node(computer_node(computer_dn))
            if self.graph.add_edge(start, end, kind, properties):
                self.duplicate_edges += 1

    def _base_properties(self, attributes, setting, uncertain: bool, reason: Optional[str]) -> Dict[str, Any]:
        properties: Dict[str, Any] = {
            "source": SOURCE_TAG,
            "gpo": attributes.uid or "",
            # Left out rather than written blank, so an empty property never
            # reads as "we looked and there was nothing".
            "gpoDisplayName": attributes.display_name or None,
            "settingSource": getattr(setting, "source", None) or None,
        }
        if uncertain:
            properties["uncertain"] = True
            properties["reason"] = reason
        return properties

    # -- per setting type ----------------------------------------------------

    def group_setting(self, setting, scope, attributes, uncertain, reason) -> None:
        match = match_local_group(setting)
        if match is None:
            # Not one of the privileged local groups we model.
            self._skip_setting("group_not_privileged")
            return
        kind, group_name, group_sid = match

        if setting.action == SettingAction.Remove:
            # The group itself is being deleted; nobody gains anything.
            self._skip_setting("group_setting_removed")
            return
        if not setting.members:
            self._skip_setting("group_setting_no_members")
            return

        for member in setting.members:
            if member.action == SettingAction.Remove:
                self._skip_setting("group_member_removed")
                continue
            principal = principal_node(member.name, member.sid)
            if principal is None:
                self._skip_setting("unidentified_principal")
                continue
            properties = self._base_properties(attributes, setting, uncertain, reason)
            properties["localGroup"] = group_name
            if group_sid:
                properties["localGroupSid"] = group_sid
            self._emit(principal, scope, kind, properties)

    def priv_right_setting(self, setting, scope, attributes, uncertain, reason) -> None:
        privilege = (setting.privilege or "").strip()
        option = self.priv_rights.get(privilege.lower())
        if option is None:
            # Not in the ported classification table; inventing a verdict here
            # would be exactly the kind of guess this export avoids.
            self._skip_setting("privilege_unclassified")
            return
        if not (option.local_privesc or option.grants_remote_access):
            self._skip_setting("privilege_not_privesc_or_remote")
            return

        trustees: List[Tuple[Optional[str], Optional[str]]] = [
            (trustee.display_name, trustee.sid) for trustee in setting.trustees
        ]
        known_sids = {(sid or "").upper() for _name, sid in trustees}
        for sid in setting.trustee_sids:
            if (sid or "").upper() not in known_sids:
                trustees.append((None, sid))

        for name, sid in trustees:
            principal = principal_node(name, sid)
            if principal is None:
                self._skip_setting("unidentified_principal")
                continue
            properties = self._base_properties(attributes, setting, uncertain, reason)
            properties["privilege"] = privilege
            if option.local_privesc:
                properties["adminEquivalent"] = True
            if option.grants_remote_access:
                properties["grantsRemoteAccess"] = True
            if option.ms_description:
                properties["msDescription"] = option.ms_description
            self._emit(principal, scope, EDGE_GRANTS_PRIVILEGE, properties)

    def nt_service_setting(self, setting, scope, attributes, uncertain, reason) -> None:
        account = (setting.account_name or setting.user_name or "").strip()
        if not account:
            self._skip_setting("service_no_account")
            return
        if account.lower() in BUILTIN_SERVICE_ACCOUNTS:
            # A machine-local pseudo-principal, not an AD object.
            self._skip_setting("service_builtin_account")
            return
        principal = principal_node(account, None)
        if principal is None:
            self._skip_setting("unidentified_principal")
            return

        properties = self._base_properties(attributes, setting, uncertain, reason)
        properties["serviceName"] = (setting.service_name or setting.name or "").strip() or None
        if setting.startup_type:
            properties["startupType"] = setting.startup_type
        if setting.password:
            # The GPP cpassword decrypted, so this account's credentials are
            # recoverable by anyone who can read sysvol.
            properties["gppPasswordRecovered"] = True
        self._emit(principal, scope, EDGE_SERVICE_ACCOUNT, properties)

    def sched_task_setting(self, setting, scope, attributes, uncertain, reason) -> None:
        principals = setting.principals or []
        if not principals:
            self._skip_setting("sched_task_no_principal")
            return
        for task_principal in principals:
            account = (task_principal.user_id or task_principal.id or "").strip()
            if not account:
                self._skip_setting("sched_task_no_principal")
                continue
            if account.lower() in BUILTIN_SERVICE_ACCOUNTS:
                self._skip_setting("sched_task_builtin_account")
                continue
            principal = principal_node(account, None)
            if principal is None:
                self._skip_setting("unidentified_principal")
                continue
            properties = self._base_properties(attributes, setting, uncertain, reason)
            properties["taskName"] = (setting.name or "").strip() or None
            if task_principal.run_level:
                properties["runLevel"] = task_principal.run_level
            if task_principal.logon_type:
                properties["logonType"] = task_principal.logon_type
            if task_principal.password:
                properties["gppPasswordRecovered"] = True
            self._emit(principal, scope, EDGE_SCHED_TASK_PRINCIPAL, properties)

    # -- driver --------------------------------------------------------------

    def gpo_result(self, result, scope) -> bool:
        """Derive every edge from one GPO. Returns True if it produced any."""
        before = len(self.graph.edges)
        attributes = result.attributes
        uncertain, reason = scope_uncertainty(scope)

        for setting_result in result.setting_results:
            setting = getattr(setting_result, "setting", None)
            if setting is None:
                continue
            if getattr(setting, "policy_type", None) == PolicyType.User:
                # Applies wherever the affected users log on, which the link
                # scope does not tell us. Refuse to guess a machine set.
                self._skip_setting("user_scoped_setting")
                continue

            if isinstance(setting, GroupSetting):
                self.group_setting(setting, scope, attributes, uncertain, reason)
            elif isinstance(setting, PrivRightSetting):
                self.priv_right_setting(setting, scope, attributes, uncertain, reason)
            elif isinstance(setting, NtServiceSetting):
                self.nt_service_setting(setting, scope, attributes, uncertain, reason)
            elif isinstance(setting, SchedTaskSetting):
                self.sched_task_setting(setting, scope, attributes, uncertain, reason)

        return len(self.graph.edges) > before


# ------------------------------------------------------------------- entry point

def export(gpo_results: Iterable, scopes: Dict[str, Any], output_prefix: str, domain: Optional[str] = None) -> dict:
    """Derive BloodHound edges from assessed GPOs and write both artefacts.

    `gpo_results` is an iterable of `GpoResult`; `scopes` maps an upper-case GPO
    guid in `{...}` form to a `GpoScope`. `output_prefix` is treated as a
    basename: `<prefix>.json` and `<prefix>.cypher` are written.

    Returns a summary dict: files written, edge counts per kind, and every
    reason something was skipped -- the skip counts are part of the output, not
    debug noise, because "we found 4 edges and dropped 900 settings we could not
    scope" is a materially different result from "we found 4 edges".
    """
    deriver = _Deriver()
    considered = 0
    productive = 0
    contributing: List[Dict[str, Any]] = []

    for result in gpo_results:
        considered += 1
        attributes = result.attributes
        guid = (attributes.uid or "").upper()
        scope = scopes.get(guid)

        if scope is None:
            # No scope resolved means no idea what it reaches; emit nothing.
            deriver._skip_gpo("no_scope_resolved")
            continue
        if scope.is_orphaned:
            deriver._skip_gpo("gpo_orphaned")
            continue
        if scope.all_links_disabled:
            deriver._skip_gpo("gpo_all_links_disabled")
            continue
        if not scope.computer_policy_enabled:
            # Every edge kind here targets computers.
            deriver._skip_gpo("gpo_computer_policy_disabled")
            continue
        if not scope.affected_computers:
            deriver._skip_gpo("gpo_no_affected_computers")
            continue

        if deriver.gpo_result(result, scope):
            productive += 1
            uncertain, reason = scope_uncertainty(scope)
            contributing.append(
                {
                    "guid": attributes.uid,
                    "displayName": attributes.display_name,
                    "affectedComputers": len(scope.affected_computers),
                    "uncertain": uncertain,
                    "reason": reason,
                    "notes": list(scope.notes),
                }
            )

    edges = sorted(deriver.graph.edges.items(), key=lambda item: (item[0][2], item[0][0], item[0][1]))
    nodes = sorted(deriver.graph.nodes.values(), key=lambda node: node.id)

    edge_counts: Dict[str, int] = {}
    uncertain_edges = 0
    for (_start, _end, kind), properties in edges:
        edge_counts[kind] = edge_counts.get(kind, 0) + 1
        if properties.get("uncertain"):
            uncertain_edges += 1

    metadata = {
        "tool": SOURCE_TAG,
        "generated": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "domain": domain,
        "sourceKind": "GroupPolicy",
        "schemaNote": (
            "Shaped after BloodHound CE's OpenGraph generic-ingest payload, but "
            "the exact schema is UNVERIFIED against any specific BloodHound "
            "version. Node ids are objectid/SID where known, otherwise a "
            "distinguishedName, otherwise a bare name; each node carries "
            "group3rpyMatchBy naming the property its id should be matched on."
        ),
        "derivedEdgeKinds": list(ALL_EDGE_KINDS),
        "customEdgeKinds": [
            EDGE_LOCAL_GROUP_MEMBER,
            EDGE_GRANTS_PRIVILEGE,
            EDGE_SERVICE_ACCOUNT,
            EDGE_SCHED_TASK_PRINCIPAL,
        ],
        "uncertainEdgeNote": (
            "An edge with uncertain = true comes from a GPO narrowed by security "
            "filtering or a WMI filter, so it may reach fewer computers than "
            "listed. See its reason property."
        ),
        "edgeCounts": edge_counts,
        "gpos": contributing,
    }

    directory = os.path.dirname(os.path.abspath(output_prefix))
    if directory:
        os.makedirs(directory, exist_ok=True)

    json_path = output_prefix + ".json"
    cypher_path = output_prefix + ".cypher"
    write_json(json_path, nodes, edges, metadata)
    write_cypher(cypher_path, deriver.graph.nodes, edges, metadata)

    return {
        "files": [json_path, cypher_path],
        "edge_counts": edge_counts,
        "edge_total": len(edges),
        "uncertain_edges": uncertain_edges,
        "node_count": len(nodes),
        "gpos_considered": considered,
        "gpos_with_edges": productive,
        "deduplicated_edges": deriver.duplicate_edges,
        "skipped_gpos": dict(deriver.skipped_gpos),
        "skipped_settings": dict(deriver.skipped_settings),
    }
