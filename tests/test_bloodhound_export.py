"""Tests for the BloodHound edge export.

These assert the honesty properties as hard as the edge derivation: a GPO that
cannot apply must produce nothing, a narrowed GPO must produce edges that admit
it, and the Cypher must be safe to hand to a client -- MERGE only, provenance
stamped, rollback documented, and every string literal escaped.
"""

import json
import re

from group3rpy.ad.gpo import GPOAttributes, PolicyType, SettingAction
from group3rpy.ad.scope import GpoLinkRef, GpoScope
from group3rpy.ad.trustee import Trustee
from group3rpy.assessment.finding import GpoResult, SettingResult
from group3rpy.options.assessment_options import AssessmentOptions
from group3rpy.settings import (
    GroupSetting,
    GroupSettingMember,
    NtServiceSetting,
    PrivRightSetting,
    RegistrySetting,
    SchedTaskSetting,
)
from group3rpy.settings.sched_task_setting import SchedTaskPrincipal
from group3rpy.view import bloodhound_export
from group3rpy.view.bloodhound_export import export

COMPUTERS = [
    "CN=WS01,OU=Workstations,DC=corp,DC=local",
    "CN=WS02,OU=Workstations,DC=corp,DC=local",
    "CN=WS03,OU=Workstations,DC=corp,DC=local",
]


# ------------------------------------------------------------------ fixtures


def make_link(disabled=False, enforced=False):
    return GpoLinkRef(
        gpo_guid="{11111111-1111-1111-1111-111111111111}",
        container_dn="OU=Workstations,DC=corp,DC=local",
        container_kind="ou",
        link_index=0,
        disabled=disabled,
        enforced=enforced,
    )


def make_scope(
    guid="{11111111-1111-1111-1111-111111111111}",
    computers=None,
    links=None,
    computer_policy_enabled=True,
    security_filter_principals=None,
    wmi_filter=None,
):
    return GpoScope(
        guid=guid,
        display_name="Workstation Policy",
        links=[make_link()] if links is None else links,
        computer_policy_enabled=computer_policy_enabled,
        affected_computers=list(COMPUTERS if computers is None else computers),
        security_filter_principals=list(security_filter_principals or []),
        wmi_filter=wmi_filter,
    )


def make_result(settings, guid="{11111111-1111-1111-1111-111111111111}", display_name="Workstation Policy"):
    attributes = GPOAttributes(
        display_name=display_name,
        uid=guid,
        distinguished_name=f"CN={guid},CN=Policies,CN=System,DC=corp,DC=local",
        computer_policy_enabled=True,
        user_policy_enabled=False,
    )
    result = GpoResult(AssessmentOptions(), attributes)
    result.setting_results = [
        SettingResult(setting=setting, findings=[]) for setting in settings
    ]
    return result


def group_setting(group_name, member_name="CORP\\Helpdesk", member_sid=None, source="\\\\corp.local\\sysvol\\gpt.inf"):
    return GroupSetting(
        source=source,
        policy_type=PolicyType.Computer,
        name=group_name,
        action=SettingAction.Update,
        members=[
            GroupSettingMember(
                name=member_name, sid=member_sid, action=SettingAction.Add
            )
        ],
    )


def run_export(tmp_path, results, scopes, name="bh"):
    prefix = str(tmp_path / name)
    summary = export(results, scopes, prefix, domain="corp.local")
    with open(prefix + ".json", encoding="utf-8") as handle:
        document = json.load(handle)
    with open(prefix + ".cypher", encoding="utf-8") as handle:
        cypher = handle.read()
    return summary, document, cypher


# --------------------------------------------------------------- derivation


def test_administrators_over_three_computers_yields_three_admin_to(tmp_path):
    result = make_result([group_setting("Administrators")])
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_counts"] == {"AdminTo": 3}
    assert summary["edge_total"] == 3
    admin_edges = [edge for edge in document["edges"] if edge["kind"] == "AdminTo"]
    assert len(admin_edges) == 3
    assert {edge["end"] for edge in admin_edges} == {dn.upper() for dn in COMPUTERS}
    assert {edge["start"] for edge in admin_edges} == {"CORP\\HELPDESK"}
    for edge in admin_edges:
        assert edge["properties"]["localGroup"] == "Administrators"
        assert edge["properties"]["localGroupSid"] == "S-1-5-32-544"
        assert edge["properties"]["source"] == "group3rpy"
        assert "uncertain" not in edge["properties"]


def test_orphaned_gpo_yields_no_edges(tmp_path):
    result = make_result([group_setting("Administrators")])
    scope = make_scope(links=[], computers=[])
    assert scope.is_orphaned
    summary, document, cypher = run_export(
        tmp_path, [result], {result.attributes.uid: scope}
    )

    assert summary["edge_total"] == 0
    assert document["edges"] == []
    assert summary["skipped_gpos"] == {"gpo_orphaned": 1}
    # Header comments only; no executable statement at all.
    assert not [
        line
        for line in cypher.splitlines()
        if line.strip() and not line.lstrip().startswith("//")
    ]


def test_all_links_disabled_yields_no_edges(tmp_path):
    result = make_result([group_setting("Administrators")])
    scope = make_scope(links=[make_link(disabled=True)])
    assert scope.all_links_disabled
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: scope}
    )

    assert summary["edge_total"] == 0
    assert document["edges"] == []
    assert summary["skipped_gpos"] == {"gpo_all_links_disabled": 1}


def test_computer_policy_disabled_yields_no_edges(tmp_path):
    result = make_result([group_setting("Administrators")])
    scope = make_scope(computer_policy_enabled=False)
    summary, _document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: scope}
    )

    assert summary["edge_total"] == 0
    assert summary["skipped_gpos"] == {"gpo_computer_policy_disabled": 1}


def test_security_filtered_gpo_still_emits_but_flags_uncertainty(tmp_path):
    result = make_result([group_setting("Administrators")])
    scope = make_scope(
        security_filter_principals=[
            Trustee(sid="S-1-5-21-1-2-3-1104", display_name="CORP\\Tier1 Servers")
        ]
    )
    assert scope.security_filtering_narrowed
    summary, document, cypher = run_export(
        tmp_path, [result], {result.attributes.uid: scope}
    )

    assert summary["edge_total"] == 3
    assert summary["uncertain_edges"] == 3
    for edge in document["edges"]:
        assert edge["properties"]["uncertain"] is True
        assert "Security filtering restricts this GPO to" in edge["properties"]["reason"]
        assert "CORP\\Tier1 Servers" in edge["properties"]["reason"]
    assert "r.uncertain = true" in cypher


def test_wmi_filter_flags_uncertainty(tmp_path):
    result = make_result([group_setting("Administrators")])
    scope = make_scope(wmi_filter="select * from Win32_OperatingSystem")
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: scope}
    )

    assert summary["uncertain_edges"] == 3
    assert all(edge["properties"]["uncertain"] for edge in document["edges"])
    assert "WMI filter" in document["edges"][0]["properties"]["reason"]


def test_rdp_and_remote_management_groups_map_to_their_own_kinds(tmp_path):
    result = make_result(
        [
            group_setting("BUILTIN\\Remote Desktop Users", member_name="CORP\\Helpdesk"),
            group_setting("Remote Management Users", member_name="CORP\\Automation"),
        ]
    )
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_counts"] == {"CanRDP": 3, "CanPSRemote": 3}
    rdp = [edge for edge in document["edges"] if edge["kind"] == "CanRDP"]
    psremote = [edge for edge in document["edges"] if edge["kind"] == "CanPSRemote"]
    assert {edge["start"] for edge in rdp} == {"CORP\\HELPDESK"}
    assert {edge["start"] for edge in psremote} == {"CORP\\AUTOMATION"}
    assert rdp[0]["properties"]["localGroupSid"] == "S-1-5-32-555"
    assert psremote[0]["properties"]["localGroupSid"] == "S-1-5-32-580"


def test_operator_groups_are_not_passed_off_as_admin_to(tmp_path):
    result = make_result(
        [
            group_setting("Backup Operators", member_name="CORP\\Backup Svc"),
            group_setting("S-1-5-32-562", member_name="CORP\\Monitoring"),
        ]
    )
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_counts"] == {"GPOLocalGroupMember": 6}
    assert "AdminTo" not in summary["edge_counts"]
    groups = {edge["properties"]["localGroup"] for edge in document["edges"]}
    assert groups == {"Backup Operators", "Distributed COM Users"}


def test_group_matched_by_sid_when_display_name_is_localised(tmp_path):
    setting = group_setting("Administratoren", member_name="CORP\\Helpdesk")
    setting.group_sid = "S-1-5-32-544"
    result = make_result([setting])
    summary, _document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_counts"] == {"AdminTo": 3}


def test_unprivileged_group_and_removals_emit_nothing(tmp_path):
    removed_group = group_setting("Administrators")
    removed_group.action = SettingAction.Remove
    removed_member = group_setting("Administrators")
    removed_member.members[0].action = SettingAction.Remove
    result = make_result(
        [group_setting("Users"), removed_group, removed_member, RegistrySetting()]
    )
    summary, _document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_total"] == 0
    assert summary["skipped_settings"] == {
        "group_not_privileged": 1,
        "group_setting_removed": 1,
        "group_member_removed": 1,
    }


def test_unidentifiable_principals_are_skipped(tmp_path):
    empty_member = group_setting("Administrators", member_name=None)
    placeholder = group_setting("Administrators", member_name="SID Resolution Failed")
    variable = group_setting("Administrators", member_name="%LogonUser%")
    result = make_result([empty_member, placeholder, variable])
    summary, _document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_total"] == 0
    assert summary["skipped_settings"] == {"unidentified_principal": 3}


def test_member_sid_wins_over_failed_resolution_placeholder(tmp_path):
    setting = group_setting(
        "Administrators",
        member_name="SID Resolution Failed",
        member_sid="S-1-5-21-1-2-3-1105",
    )
    result = make_result([setting])
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_counts"] == {"AdminTo": 3}
    assert {edge["start"] for edge in document["edges"]} == {"S-1-5-21-1-2-3-1105"}


# ------------------------------------------------------------- priv rights


def test_local_privesc_right_yields_admin_equivalent_edge(tmp_path):
    setting = PrivRightSetting(
        source="\\\\corp.local\\sysvol\\gpt.inf",
        policy_type=PolicyType.Computer,
        privilege="SeDebugPrivilege",
        trustees=[Trustee(sid="S-1-5-21-1-2-3-1106", display_name="CORP\\Devs")],
    )
    result = make_result([setting])
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_counts"] == {"GPOGrantsPrivilege": 3}
    for edge in document["edges"]:
        assert edge["properties"]["privilege"] == "SeDebugPrivilege"
        assert edge["properties"]["adminEquivalent"] is True
        assert edge["properties"]["msDescription"] == "Debug programs"


def test_non_privesc_and_unknown_rights_emit_nothing(tmp_path):
    harmless = PrivRightSetting(
        policy_type=PolicyType.Computer,
        privilege="SeShutdownPrivilege",
        trustees=[Trustee(sid="S-1-5-21-1-2-3-1107", display_name="CORP\\Devs")],
    )
    unknown = PrivRightSetting(
        policy_type=PolicyType.Computer,
        privilege="SeMadeUpPrivilege",
        trustees=[Trustee(sid="S-1-5-21-1-2-3-1108", display_name="CORP\\Devs")],
    )
    result = make_result([harmless, unknown])
    summary, _document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_total"] == 0
    assert summary["skipped_settings"] == {
        "privilege_not_privesc_or_remote": 1,
        "privilege_unclassified": 1,
    }


def test_remote_access_right_is_flagged_without_admin_equivalence(tmp_path):
    setting = PrivRightSetting(
        policy_type=PolicyType.Computer,
        privilege="SeRemoteInteractiveLogonRight",
        trustees=[Trustee(sid="S-1-5-21-1-2-3-1109", display_name="CORP\\Support")],
    )
    result = make_result([setting])
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_counts"] == {"GPOGrantsPrivilege": 3}
    properties = document["edges"][0]["properties"]
    assert properties["grantsRemoteAccess"] is True
    assert "adminEquivalent" not in properties


# -------------------------------------------------- services and sched tasks


def test_service_account_edge(tmp_path):
    setting = NtServiceSetting(
        source="\\\\corp.local\\sysvol\\Services.xml",
        policy_type=PolicyType.Computer,
        service_name="BackupAgent",
        account_name="CORP\\svc_backup",
        startup_type="Automatic",
        password="Summer2024!",
    )
    result = make_result([setting])
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_counts"] == {"GPOServiceAccount": 3}
    properties = document["edges"][0]["properties"]
    assert properties["serviceName"] == "BackupAgent"
    assert properties["startupType"] == "Automatic"
    assert properties["gppPasswordRecovered"] is True
    assert {edge["start"] for edge in document["edges"]} == {"CORP\\SVC_BACKUP"}


def test_builtin_service_accounts_emit_nothing(tmp_path):
    result = make_result(
        [
            NtServiceSetting(
                policy_type=PolicyType.Computer,
                service_name="Spooler",
                account_name="LocalSystem",
            ),
            NtServiceSetting(
                policy_type=PolicyType.Computer,
                service_name="Time",
                user_name="NT AUTHORITY\\LocalService",
            ),
            NtServiceSetting(policy_type=PolicyType.Computer, service_name="NoAccount"),
        ]
    )
    summary, _document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_total"] == 0
    assert summary["skipped_settings"] == {
        "service_builtin_account": 2,
        "service_no_account": 1,
    }


def test_scheduled_task_principal_edge(tmp_path):
    setting = SchedTaskSetting(
        source="\\\\corp.local\\sysvol\\ScheduledTasks.xml",
        policy_type=PolicyType.Computer,
        name="Nightly Sync",
        principals=[
            SchedTaskPrincipal(
                id="Author",
                user_id="CORP\\svc_task",
                run_level="HighestAvailable",
                logon_type="Password",
                password="Winter2024!",
            ),
            SchedTaskPrincipal(id="System", user_id="NT AUTHORITY\\System"),
        ],
    )
    result = make_result([setting])
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_counts"] == {"GPOScheduledTaskPrincipal": 3}
    assert summary["skipped_settings"] == {"sched_task_builtin_account": 1}
    properties = document["edges"][0]["properties"]
    assert properties["taskName"] == "Nightly Sync"
    assert properties["runLevel"] == "HighestAvailable"
    assert properties["logonType"] == "Password"
    assert properties["gppPasswordRecovered"] is True


def test_user_branch_settings_are_skipped_not_guessed(tmp_path):
    setting = group_setting("Administrators")
    setting.policy_type = PolicyType.User
    result = make_result([setting])
    summary, _document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert summary["edge_total"] == 0
    assert summary["skipped_settings"] == {"user_scoped_setting": 1}


def test_gpo_without_a_resolved_scope_emits_nothing(tmp_path):
    result = make_result([group_setting("Administrators")])
    summary, _document, _cypher = run_export(tmp_path, [result], {})

    assert summary["edge_total"] == 0
    assert summary["skipped_gpos"] == {"no_scope_resolved": 1}


# ------------------------------------------------------------ deduplication


def test_duplicate_triples_collapse_to_one_edge(tmp_path):
    # The same principal added to local Administrators twice in one GPO, and
    # again by a second GPO reaching the same machines.
    first = make_result(
        [group_setting("Administrators"), group_setting("BUILTIN\\Administrators")]
    )
    second = make_result(
        [group_setting("Administrators", source="\\\\corp.local\\sysvol\\other.inf")],
        guid="{22222222-2222-2222-2222-222222222222}",
        display_name="Second Policy",
    )
    scopes = {
        first.attributes.uid: make_scope(),
        second.attributes.uid: make_scope(guid=second.attributes.uid),
    }
    summary, document, cypher = run_export(tmp_path, [first, second], scopes)

    assert summary["edge_counts"] == {"AdminTo": 3}
    assert summary["deduplicated_edges"] == 6
    keys = [(edge["start"], edge["end"], edge["kind"]) for edge in document["edges"]]
    assert len(keys) == len(set(keys)) == 3
    # Provenance from both GPOs survives the merge.
    properties = document["edges"][0]["properties"]
    assert "{11111111-1111-1111-1111-111111111111}" in properties["gpo"]
    assert "{22222222-2222-2222-2222-222222222222}" in properties["gpo"]
    assert "Second Policy" in properties["gpoDisplayName"]
    assert cypher.count("MERGE (s)-[r:AdminTo]->(t)") == 3


def test_merged_uncertainty_is_sticky(tmp_path):
    certain = make_result([group_setting("Administrators")])
    filtered = make_result(
        [group_setting("Administrators")],
        guid="{33333333-3333-3333-3333-333333333333}",
        display_name="Filtered Policy",
    )
    scopes = {
        certain.attributes.uid: make_scope(),
        filtered.attributes.uid: make_scope(
            guid=filtered.attributes.uid,
            security_filter_principals=[
                Trustee(sid="S-1-5-21-1-2-3-1110", display_name="CORP\\Tier1")
            ],
        ),
    }
    summary, document, _cypher = run_export(tmp_path, [certain, filtered], scopes)

    assert summary["edge_total"] == 3
    assert all(edge["properties"]["uncertain"] is True for edge in document["edges"])


# ------------------------------------------------------------------- cypher


def test_cypher_is_merge_only_with_provenance_and_rollback(tmp_path):
    result = make_result([group_setting("Administrators")])
    summary, _document, cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    code = [
        line
        for line in cypher.splitlines()
        if line.strip() and not line.lstrip().startswith("//")
    ]
    assert code, "expected executable statements"
    # The only CREATE anywhere is the `ON CREATE SET` clause of a MERGE; there is
    # no CREATE statement, so re-running the file cannot duplicate an edge.
    for line in code:
        for match in re.finditer(r"CREATE", line):
            assert line[max(0, match.start() - 3) : match.end() + 4] == "ON CREATE SET", line
    assert sum(1 for line in code if line.startswith("MERGE (s)-[r:AdminTo]->(t)")) == 3
    # Nodes are matched, never created, so nothing phantom appears in the DB.
    assert sum(1 for line in code if line.startswith("MATCH (")) == 6
    assert "r.source = 'group3rpy'" in cypher
    assert "r.gpo = '{11111111-1111-1111-1111-111111111111}'" in cypher
    assert "r.gpoDisplayName = 'Workstation Policy'" in cypher
    assert "r.settingSource = " in cypher

    # Rollback, commented out, is in the header before any statement.
    rollback = "// MATCH ()-[r]->() WHERE r.source = 'group3rpy' DELETE r;"
    assert rollback in cypher
    assert cypher.index(rollback) < cypher.index("MERGE (s)-[")
    # Provenance is only written on creation, so rolling back cannot delete an
    # edge BloodHound collected itself.
    assert "ON CREATE SET r.source = 'group3rpy'" in cypher
    assert "ON MATCH SET r.group3rpySeen = true" in cypher
    assert summary["files"][1].endswith(".cypher")


def test_cypher_escapes_quotes_and_backslashes_in_display_name(tmp_path):
    nasty = "Bob's \"Special\" GPO \\ backslash"
    result = make_result(
        [group_setting("Administrators", member_name="CORP\\O'Brien")],
        display_name=nasty,
    )
    _summary, document, cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    # The raw JSON keeps the name exactly as parsed.
    assert document["edges"][0]["properties"]["gpoDisplayName"] == nasty

    # The Cypher literal escapes the backslash, the single quote and the double
    # quote, and nothing else.
    expected = "r.gpoDisplayName = 'Bob\\'s \\\"Special\\\" GPO \\\\ backslash'"
    assert expected in cypher
    assert "r.gpo" in cypher
    # The member name's apostrophe is escaped in its MATCH clause too.
    assert "toUpper(s.name) = 'CORP\\\\O\\'BRIEN'" in cypher

    # Every single-quoted literal is balanced: stripping escaped characters must
    # leave an even number of quotes on each executable line.
    for line in cypher.splitlines():
        if not line.strip() or line.lstrip().startswith("//"):
            continue
        stripped = re.sub(r"\\.", "", line)
        assert stripped.count("'") % 2 == 0, line


def test_name_only_principal_gets_every_plausible_match_form(tmp_path):
    # BloodHound stores SAM@DOMAIN.FQDN; the GPO only gave us CORP\Helpdesk, so
    # an exact name match on its own would silently match nothing.
    result = make_result([group_setting("Administrators", member_name="CORP\\Helpdesk")])
    _summary, document, cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert "toUpper(s.name) = 'CORP\\\\HELPDESK'" in cypher
    assert "toUpper(s.samaccountname) = 'HELPDESK'" in cypher
    assert "toUpper(s.name) STARTS WITH 'HELPDESK@'" in cypher
    assert "more\n//   than one object" in cypher

    principal = next(
        node for node in document["nodes"] if node["id"] == "CORP\\HELPDESK"
    )
    assert principal["properties"]["samaccountname"] == "HELPDESK"
    assert principal["properties"]["group3rpyNetbios"] == "CORP"


def test_blank_provenance_is_omitted_not_written_empty(tmp_path):
    setting = group_setting("Administrators", source=None)
    result = make_result([setting], display_name=None)
    _summary, document, cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    properties = document["edges"][0]["properties"]
    assert "gpoDisplayName" not in properties
    assert "settingSource" not in properties
    assert "= ''" not in cypher


def test_cypher_refuses_an_unsafe_relationship_kind(tmp_path):
    nodes = {
        "A": bloodhound_export.Node(
            id="A", kinds=["Base"], properties={"group3rpyMatchBy": "name", "name": "A"}
        ),
        "B": bloodhound_export.Node(
            id="B", kinds=["Base"], properties={"group3rpyMatchBy": "name", "name": "B"}
        ),
    }
    edges = [(("A", "B", "Admin`To]-(x)"), {"source": "group3rpy"})]
    try:
        bloodhound_export.write_cypher(
            str(tmp_path / "unsafe.cypher"), nodes, edges, {"generated": "now"}
        )
    except ValueError as error:
        assert "unsafe relationship kind" in str(error)
    else:  # pragma: no cover - the guard must fire
        raise AssertionError("expected ValueError for an unsafe kind")


# --------------------------------------------------------------------- json


def test_json_is_self_describing_and_referentially_intact(tmp_path):
    result = make_result(
        [
            group_setting("Administrators"),
            PrivRightSetting(
                policy_type=PolicyType.Computer,
                privilege="SeDebugPrivilege",
                trustees=[Trustee(sid="S-1-5-21-1-2-3-1111", display_name="CORP\\Devs")],
            ),
            NtServiceSetting(
                policy_type=PolicyType.Computer,
                service_name="BackupAgent",
                account_name="CORP\\svc_backup",
            ),
        ]
    )
    summary, document, _cypher = run_export(
        tmp_path, [result], {result.attributes.uid: make_scope()}
    )

    assert set(document) == {"metadata", "nodes", "edges"}
    metadata = document["metadata"]
    assert metadata["tool"] == "group3rpy"
    assert metadata["domain"] == "corp.local"
    assert "UNVERIFIED" in metadata["schemaNote"]
    assert metadata["edgeCounts"] == summary["edge_counts"]
    assert metadata["gpos"][0]["affectedComputers"] == 3

    node_ids = {node["id"] for node in document["nodes"]}
    assert len(node_ids) == len(document["nodes"])
    for node in document["nodes"]:
        assert node["kinds"]
        assert node["kinds"][-1] == "Base"
        assert node["properties"]["group3rpyMatchBy"] in (
            "objectid",
            "distinguishedname",
            "name",
        )
    for edge in document["edges"]:
        assert edge["start"] in node_ids
        assert edge["end"] in node_ids
        assert edge["kind"] in bloodhound_export.ALL_EDGE_KINDS
        assert edge["properties"]["source"] == "group3rpy"

    computer_nodes = [
        node for node in document["nodes"] if "Computer" in node["kinds"]
    ]
    assert len(computer_nodes) == 3
    assert {node["properties"]["name"] for node in computer_nodes} == {
        "WS01.CORP.LOCAL",
        "WS02.CORP.LOCAL",
        "WS03.CORP.LOCAL",
    }
    assert summary["node_count"] == len(document["nodes"])
    assert summary["files"][0].endswith(".json")
