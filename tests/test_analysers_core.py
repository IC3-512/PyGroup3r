"""Fidelity tests for the six 'core' analysers ported from
upstream/Group3r/Assessment/Analysers/{Registry,SchedTask,Shortcut,Script,Group,File}.cs

Every expected string in here was copied out of the C# source, so a drifting
finding reason or triage level fails the test. The tests also pin down a few
upstream quirks that a "helpful" port would silently fix:

  * a RegKey rule whose Triage is Green can never fire, because the guard is
    `(int)MinTriage < (int)ruleKey.Triage` and MinTriage starts at Green;
  * several Yellow findings are guarded with `(int)MinTriage < 3`, so they survive
    `-t red` even though they are below Red;
  * SchedTask's multi-attachment message starts with a stray ", ".

Path analysis is made inert with NullFsProvider; where a writable path *is* the
point of the test, PathAnalyser is swapped for a stub that returns a canned
PathResult, so the analyser logic is what gets exercised.
"""

import warnings

import pytest

from group3rpy.ad.gpo import ScriptType, SettingAction
from group3rpy.assessment.analysers.file import FileAnalyser
from group3rpy.assessment.analysers.group import GroupAnalyser
from group3rpy.assessment.analysers.registry import RegistryAnalyser
from group3rpy.assessment.analysers.sched_task import SchedTaskAnalyser
from group3rpy.assessment.analysers.script import ScriptAnalyser
from group3rpy.assessment.analysers.shortcut import ShortcutAnalyser
from group3rpy.assessment.finding import DirPathResult, FilePathResult
from group3rpy.classifiers.constants import Triage
from group3rpy.options.assessment_options import AssessmentOptions
from group3rpy.sddl.securable_object_type import SecurableObjectType
from group3rpy.sddl.sddl import Sddl
from group3rpy.settings import (
    FileSetting,
    GroupSetting,
    GroupSettingMember,
    RegistrySetting,
    RegistryValue,
    SchedTaskEmailAction,
    SchedTaskExecAction,
    SchedTaskPrincipal,
    SchedTaskSetting,
    SchedTaskShowMessageAction,
    ScriptSetting,
    ShortcutSetting,
)
from group3rpy.smb.provider import NullFsProvider

SOURCE = "\\\\dc.test.local\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Registry.pol"


class RecordingMq:
    """Stand-in for the BlockingMq the controller injects into every analyser."""

    def __init__(self):
        self.messages: list[tuple[str, str]] = []

    def trace(self, message):
        self.messages.append(("trace", message))

    def degub(self, message):
        self.messages.append(("degub", message))

    def info(self, message):
        self.messages.append(("info", message))

    def error(self, message):
        self.messages.append(("error", message))


@pytest.fixture(scope="module")
def assessment_options() -> AssessmentOptions:
    # `[[:space:]]` in the ported Snaffler patterns makes Python warn; it is
    # verbatim from upstream, so the warning is expected here.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        options = AssessmentOptions()
    options.fs = NullFsProvider()
    return options


def run(analyser_cls, setting, assessment_options, min_triage=Triage.Green):
    analyser = analyser_cls(setting)
    analyser.mq = RecordingMq()
    analyser.min_triage = min_triage
    result = analyser.analyse(assessment_options)
    return result, analyser


def reasons(result):
    return [finding.finding_reason for finding in result.findings]


def triages(result):
    return [finding.triage for finding in result.findings]


class StubPathAnalyser:
    """Replaces PathAnalyser so the analysers see whatever PathResult we want.

    `PATHS` is consulted by path, and anything not in it analyses to None, which
    is what the real PathAnalyser returns for a path that doesn't exist.
    """

    PATHS: dict = {}

    def __init__(self, assessment_options):
        self.assessment_options = assessment_options

    def analyse_path(self, path):
        return self.PATHS.get(path)


@pytest.fixture()
def stub_paths(monkeypatch):
    """Install StubPathAnalyser into every analyser module that uses one."""
    paths: dict = {}

    class Stub(StubPathAnalyser):
        PATHS = paths

    for module in (
        "group3rpy.assessment.analysers.file",
        "group3rpy.assessment.analysers.script",
        "group3rpy.assessment.analysers.sched_task",
        "group3rpy.assessment.analysers.shortcut",
    ):
        monkeypatch.setattr(module + ".PathAnalyser", Stub)
    return paths


# --------------------------------------------------------------------- Registry


def test_registry_key_sddl_findings(assessment_options):
    """Owner + DACL assessment of an .inf-supplied registry key ACL."""
    setting = RegistrySetting(
        source=SOURCE,
        key="MACHINE\\System\\CurrentControlSet\\Services\\Fake",
        parsed_key_sddl=Sddl(
            "O:DUD:(A;;KA;;;DU)(A;;KR;;;BA)", SecurableObjectType.RegistryKey
        ),
    )

    result, _ = run(RegistryAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Found some interesting ACEs on a registry key, probably because someone was being given control of it.",
        "The Domain Users trustee has been made owner of this registry key.",
        "The Domain Users trustee has been granted rights to modify this registry key.",
        "The Domain Users trustee has been granted additional rights over this registry key.",
    ]
    assert triages(result) == [
        Triage.Green,
        Triage.Green,
        Triage.Yellow,
        Triage.Green,
    ]
    # the whole simplified ACL rides along on the first finding
    assert len(result.findings[0].acl_result) == 3
    assert result.setting is setting


def test_registry_key_sddl_findings_min_triage_red(assessment_options):
    """`-t red` drops the two `MinTriage < 2` findings and keeps the `< 3` ones.

    Keeping the owner finding (a Green) at Red is upstream behaviour: its guard is
    `(int)MinTriage < 3`, not `< 2`.
    """
    setting = RegistrySetting(
        source=SOURCE,
        key="MACHINE\\System\\CurrentControlSet\\Services\\Fake",
        parsed_key_sddl=Sddl(
            "O:DUD:(A;;KA;;;DU)(A;;KR;;;BA)", SecurableObjectType.RegistryKey
        ),
    )

    result, _ = run(RegistryAnalyser, setting, assessment_options, Triage.Red)

    assert reasons(result) == [
        "The Domain Users trustee has been made owner of this registry key.",
        "The Domain Users trustee has been granted rights to modify this registry key.",
    ]


def test_registry_high_priv_owner_and_trustee_are_boring(assessment_options):
    setting = RegistrySetting(
        source=SOURCE,
        key="MACHINE\\System\\CurrentControlSet\\Services\\Fake",
        parsed_key_sddl=Sddl(
            "O:BAD:(A;;KA;;;BA)", SecurableObjectType.RegistryKey
        ),
    )

    result, _ = run(RegistryAnalyser, setting, assessment_options)

    # the ACL is still 'interesting' enough for the blanket finding, but neither
    # the owner nor the ACE produce one, because Administrators is high priv.
    assert reasons(result) == [
        "Found some interesting ACEs on a registry key, probably because someone was being given control of it."
    ]


def test_registry_value_matches_not_default_rule(assessment_options):
    """EveryoneIncludesAnonymous=1 is a Yellow NotDefault RegKey rule."""
    rule = next(
        reg_key
        for reg_key in assessment_options.reg_keys
        if reg_key.value_name == "EveryoneIncludesAnonymous"
    )
    setting = RegistrySetting(
        source=SOURCE,
        key="MACHINE\\System\\CurrentControlSet\\Control\\Lsa",
        values=[
            RegistryValue(value_name="EveryoneIncludesAnonymous", value_bytes=b"1")
        ],
    )

    result, _ = run(RegistryAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "This registry key was set to a non-default value, which was interesting enough for me."
    ]
    assert triages(result) == [Triage.Yellow]
    assert result.findings[0].finding_detail == (
        rule.friendly_description + " " + rule.ms_desc
    )

    # `(int)MinTriage < (int)ruleKey.Triage` -> Red suppresses a Yellow rule.
    suppressed, _ = run(RegistryAnalyser, setting, assessment_options, Triage.Red)
    assert suppressed.findings == []


def test_registry_value_matching_default_is_not_a_finding(assessment_options):
    setting = RegistrySetting(
        source=SOURCE,
        key="MACHINE\\System\\CurrentControlSet\\Control\\Lsa",
        values=[
            RegistryValue(value_name="EveryoneIncludesAnonymous", value_bytes=b"0")
        ],
    )

    result, _ = run(RegistryAnalyser, setting, assessment_options)

    assert result.findings == []


def test_registry_less_than_good_rule_is_black(assessment_options):
    """LmCompatibilityLevel < 3 is the one Black LessThanGood rule."""
    setting = RegistrySetting(
        source=SOURCE,
        key="MACHINE\\System\\CurrentControlSet\\Control\\Lsa",
        values=[RegistryValue(value_name="LmCompatibilityLevel", value_bytes=b"1")],
    )

    result, _ = run(RegistryAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "This registry key was set to a 'less-than-good' value, which made it interesting."
    ]
    assert triages(result) == [Triage.Black]

    # and a good value is not a finding at all
    setting.values = [
        RegistryValue(value_name="LmCompatibilityLevel", value_bytes=b"5")
    ]
    ok, _ = run(RegistryAnalyser, setting, assessment_options)
    assert ok.findings == []


def test_registry_present_rule_fires_at_its_own_triage(assessment_options):
    setting = RegistrySetting(
        source=SOURCE,
        key="MACHINE\\Software\\ORL\\WinVNC3",
        values=[RegistryValue()],
    )

    result, _ = run(RegistryAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "This registry key being present at all is considered interesting."
    ]
    assert triages(result) == [Triage.Red]


def test_registry_uninteresting_key_produces_nothing(assessment_options):
    setting = RegistrySetting(
        source=SOURCE,
        key="MACHINE\\Software\\Definitely\\Not\\Interesting",
        values=[RegistryValue(value_name="Whatever", value_bytes=b"1")],
    )

    result, _ = run(RegistryAnalyser, setting, assessment_options)

    assert result.findings == []


# -------------------------------------------------------------------- SchedTask


def test_sched_task_cpassword_is_black(assessment_options):
    principal = SchedTaskPrincipal(
        id="Author", cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
    )
    setting = SchedTaskSetting(source=SOURCE, principals=[principal])

    result, _ = run(SchedTaskAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Group Policy Preferences password found:Local*P4ssword!"
    ]
    assert triages(result) == [Triage.Black]
    assert result.findings[0].finding_detail == (
        "Refer to MS14-025 and https://adsecurity.org/?p=63"
    )
    # the decrypted password is written back onto the principal
    assert principal.password == "Local*P4ssword!"


def test_sched_task_no_principals_no_findings(assessment_options):
    setting = SchedTaskSetting(source=SOURCE, principals=[SchedTaskPrincipal()])

    result, _ = run(SchedTaskAnalyser, setting, assessment_options)

    assert result.findings == []


def test_sched_task_exec_args_look_like_a_password(assessment_options):
    setting = SchedTaskSetting(
        source=SOURCE,
        actions=[
            SchedTaskExecAction(
                command="C:\\windows\\system32\\cmd.exe", args="/c net use /PASSWORD:hunter2"
            )
        ],
    )

    result, _ = run(SchedTaskAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Scheduled Task exec action has an arguments setting that looks like it might have a password in it?"
    ]
    assert triages(result) == [Triage.Yellow]
    assert result.findings[0].finding_detail == (
        "Arguments were: /c net use /PASSWORD:hunter2"
    )

    # upstream guards this Yellow with `(int)MinTriage < 3`, so Red keeps it...
    at_red, _ = run(SchedTaskAnalyser, setting, assessment_options, Triage.Red)
    assert len(at_red.findings) == 1
    # ...and only Black drops it.
    at_black, _ = run(SchedTaskAnalyser, setting, assessment_options, Triage.Black)
    assert at_black.findings == []


def test_sched_task_boring_exec_action(assessment_options):
    setting = SchedTaskSetting(
        source=SOURCE,
        actions=[
            SchedTaskExecAction(command="C:\\windows\\system32\\cmd.exe", args="/c exit")
        ],
    )

    result, _ = run(SchedTaskAnalyser, setting, assessment_options)

    assert result.findings == []


def test_sched_task_email_attachments_keep_the_stray_separator(assessment_options):
    one = SchedTaskSetting(
        source=SOURCE, actions=[SchedTaskEmailAction(attachments=["\\\\dc\\share\\a.txt"])]
    )
    result, _ = run(SchedTaskAnalyser, one, assessment_options)
    assert reasons(result) == [
        "Scheduled Task is emailing attachments. Could be interesting."
    ]
    assert triages(result) == [Triage.Green]
    assert result.findings[0].finding_detail == "Check out \\\\dc\\share\\a.txt"

    many = SchedTaskSetting(
        source=SOURCE,
        actions=[SchedTaskEmailAction(attachments=["a.txt", "b.txt"])],
    )
    result, _ = run(SchedTaskAnalyser, many, assessment_options)
    # the original builds this with `attachments + ", " + attachment` from an
    # empty string, so the leading ", " is expected.
    assert result.findings[0].finding_detail == "Check out , a.txt, b.txt"


def test_sched_task_show_message_only_traces(assessment_options):
    setting = SchedTaskSetting(
        source=SOURCE, actions=[SchedTaskShowMessageAction(title="hi", body="there")]
    )

    result, analyser = run(SchedTaskAnalyser, setting, assessment_options)

    assert result.findings == []
    assert analyser.mq.messages == [
        (
            "trace",
            "Scheduled tasks that just show messages probably aren't worth a finding. Also I've never seen this used IRL.",
        )
    ]


def test_sched_task_writable_command_is_red(assessment_options, stub_paths):
    path = "\\\\dc\\share\\task.exe"
    stub_paths[path] = FilePathResult(
        assessed_path=path, file_exists=True, file_writable=True
    )
    setting = SchedTaskSetting(
        source=SOURCE, actions=[SchedTaskExecAction(command=path)]
    )

    result, _ = run(SchedTaskAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Scheduled Task execute action points at a file that you can modify."
    ]
    assert triages(result) == [Triage.Red]
    assert result.findings[0].finding_detail == (
        "It points to \\\\dc\\share\\task.exe, so maybe see what happens if you modify that file."
    )


def test_sched_task_writable_working_dir_is_yellow(assessment_options, stub_paths):
    path = "\\\\dc\\share\\workdir"
    stub_paths[path] = DirPathResult(
        assessed_path=path, directory_exists=True, directory_writable=True
    )
    setting = SchedTaskSetting(
        source=SOURCE,
        actions=[SchedTaskExecAction(command="C:\\x.exe", working_dir=path)],
    )

    result, _ = run(SchedTaskAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Scheduled task exec action is configured to use a working directory that you can write to."
    ]
    assert triages(result) == [Triage.Yellow]
    assert result.findings[0].finding_detail == (
        "You might be able to pull some DLL sideloading shenanigans in \\\\dc\\share\\workdir"
    )


def test_sched_task_source_in_ntfrs_marks_setting_morphed(assessment_options):
    setting = SchedTaskSetting(source="\\\\dc\\sysvol\\NTFRS_0123abc\\whatever.xml")

    run(SchedTaskAnalyser, setting, assessment_options)

    assert setting.is_morphed is True


# --------------------------------------------------------------------- Shortcut


def test_shortcut_writable_target_is_red(assessment_options, stub_paths):
    path = "\\\\dc\\share\\thing.exe"
    stub_paths[path] = FilePathResult(
        assessed_path=path, file_exists=True, file_writable=True
    )
    setting = ShortcutSetting(source=SOURCE, target_path=path, start_in="", arguments="")

    result, _ = run(ShortcutAnalyser, setting, assessment_options)

    assert reasons(result) == ["Shortcut points at a file that you can modify."]
    assert triages(result) == [Triage.Red]
    assert result.findings[0].finding_detail == (
        "It points to \\\\dc\\share\\thing.exe so maybe see what happens if you modify that file."
    )


def test_shortcut_missing_target_with_writable_parent(assessment_options, stub_paths):
    path = "\\\\dc\\share\\nope\\thing.exe"
    stub_paths[path] = FilePathResult(
        assessed_path=path,
        parent_directory_exists="\\\\dc\\share",
        parent_directory_writable=True,
    )
    setting = ShortcutSetting(source=SOURCE, target_path=path, start_in="", arguments="")

    result, _ = run(ShortcutAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Shortcut points to a file that doesn't exist, in a directory that ALSO doesn't exist, but there's a parent directory that DOES exist that you can write to."
    ]
    assert triages(result) == [Triage.Red]


def test_shortcut_writable_start_in_is_yellow(assessment_options, stub_paths):
    start_in = "\\\\dc\\share\\workdir"
    stub_paths[start_in] = DirPathResult(
        assessed_path=start_in, directory_exists=True, directory_writable=True
    )
    setting = ShortcutSetting(
        source=SOURCE, target_path="C:\\x.exe", start_in=start_in, arguments=""
    )

    result, _ = run(ShortcutAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Shortcut is configured to use a working directory that you can write to."
    ]
    assert triages(result) == [Triage.Yellow]


def test_shortcut_arguments_are_case_sensitive(assessment_options):
    """`setting.Arguments.Contains("pass")` has no ToLower() in Shortcut.cs."""
    lower = ShortcutSetting(
        source=SOURCE,
        target_path="C:\\x.exe",
        start_in="",
        arguments="-password hunter2",
    )
    result, _ = run(ShortcutAnalyser, lower, assessment_options)
    assert reasons(result) == [
        "Shortcut has an arguments setting that looks like it might have a password in it?"
    ]
    assert triages(result) == [Triage.Yellow]
    assert result.findings[0].finding_detail == "Arguments were: -password hunter2"

    upper = ShortcutSetting(
        source=SOURCE, target_path="C:\\x.exe", start_in="", arguments="-PASSWORD hunter2"
    )
    result, _ = run(ShortcutAnalyser, upper, assessment_options)
    assert result.findings == []


def test_shortcut_local_target_produces_nothing(assessment_options):
    setting = ShortcutSetting(
        source=SOURCE,
        target_path="C:\\Program Files\\thing\\thing.exe",
        start_in="C:\\Program Files\\thing",
        arguments="-quiet",
    )

    result, _ = run(ShortcutAnalyser, setting, assessment_options)

    assert result.findings == []


# ----------------------------------------------------------------------- Script


def test_script_parameters_look_like_a_password(assessment_options):
    setting = ScriptSetting(
        source="\\\\dc\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Scripts\\scripts.ini",
        script_type=ScriptType.Startup,
        cmd_line="setup.bat",
        parameters="-Password hunter2",
    )

    result, _ = run(ScriptAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Startup script has an arguments setting that looks like it might have a password in it?"
    ]
    assert triages(result) == [Triage.Yellow]
    assert result.findings[0].finding_detail == "Arguments were: -Password hunter2"

    # guarded with `(int)MinTriage < 3` upstream, so Red keeps it and Black drops it
    at_red, _ = run(ScriptAnalyser, setting, assessment_options, Triage.Red)
    assert len(at_red.findings) == 1
    at_black, _ = run(ScriptAnalyser, setting, assessment_options, Triage.Black)
    assert at_black.findings == []


def test_script_boring_parameters(assessment_options):
    setting = ScriptSetting(
        source="\\\\dc\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Scripts\\scripts.ini",
        script_type=ScriptType.Logon,
        cmd_line="logon.bat",
        parameters="-quiet",
    )

    result, _ = run(ScriptAnalyser, setting, assessment_options)

    assert result.findings == []


def test_script_writable_file_is_black(assessment_options, stub_paths):
    """A relative CmdLine is resolved against <gpo dir>\\<ScriptType>\\."""
    source = "\\\\dc\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Scripts\\scripts.ini"
    resolved = (
        "\\\\dc\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Scripts\\Logon\\logon.bat"
    )
    stub_paths[resolved] = FilePathResult(
        assessed_path=resolved, file_exists=True, file_writable=True
    )
    setting = ScriptSetting(
        source=source,
        script_type=ScriptType.Logon,
        cmd_line="logon.bat",
        parameters="",
    )

    result, _ = run(ScriptAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Writable Logon script file identified at " + resolved
    ]
    assert triages(result) == [Triage.Black]
    assert result.findings[0].finding_detail == (
        "This script will run in the context of the users/computers to which this GPO is applied. "
        "Change the script, get command exec as those users/computers."
    )
    assert result.findings[0].path_findings == [stub_paths[resolved]]


def test_script_writable_dir_is_a_green_misconfig(assessment_options, stub_paths):
    resolved = (
        "\\\\dc\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Scripts\\Logon\\logon.bat"
    )
    stub_paths[resolved] = DirPathResult(
        assessed_path=resolved, directory_exists=True, directory_writable=True
    )
    setting = ScriptSetting(
        source="\\\\dc\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Scripts\\scripts.ini",
        script_type=ScriptType.Logon,
        cmd_line="logon.bat",
        parameters="",
    )

    result, _ = run(ScriptAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Honestly this looks like a misconfigured Logon script setting in a GPO or a bug in Group3r."
    ]
    assert triages(result) == [Triage.Green]

    # this one really is guarded with `(int)MinTriage < 2`
    at_red, _ = run(ScriptAnalyser, setting, assessment_options, Triage.Red)
    assert at_red.findings == []


def test_script_missing_file_with_writable_parent_is_red(
    assessment_options, stub_paths
):
    resolved = (
        "\\\\dc\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Scripts\\Logon\\logon.bat"
    )
    parent = "\\\\dc\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Scripts"
    stub_paths[resolved] = FilePathResult(
        assessed_path=resolved,
        parent_directory_exists=parent,
        parent_directory_writable=True,
    )
    setting = ScriptSetting(
        source="\\\\dc\\sysvol\\test.local\\Policies\\{GUID}\\Machine\\Scripts\\scripts.ini",
        script_type=ScriptType.Logon,
        cmd_line="logon.bat",
        parameters="",
    )

    result, _ = run(ScriptAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Missing Logon script with a writable parent dir identified at "
        + parent
        + ". The original target path was "
        + resolved
    ]
    assert triages(result) == [Triage.Red]


# ------------------------------------------------------------------------ Group


def test_group_low_priv_member_added_to_privileged_group(assessment_options):
    setting = GroupSetting(
        source=SOURCE,
        name="Administrators",
        action=SettingAction.Update,
        members=[GroupSettingMember(name="Domain Users")],
    )

    result, _ = run(GroupAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "A privileged local group is having a low-priv member added to it."
    ]
    assert triages(result) == [Triage.Red]
    assert result.findings[0].finding_detail == (
        "Group Administrators is having Domain Users added to it."
    )


def test_group_unknown_member_added_to_privileged_group_is_green(assessment_options):
    setting = GroupSetting(
        source=SOURCE,
        name="Administrators",
        action=SettingAction.Add,
        members=[GroupSettingMember(name="TESTLAB\\svc_backup")],
    )

    result, analyser = run(GroupAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "A privileged local group is having a member added to it. Might be interesting, hard to say."
    ]
    assert triages(result) == [Triage.Green]
    assert result.findings[0].finding_detail == (
        "Group Administrators is having TESTLAB\\svc_backup added to it."
    )
    # an unresolvable member is swallowed silently (the Mq.Trace is commented out
    # upstream), so nothing should have been logged.
    assert analyser.mq.messages == []

    # `(int)MinTriage < 2` -> Red suppresses it
    at_red, _ = run(GroupAnalyser, setting, assessment_options, Triage.Red)
    assert at_red.findings == []


def test_group_rename_of_privileged_group_is_green(assessment_options):
    setting = GroupSetting(
        source=SOURCE,
        name="Administrators",
        new_name="Wheel",
        action=SettingAction.Update,
    )

    result, _ = run(GroupAnalyser, setting, assessment_options)

    assert reasons(result) == ["A privileged local group is being renamed."]
    assert triages(result) == [Triage.Green]
    assert result.findings[0].finding_detail == (
        "Group Administrators is being renamed to Wheel"
    )

    at_red, _ = run(GroupAnalyser, setting, assessment_options, Triage.Red)
    assert at_red.findings == []


def test_group_sid_lookup_and_unresolvable_group_traces(assessment_options):
    """A group named by SID resolves; an unknown one falls into the catch."""
    by_sid = GroupSetting(
        source=SOURCE,
        name="S-1-5-32-544",
        action=SettingAction.Update,
        members=[GroupSettingMember(name="Everyone")],
    )
    result, analyser = run(GroupAnalyser, by_sid, assessment_options)
    assert reasons(result) == [
        "A privileged local group is having a low-priv member added to it."
    ]
    assert analyser.mq.messages == []

    unknown = GroupSetting(
        source=SOURCE,
        name="Totally Made Up Group",
        action=SettingAction.Update,
        members=[GroupSettingMember(name="Domain Users")],
    )
    result, analyser = run(GroupAnalyser, unknown, assessment_options)
    assert result.findings == []
    assert len(analyser.mq.messages) == 1
    kind, message = analyser.mq.messages[0]
    assert kind == "trace"
    assert message.startswith(
        "Group Totally Made Up Group threw an error trying to match it to a well "
        "known name or well known sid."
    )


def test_group_delete_all_and_remove_actions_are_not_findings(assessment_options):
    deleting = GroupSetting(
        source=SOURCE,
        name="Administrators",
        action=SettingAction.Update,
        delete_all_users=True,
        members=[GroupSettingMember(name="Domain Users")],
    )
    assert run(GroupAnalyser, deleting, assessment_options)[0].findings == []

    removing = GroupSetting(
        source=SOURCE,
        name="Administrators",
        action=SettingAction.Remove,
        members=[GroupSettingMember(name="Domain Users")],
    )
    assert run(GroupAnalyser, removing, assessment_options)[0].findings == []

    unprivileged = GroupSetting(
        source=SOURCE,
        name="Users",
        action=SettingAction.Update,
        members=[GroupSettingMember(name="Domain Users")],
    )
    assert run(GroupAnalyser, unprivileged, assessment_options)[0].findings == []


# ------------------------------------------------------------------------- File


def test_file_writable_source_is_red(assessment_options, stub_paths):
    from_path = "\\\\dc\\share\\template\\app.config"
    stub_paths[from_path] = FilePathResult(
        assessed_path=from_path, file_exists=True, file_writable=True
    )
    setting = FileSetting(
        source=SOURCE,
        from_path=from_path,
        target_path="C:\\Program Files\\app\\app.config",
    )

    result, _ = run(FileAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Writable file identified at "
        + from_path
        + " to be copied to C:\\Program Files\\app\\app.config"
    ]
    assert triages(result) == [Triage.Red]
    assert result.findings[0].finding_detail.startswith(
        "This GPO setting will copy a file from point A to point B."
    )


def test_file_writable_dir_is_a_green_misconfig(assessment_options, stub_paths):
    from_path = "\\\\dc\\share\\template"
    stub_paths[from_path] = DirPathResult(
        assessed_path=from_path, directory_exists=True, directory_writable=True
    )
    setting = FileSetting(
        source=SOURCE, from_path=from_path, target_path="C:\\temp\\whatever"
    )

    result, _ = run(FileAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "Honestly this looks like a misconfigured GPP File GPO setting, or a bug in Group3r."
    ]
    assert triages(result) == [Triage.Green]

    at_red, _ = run(FileAnalyser, setting, assessment_options, Triage.Red)
    assert at_red.findings == []


def test_file_missing_source_with_writable_parent_is_yellow(
    assessment_options, stub_paths
):
    from_path = "\\\\dc\\share\\template\\missing.config"
    parent = "\\\\dc\\share\\template"
    stub_paths[from_path] = FilePathResult(
        assessed_path=from_path,
        parent_directory_exists=parent,
        parent_directory_writable=True,
    )
    setting = FileSetting(
        source=SOURCE, from_path=from_path, target_path="C:\\temp\\missing.config"
    )

    result, _ = run(FileAnalyser, setting, assessment_options)

    assert reasons(result) == [
        "A GPP File GPO setting is missing its source file, and it has a writable "
        "parent dir identified at "
        + parent
        + ". The original target path was "
        + from_path
        + ". Depending on the file type you might be able to do something fun?"
    ]
    assert triages(result) == [Triage.Yellow]

    # guarded with `(int)MinTriage < 3`, so Red keeps it and Black drops it
    at_red, _ = run(FileAnalyser, setting, assessment_options, Triage.Red)
    assert len(at_red.findings) == 1
    at_black, _ = run(FileAnalyser, setting, assessment_options, Triage.Black)
    assert at_black.findings == []


def test_file_drive_letter_source_is_never_analysed(assessment_options, stub_paths):
    """`Char.IsLetter(fromPath.FirstOrDefault())` short-circuits drive letters."""
    from_path = "C:\\share\\template\\app.config"
    stub_paths[from_path] = FilePathResult(
        assessed_path=from_path, file_exists=True, file_writable=True
    )
    setting = FileSetting(
        source=SOURCE, from_path=from_path, target_path="C:\\temp\\app.config"
    )

    result, _ = run(FileAnalyser, setting, assessment_options)

    assert result.findings == []


def test_file_without_paths_produces_nothing(assessment_options):
    setting = FileSetting(source=SOURCE)

    result, _ = run(FileAnalyser, setting, assessment_options)

    assert result.findings == []
