"""Fidelity tests for the SYSVOL file parsers ported from
upstream/LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/

Realistic fixture files are written into a temp dir and driven through
`GpoFileFactory` + `LocalFsProvider`, i.e. the same route Sysvol takes, so the
tests cover factory dispatch, the BOM/encoding sniffing, and each parser's field
mapping.

They also pin down upstream quirks that a "helpful" port would quietly fix:

  * GptTmpl.inf `[Event Audit]` settings are parsed and then never added to
    Settings, so they do not come out of the parser at all;
  * `Registry Values` drops the first *and* last element of the key path, since
    the last one is the value name;
  * registry.pol keys lose their first path component the same way;
  * GPP boolean attributes written as "1"/"0" do not parse, because
    Boolean.TryParse only accepts "true"/"false";
  * `IniFiles` settings never get an Action, because the C# throws away the
    result of ParseSettingAction;
  * `Enum.TryParse` failure leaves the *zero-valued* enum member, not the value
    the variable was seeded with, so an unparseable GPP hive becomes
    HKEY_CLASSES_ROOT rather than the HKEY_LOCAL_MACHINE the comment claims.
"""

import os
import struct

import pytest

from group3rpy.ad.gpo import PolicyType, ScriptType, SettingAction
from group3rpy.settings import (
    DataSourceSetting,
    DriveSetting,
    GroupSetting,
    IniFileSetting,
    KerbPolicySetting,
    NtServiceSetting,
    PrivRightSetting,
    RegHive,
    RegistrySetting,
    RegKeyValType,
    SchedTaskExecAction,
    SchedTaskSetting,
    SchedTaskType,
    ScriptSetting,
    SystemAccessSetting,
    UserSetting,
)
from group3rpy.smb.provider import LocalFsProvider
from group3rpy.sysvol.gpo_file_factory import GpoFileFactory
from group3rpy.sysvol.inf_gpo_file import InfGpoFile
from group3rpy.sysvol.ini_gpo_file import IniGpoFile
from group3rpy.sysvol.pol_gpo_file import PolGpoFile
from group3rpy.sysvol.sysvol import Sysvol
from group3rpy.sysvol.xml_gpo_file import XmlGpoFile

TEST_SYSVOL = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "upstream",
    "TestSysvol",
)

# The published GPP test vector -- MS14-025 / Get-GPPPassword's example blob.
CPASSWORD = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
CPASSWORD_PLAINTEXT = "Local*P4ssword!"


class RecordingLogger:
    """Stands in for BlockingMq; keeps every message so log text can be asserted."""

    def __init__(self):
        self.traces = []
        self.degubs = []
        self.errors = []

    def trace(self, message):
        self.traces.append(message)

    def degub(self, message):
        self.degubs.append(message)

    def error(self, message):
        self.errors.append(message)


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

GROUPS_XML = """<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2015-08-25 12:01:20" uid="{5F27ADB9-1F0F-4D8C-8FA7-62ABD3CB0A4B}">
    <Properties action="U" newName="" description="local admins" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
      <Members>
        <Member name="EXAMPLE\\Domain Users" action="ADD" sid="S-1-5-21-1111111111-2222222222-3333333333-513"/>
        <Member name="EXAMPLE\\itguy" action="REMOVE" sid=""/>
      </Members>
    </Properties>
  </Group>
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="EXAMPLE\\localadmin" image="2" changed="2015-08-25 12:02:00" uid="{B7BD1F0F-0D08-4B67-8B02-1E1ADAF39CBD}">
    <Properties action="U" newName="" fullName="Local Admin" description="backdoor" cpassword="{cpassword}" changeLogon="0" noChange="1" neverExpires="true" acctDisabled="false" userName="EXAMPLE\\localadmin"/>
  </User>
</Groups>
""".replace("{cpassword}", CPASSWORD)

REGISTRY_XML = """<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">
  <Collection clsid="{53B533F5-224C-47e3-B01B-CA3B3F3FFEB9}" name="Autologon">
    <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="DefaultPassword" status="DefaultPassword" image="12" changed="2015-08-25 12:01:20" uid="{19A2ED4C-3C6E-4C6E-9F1C-2CC4AA4EDBBF}" displayDecimal="0">
      <Properties action="U" displayDecimal="0" default="0" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" name="DefaultPassword" type="REG_SZ" value="Summer2015!"/>
    </Registry>
  </Collection>
  <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="AutoAdminLogon" status="AutoAdminLogon" image="12" uid="{0C1B2F0B-2C27-4BFC-9B22-0F1C6D4B2AB3}">
    <Properties action="C" displayDecimal="1" default="0" hive="HKEY_WRONG_HIVE" key="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" name="AutoAdminLogon" type="REG_DWORD" value="1"/>
  </Registry>
</RegistrySettings>
"""

SCHEDULED_TASKS_XML = """<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <Task clsid="{2DB5A4B2-8F19-4e93-9C3E-CCCCDFE4E6DB}" name="Legacy Task" image="0" changed="2015-08-25 12:01:20" uid="{07C3FA1B-45A7-4C7E-B2C8-0FA8D6CB43A0}">
    <Properties action="C" name="Legacy Task" appName="C:\\scripts\\legacy.exe" args="-quiet" startIn="C:\\scripts" comment="does a thing" enabled="true" deleteWhenDone="0" startOnlyIfIdle="false" stopOnIdleEnd="true" noStartIfOnBatteries="1" stopIfGoingOnBatteries="true" systemRequired="false" runAs="EXAMPLE\\svc_legacy" logonType="Password" cpassword="{cpassword}">
      <Triggers>
        <Trigger type="DAILY" startHour="3" startMinutes="30" beginYear="2015" beginMonth="8" beginDay="25" hasEndDate="0" repeatTask="0"/>
      </Triggers>
    </Properties>
  </Task>
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="Modern Task" image="0" changed="2015-08-25 13:00:00" uid="{5B1C0EAE-6F44-4E69-8B7F-1E1B9E3DCE72}">
    <Properties action="R" name="Modern Task" runAs="EXAMPLE\\svc_modern" logonType="Password" comment="v2 comment" systemRequired="true">
      <Task version="1.3">
        <RegistrationInfo>
          <Author>EXAMPLE\\admin</Author>
          <Description>runs the thing</Description>
        </RegistrationInfo>
        <Principals>
          <Principal id="Author">
            <UserId>EXAMPLE\\svc_modern</UserId>
            <LogonType>Password</LogonType>
            <RunLevel>HighestAvailable</RunLevel>
            <Cpassword>{cpassword}</Cpassword>
          </Principal>
        </Principals>
        <Settings>
          <IdleSettings>
            <Duration>PT10M</Duration>
            <WaitTimeout>PT1H</WaitTimeout>
            <StopOnIdleEnd>true</StopOnIdleEnd>
            <RestartOnIdle>false</RestartOnIdle>
          </IdleSettings>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
          <AllowHardTerminate>true</AllowHardTerminate>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <Enabled>true</Enabled>
          <Hidden>true</Hidden>
          <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
          <Priority>7</Priority>
        </Settings>
        <Triggers>
          <CalendarTrigger>
            <StartBoundary>2015-08-25T13:00:00</StartBoundary>
          </CalendarTrigger>
          <BootTrigger/>
        </Triggers>
        <Actions Context="Author">
          <Exec>
            <Command>\\\\dc1\\netlogon\\payload.exe</Command>
            <Arguments>-force</Arguments>
            <WorkingDirectory>C:\\Windows\\Temp</WorkingDirectory>
          </Exec>
          <ShowMessage>
            <Title>hello</Title>
            <Body>world</Body>
          </ShowMessage>
          <SendEmail>
            <From>gpo@example.com</From>
            <To>admin@example.com</To>
            <Subject>done</Subject>
            <Body>it ran</Body>
            <HeaderFields>X-Thing: yes</HeaderFields>
            <Attachments>
              <File>C:\\logs\\one.log</File>
              <File>C:\\logs\\two.log</File>
            </Attachments>
            <Server>smtp.example.com</Server>
          </SendEmail>
        </Actions>
      </Task>
    </Properties>
  </TaskV2>
</ScheduledTasks>
""".replace("{cpassword}", CPASSWORD)

SERVICES_XML = """<?xml version="1.0" encoding="utf-8"?>
<NTServices clsid="{2CFB484A-4E96-4b5d-A0B6-093D2F91E6AE}">
  <NTService clsid="{AB6F0B22-341F-4dbc-AB0F-A0F0A98BB88F}" name="AppSvc" image="4" changed="2015-08-25 12:01:20" uid="{7E1AB2D5-0E4D-4F0F-9A52-DE2C3E4EB8B1}">
    <Properties startupType="AUTOMATIC" serviceName="AppSvc" serviceAction="START" timeout="30" program="C:\\app\\app.exe" arguments="-run" accountName="EXAMPLE\\svc_app" userName="EXAMPLE\\svc_app" cpassword="{cpassword}" firstFailure="RESTART" resetFailCountDelay="1" append="0" interact="1"/>
  </NTService>
</NTServices>
""".replace("{cpassword}", CPASSWORD)

DRIVES_XML = """<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="P:" status="P:" image="2" changed="2015-08-25 12:01:20" uid="{D7CE3B7E-8B9D-4AF9-9F1B-C4B1DF8C2E98}">
    <Properties action="U" thisDrive="SHOW" allDrives="NOCHANGE" userName="EXAMPLE\\svc_maps" cpassword="{cpassword}" path="\\\\fileserver\\profiles" label="Profiles" persistent="1" useLetter="1" letter="P"/>
  </Drive>
</Drives>
""".replace("{cpassword}", CPASSWORD)

INI_FILES_XML = """<?xml version="1.0" encoding="utf-8"?>
<IniFiles clsid="{694CC220-C298-4b62-8CA1-ECDFEF4A75B4}">
  <Ini clsid="{E1D94B2F-3E4D-4D2F-8C6A-8D04AB7B1E9B}" name="app.ini" image="0" changed="2015-08-25 12:01:20" uid="{7C1D5AE4-7C3F-4D0D-9F60-4EEDE41C6F9A}">
    <Properties action="U" path="C:\\app\\app.ini" section="creds" property="password" value="Sup3rSecret"/>
  </Ini>
</IniFiles>
"""

DATASOURCES_XML = """<?xml version="1.0" encoding="utf-8"?>
<DataSources clsid="{3BFAE07A-5F73-4ACC-B5D9-5B2D1AF54BE2}">
  <DataSource clsid="{6E9C0BC5-D0F1-4A7D-AFBD-C8C0C0B7AE0C}" name="AppDSN" image="0" changed="2015-08-25 12:01:20" uid="{1FEB6E0B-91B7-4C5E-9DAB-ED8DA9B0D6A6}">
    <Properties action="C" userDSN="0" dsn="AppDSN" driver="SQL Server" description="app db" username="sa" cpassword="{cpassword}"/>
  </DataSource>
</DataSources>
""".replace("{cpassword}", CPASSWORD)

SCRIPTS_INI = (
    "[Startup]\r\n"
    "0CmdLine=startup.bat\r\n"
    "0Parameters=\r\n"
    "1CmdLine=\\\\dc1\\netlogon\\map.vbs\r\n"
    "1Parameters=-quiet\r\n"
    "[Shutdown]\r\n"
    "0CmdLine=bye.bat\r\n"
    "0Parameters=now\r\n"
)

PSSCRIPTS_INI = (
    "[Logon]\r\n"
    "0CmdLine=logon.ps1\r\n"
    "0Parameters=-NoProfile\r\n"
    "[ScriptsConfig]\r\n"
    "StartExecutePSFirst=true\r\n"
    "EndExecutePSFirst=false\r\n"
)

GPTTMPL_INF = (
    "[Unicode]\r\n"
    "Unicode=yes\r\n"
    "[System Access]\r\n"
    "MinimumPasswordAge = 1\r\n"
    "MaximumPasswordAge = 42\r\n"
    "ClearTextPassword = 1\r\n"
    "[Kerberos Policy]\r\n"
    "MaxTicketAge = 10\r\n"
    "[Event Audit]\r\n"
    "AuditLogonEvents = 3\r\n"
    "[Privilege Rights]\r\n"
    "SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,EXAMPLE\\itguy\r\n"
    "SeDenyBatchLogonRight = \r\n"
    "[Registry Values]\r\n"
    "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,1\r\n"
    "MACHINE\\Software\\Policies\\Thing\\Banner=1,hello there\r\n"
    "[Version]\r\n"
    'signature="$CHICAGO$"\r\n'
    "Revision=1\r\n"
)


def _pol_bytes(records, version=1):
    """Build a registry.pol image the way the Windows client writes one."""

    def u(text):
        return text.encode("utf-16-le")

    out = b"PReg" + struct.pack("<I", version)
    for key, value_name, val_type, data in records:
        out += u("[")
        out += u(key) + u("\0")
        out += u(";")
        out += u(value_name) + u("\0")
        out += u(";")
        out += struct.pack("<I", val_type)
        out += u(";")
        out += struct.pack("<I", len(data))
        out += u(";")
        out += data
        out += u("]")
    return out


MACHINE_POL = _pol_bytes(
    [
        (
            "Software\\Policies\\Microsoft\\Windows\\Installer",
            "AlwaysInstallElevated",
            int(RegKeyValType.REG_DWORD),
            struct.pack("<i", 1),
        ),
        (
            "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
            "fAllowUnsolicited",
            int(RegKeyValType.REG_SZ),
            "yes\0".encode("utf-16-le"),
        ),
    ]
)

USER_POL = _pol_bytes(
    [
        (
            "Software\\Policies\\Example",
            "UserThing",
            int(RegKeyValType.REG_DWORD),
            struct.pack("<i", 7),
        )
    ]
)


@pytest.fixture()
def sysvol(tmp_path):
    """Lays out a miniature SYSVOL and returns (root, LocalFsProvider)."""
    gpo = tmp_path / "Policies" / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    machine = gpo / "Machine"
    user = gpo / "User"
    for sub in (
        machine / "Preferences" / "Groups",
        machine / "Preferences" / "Registry",
        machine / "Preferences" / "ScheduledTasks",
        machine / "Preferences" / "Services",
        machine / "Preferences" / "IniFiles",
        machine / "Microsoft" / "Windows NT" / "SecEdit",
        machine / "Scripts",
        user / "Preferences" / "Drives",
        user / "Preferences" / "DataSources",
        user / "Scripts",
    ):
        sub.mkdir(parents=True, exist_ok=True)

    # UTF-8 with a BOM, which is what the GPMC writes for preference XML.
    (machine / "Preferences" / "Groups" / "Groups.xml").write_bytes(
        b"\xef\xbb\xbf" + GROUPS_XML.encode("utf-8")
    )
    (machine / "Preferences" / "Registry" / "Registry.xml").write_bytes(
        REGISTRY_XML.encode("utf-8")
    )
    (machine / "Preferences" / "ScheduledTasks" / "ScheduledTasks.xml").write_bytes(
        SCHEDULED_TASKS_XML.encode("utf-8")
    )
    (machine / "Preferences" / "Services" / "Services.xml").write_bytes(
        SERVICES_XML.encode("utf-8")
    )
    (machine / "Preferences" / "IniFiles" / "IniFiles.xml").write_bytes(
        INI_FILES_XML.encode("utf-8")
    )
    (user / "Preferences" / "Drives" / "Drives.xml").write_bytes(
        DRIVES_XML.encode("utf-8")
    )
    (user / "Preferences" / "DataSources" / "DataSources.xml").write_bytes(
        DATASOURCES_XML.encode("utf-8")
    )
    # GptTmpl.inf is UTF-16LE with a BOM in the wild.
    (machine / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf").write_bytes(
        b"\xff\xfe" + GPTTMPL_INF.encode("utf-16-le")
    )
    (machine / "Scripts" / "scripts.ini").write_bytes(
        b"\xff\xfe" + SCRIPTS_INI.encode("utf-16-le")
    )
    (user / "Scripts" / "psscripts.ini").write_bytes(PSSCRIPTS_INI.encode("utf-8"))
    (machine / "Registry.pol").write_bytes(MACHINE_POL)
    (user / "Registry.pol").write_bytes(USER_POL)
    return tmp_path, LocalFsProvider()


def parse(path, fs, logger=None):
    gpo_file = GpoFileFactory.get_file(str(path), fs, logger)
    gpo_file.parse()
    return gpo_file


def only(settings, cls):
    return [s for s in settings if isinstance(s, cls)]


# --------------------------------------------------------------------------- #
# factory
# --------------------------------------------------------------------------- #


def test_factory_dispatch(sysvol):
    root, fs = sysvol
    gpo = root / "Policies" / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    cases = [
        (gpo / "Machine" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf", InfGpoFile),
        (gpo / "Machine" / "Scripts" / "scripts.ini", IniGpoFile),
        (gpo / "User" / "Scripts" / "psscripts.ini", IniGpoFile),
        (gpo / "Machine" / "Registry.pol", PolGpoFile),
        (gpo / "Machine" / "Preferences" / "Groups" / "Groups.xml", XmlGpoFile),
    ]
    for path, expected in cases:
        assert isinstance(GpoFileFactory.get_file(str(path), fs, None), expected)


def test_factory_dispatch_is_case_insensitive_and_handles_unc_paths(sysvol):
    _root, fs = sysvol
    # A "\"-joined UNC path, as the SMB provider hands out, must dispatch the same
    # way a "/"-joined local path does.
    unc = "\\\\dc1\\sysvol\\example.com\\Policies\\{GUID}\\MACHINE\\REGISTRY.POL"
    assert isinstance(GpoFileFactory.get_file(unc, fs, None), PolGpoFile)
    unc_xml = "\\\\dc1\\sysvol\\example.com\\Policies\\{GUID}\\Machine\\Groups.XML"
    assert isinstance(GpoFileFactory.get_file(unc_xml, fs, None), XmlGpoFile)


def test_factory_rejects_unknown_file_verbatim(tmp_path):
    target = tmp_path / "gpt.ini"
    target.write_text("[General]\r\nVersion=65539\r\n")
    fs = LocalFsProvider()
    with pytest.raises(NotImplementedError) as excinfo:
        GpoFileFactory.get_file(str(target), fs, None)
    assert str(excinfo.value) == "No parser for " + str(target)


def test_factory_logs_empty_file(tmp_path):
    target = tmp_path / "Groups.xml"
    target.write_bytes(b"")
    logger = RecordingLogger()
    GpoFileFactory.get_file(str(target), LocalFsProvider(), logger)
    assert logger.degubs == ["Empty file was unparseable " + str(target)]


# --------------------------------------------------------------------------- #
# XmlGpoFile
# --------------------------------------------------------------------------- #


def test_groups_xml(sysvol):
    root, fs = sysvol
    path = (
        root
        / "Policies"
        / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        / "Machine"
        / "Preferences"
        / "Groups"
        / "Groups.xml"
    )
    settings = parse(path, fs).settings

    group = only(settings, GroupSetting)[0]
    assert group.name == "Administrators (built-in)"
    assert group.action == SettingAction.Update
    assert group.description == "local admins"
    assert group.group_sid == "S-1-5-32-544"
    # "0" is not a Boolean.TryParse-able value, so these stay false.
    assert (group.delete_all_users, group.delete_all_groups, group.remove_accounts) == (
        False,
        False,
        False,
    )
    assert [(m.name, m.sid, m.action) for m in group.members] == [
        (
            "EXAMPLE\\Domain Users",
            "S-1-5-21-1111111111-2222222222-3333333333-513",
            SettingAction.Add,
        ),
        # "REMOVE" is not in the C# lookup table, so it lands on Unknown.
        ("EXAMPLE\\itguy", "", SettingAction.Unknown),
    ]
    assert group.source == str(path)

    user = only(settings, UserSetting)[0]
    assert user.name == "EXAMPLE\\localadmin"
    assert user.full_name == "Local Admin"
    assert user.user_name == "EXAMPLE\\localadmin"
    assert user.cpassword == CPASSWORD
    assert user.password == CPASSWORD_PLAINTEXT
    assert user.pw_never_expires is True
    assert user.account_disabled is False


def test_registry_xml(sysvol):
    root, fs = sysvol
    path = (
        root
        / "Policies"
        / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        / "Machine"
        / "Preferences"
        / "Registry"
        / "Registry.xml"
    )
    settings = only(parse(path, fs).settings, RegistrySetting)
    # "//Registry" is an absolute XPath, so the one nested in a Collection counts.
    assert len(settings) == 2

    password = settings[0]
    assert password.name == "DefaultPassword"
    assert password.status == "DefaultPassword"
    assert password.action == SettingAction.Update
    assert password.hive == RegHive.HKEY_LOCAL_MACHINE
    assert password.key == "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    assert password.display_decimal == "0"
    assert password.changed is not None and password.changed.year == 2015
    value = password.values[0]
    assert value.value_name == "DefaultPassword"
    assert value.reg_key_val_type == RegKeyValType.REG_SZ
    assert value.value_string == "Summer2015!"
    assert value.value_bytes == "Summer2015!".encode("utf-16-le")

    # An unparseable hive name leaves default(RegHive), not HKEY_LOCAL_MACHINE.
    autologon = settings[1]
    assert autologon.hive == RegHive.HKEY_CLASSES_ROOT
    assert autologon.action == SettingAction.Create
    assert autologon.values[0].reg_key_val_type == RegKeyValType.REG_DWORD


def test_scheduled_tasks_xml(sysvol):
    root, fs = sysvol
    path = (
        root
        / "Policies"
        / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        / "Machine"
        / "Preferences"
        / "ScheduledTasks"
        / "ScheduledTasks.xml"
    )
    tasks = only(parse(path, fs).settings, SchedTaskSetting)
    assert [t.task_type for t in tasks] == [SchedTaskType.Task, SchedTaskType.TaskV2]

    v1 = tasks[0]
    assert v1.name == "Legacy Task"
    assert v1.setting_action == SettingAction.Create
    assert v1.comment == "does a thing"
    action = v1.actions[0]
    assert isinstance(action, SchedTaskExecAction)
    assert (action.command, action.args, action.working_dir) == (
        "C:\\scripts\\legacy.exe",
        "-quiet",
        "C:\\scripts",
    )
    assert v1.enabled is True
    assert v1.stop_on_idle_end is True
    assert v1.start_only_if_idle is False
    # noStartIfOnBatteries="1" does not parse as a bool, so it stays false.
    assert v1.disallow_start_if_on_batteries is False
    assert v1.stop_if_going_on_batteries is True
    principal = v1.principals[0]
    assert principal.user_id == "EXAMPLE\\svc_legacy"
    assert principal.logon_type == "Password"
    assert principal.cpassword == CPASSWORD
    assert len(v1.triggers) == 1

    v2 = tasks[1]
    assert v2.name == "Modern Task"
    assert v2.setting_action == SettingAction.Remove
    assert v2.author == "EXAMPLE\\admin"
    assert v2.description1 == "runs the thing"
    assert v2.comment == "v2 comment"
    assert v2.system_required is True
    assert v2.duration == "PT10M"
    assert v2.wait_timeout == "PT1H"
    assert v2.multiple_instances_policy == "IgnoreNew"
    assert v2.execution_time_limit == "PT0S"
    assert v2.priority == 7
    assert (v2.enabled, v2.hidden, v2.allow_hard_terminate) == (True, True, True)
    v2_principal = v2.principals[0]
    assert v2_principal.id == "Author"
    assert v2_principal.user_id == "EXAMPLE\\svc_modern"
    assert v2_principal.run_level == "HighestAvailable"
    assert v2_principal.cpassword == CPASSWORD
    # ShowMessage actions are collected before Exec, then SendEmail, per the C#.
    kinds = [type(a).__name__ for a in v2.actions]
    assert kinds == [
        "SchedTaskShowMessageAction",
        "SchedTaskExecAction",
        "SchedTaskEmailAction",
    ]
    message, exec_action, email = v2.actions
    assert (message.title, message.body) == ("hello", "world")
    assert exec_action.command == "\\\\dc1\\netlogon\\payload.exe"
    assert exec_action.args == "-force"
    assert exec_action.working_dir == "C:\\Windows\\Temp"
    assert email.from_ == "gpo@example.com"
    assert email.to == "admin@example.com"
    assert email.subject == "done"
    assert email.header_fields == "X-Thing: yes"
    assert email.attachments == ["C:\\logs\\one.log", "C:\\logs\\two.log"]
    assert email.server == "smtp.example.com"
    assert len(v2.triggers) == 2


def test_services_xml(sysvol):
    root, fs = sysvol
    path = (
        root
        / "Policies"
        / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        / "Machine"
        / "Preferences"
        / "Services"
        / "Services.xml"
    )
    service = only(parse(path, fs).settings, NtServiceSetting)[0]
    assert service.name == "AppSvc"
    assert service.service_name == "AppSvc"
    assert service.service_action == "START"
    assert service.startup_type == "AUTOMATIC"
    assert service.program == "C:\\app\\app.exe"
    assert service.args == "-run"
    assert service.account_name == "EXAMPLE\\svc_app"
    assert service.user_name == "EXAMPLE\\svc_app"
    assert service.cpassword == CPASSWORD
    assert service.password == CPASSWORD_PLAINTEXT
    assert service.action_on_first_failure == "RESTART"
    assert service.reset_fail_count_delay == "1"
    assert service.timeout == "30"
    assert service.interact == "1"


def test_drives_xml_decrypts_cpassword(sysvol):
    root, fs = sysvol
    path = (
        root
        / "Policies"
        / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        / "User"
        / "Preferences"
        / "Drives"
        / "Drives.xml"
    )
    drive = only(parse(path, fs).settings, DriveSetting)[0]
    assert drive.name == "P:"
    assert drive.action == SettingAction.Update
    assert drive.path == "\\\\fileserver\\profiles"
    assert drive.label == "Profiles"
    assert drive.letter == "P"
    assert drive.drive_letter == "1"  # useLetter, per the C# mapping
    assert drive.this_drive == "SHOW"
    assert drive.all_drives == "NOCHANGE"
    assert drive.user_name == "EXAMPLE\\svc_maps"
    assert drive.cpassword == CPASSWORD
    assert drive.password == CPASSWORD_PLAINTEXT


def test_datasources_and_inifiles_xml(sysvol):
    root, fs = sysvol
    base = (
        root / "Policies" / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    )
    ds = only(
        parse(base / "User" / "Preferences" / "DataSources" / "DataSources.xml", fs).settings,
        DataSourceSetting,
    )[0]
    assert ds.name == "AppDSN"
    assert ds.dsn == "AppDSN"
    assert ds.driver == "SQL Server"
    assert ds.user_name == "sa"
    assert ds.password == CPASSWORD_PLAINTEXT
    assert ds.action == SettingAction.Create

    ini = only(
        parse(base / "Machine" / "Preferences" / "IniFiles" / "IniFiles.xml", fs).settings,
        IniFileSetting,
    )[0]
    assert ini.path == "C:\\app\\app.ini"
    assert ini.section == "creds"
    assert ini.property == "password"
    assert ini.value == "Sup3rSecret"
    # The C# discards the parsed action, so it keeps the field default.
    assert ini.action == SettingAction.Update


def test_unhandled_xml_root_is_logged(tmp_path):
    target = tmp_path / "Whatever.xml"
    target.write_bytes(b'<?xml version="1.0"?><Bananas><Banana/></Bananas>')
    logger = RecordingLogger()
    gpo_file = parse(target, LocalFsProvider(), logger)
    assert gpo_file.settings == []
    assert logger.degubs == [
        "Bananas didn't seem to have a handler in the XmlParser switch case thing."
    ]


def test_malformed_xml_is_logged_not_raised(tmp_path):
    target = tmp_path / "Groups.xml"
    target.write_bytes(b"<Groups><Group></Groups>")
    logger = RecordingLogger()
    gpo_file = parse(target, LocalFsProvider(), logger)
    assert gpo_file.settings == []
    assert len(logger.errors) == 1


# --------------------------------------------------------------------------- #
# IniGpoFile
# --------------------------------------------------------------------------- #


def test_scripts_ini(sysvol):
    root, fs = sysvol
    path = (
        root
        / "Policies"
        / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        / "Machine"
        / "Scripts"
        / "scripts.ini"
    )
    scripts = only(parse(path, fs).settings, ScriptSetting)
    assert [(s.script_type, s.cmd_line, s.parameters) for s in scripts] == [
        (ScriptType.Startup, "startup.bat", ""),
        (ScriptType.Startup, "\\\\dc1\\netlogon\\map.vbs", "-quiet"),
        (ScriptType.Shutdown, "bye.bat", "now"),
    ]
    assert all(s.source == str(path) for s in scripts)


def test_psscripts_ini_ignores_execute_ps_first(sysvol):
    root, fs = sysvol
    path = (
        root
        / "Policies"
        / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        / "User"
        / "Scripts"
        / "psscripts.ini"
    )
    logger = RecordingLogger()
    scripts = only(parse(path, fs, logger).settings, ScriptSetting)
    assert [(s.script_type, s.cmd_line, s.parameters) for s in scripts] == [
        (ScriptType.Logon, "logon.ps1", "-NoProfile")
    ]
    assert logger.traces.count(
        "Ignore StartExecutePSFirst or EndExecutePSFirst configuration"
    ) == 2
    # Every [ScriptsConfig] line starts with S or E, so that section produces no
    # subsections at all and the "type of Scripts.Ini entry" complaint -- which
    # only fires per subsection -- never happens.
    assert logger.errors == []


def test_scripts_ini_unknown_section_is_logged(tmp_path):
    target = tmp_path / "scripts.ini"
    target.write_bytes(
        b"\xff\xfe" + "[Bananas]\r\n0CmdLine=peel.bat\r\n".encode("utf-16-le")
    )
    logger = RecordingLogger()
    settings = parse(target, LocalFsProvider(), logger).settings
    assert [(s.script_type, s.cmd_line) for s in settings] == [
        # No case matched, so ScriptType keeps its zero value.
        (ScriptType.Logon, "peel.bat")
    ]
    assert logger.errors == [
        "There is a type of Scripts.Ini entry that I'm not handling properly. Fuck. Bananas"
    ]


# --------------------------------------------------------------------------- #
# InfGpoFile
# --------------------------------------------------------------------------- #


def test_gpttmpl_inf(sysvol):
    root, fs = sysvol
    path = (
        root
        / "Policies"
        / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        / "Machine"
        / "Microsoft"
        / "Windows NT"
        / "SecEdit"
        / "GptTmpl.inf"
    )
    logger = RecordingLogger()
    settings = parse(path, fs, logger).settings

    priv = only(settings, PrivRightSetting)
    # The empty SeDenyBatchLogonRight has no trustees, so it is not added.
    assert len(priv) == 1
    assert priv[0].privilege == "SeNetworkLogonRight"
    assert [t.sid for t in priv[0].trustees] == ["S-1-1-0", "S-1-5-32-544", None]
    assert [t.display_name for t in priv[0].trustees] == [
        "Everyone",
        "Administrators",
        "EXAMPLE\\itguy",
    ]
    assert priv[0].source == str(path)

    reg = only(settings, RegistrySetting)
    assert len(reg) == 2
    lm = reg[0]
    assert lm.hive == RegHive.HKEY_LOCAL_MACHINE
    # First element is the hive and the last is the value name, so both go.
    assert lm.key == "System\\CurrentControlSet\\Control\\Lsa"
    assert lm.values[0].value_name == "LmCompatibilityLevel"
    assert lm.values[0].reg_key_val_type == RegKeyValType.REG_DWORD
    assert lm.values[0].value_string == "1"
    banner = reg[1]
    assert banner.key == "Software\\Policies\\Thing"
    assert banner.values[0].value_name == "Banner"
    assert banner.values[0].reg_key_val_type == RegKeyValType.REG_SZ
    assert banner.values[0].value_string == "hello there"
    assert banner.values[0].value_bytes == "hello there".encode("utf-16-le")

    sys_access = {s.setting_name: s.value_string for s in only(settings, SystemAccessSetting)}
    assert sys_access == {
        "MinimumPasswordAge": "1",
        "MaximumPasswordAge": "42",
        "ClearTextPassword": "1",
    }

    kerb = only(settings, KerbPolicySetting)
    assert [(k.key, k.value) for k in kerb] == [("MaxTicketAge", "10")]

    # [Event Audit] parses but is never added to Settings upstream.
    assert [type(s).__name__ for s in settings].count("EventAuditSetting") == 0
    # [Unicode] and [Version] are expected, so nothing is logged about them.
    assert logger.degubs == []
    assert logger.errors == []


def test_inf_unknown_section_is_logged(tmp_path):
    target = tmp_path / "GptTmpl.inf"
    target.write_bytes(
        b"\xff\xfe" + "[Bananas]\r\nBanana = 1\r\n".encode("utf-16-le")
    )
    logger = RecordingLogger()
    gpo_file = parse(target, LocalFsProvider(), logger)
    assert gpo_file.settings == []
    assert logger.degubs == ["Something unexpected or unhandled in an Inf file: Bananas"]


def test_inf_skips_comment_lines(tmp_path):
    """GetContentLines drops lines starting with ';'."""
    target = tmp_path / "GptTmpl.inf"
    target.write_bytes(
        b"\xff\xfe"
        + "[System Access]\r\n;this is a comment\r\nMinimumPasswordAge = 5\r\n".encode(
            "utf-16-le"
        )
    )
    settings = parse(target, LocalFsProvider()).settings
    assert [(s.setting_name, s.value_string) for s in settings] == [
        ("MinimumPasswordAge", "5")
    ]


# --------------------------------------------------------------------------- #
# PolGpoFile
# --------------------------------------------------------------------------- #


def test_machine_registry_pol(sysvol):
    root, fs = sysvol
    path = (
        root
        / "Policies"
        / "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        / "Machine"
        / "Registry.pol"
    )
    gpo_file = parse(path, fs)
    assert gpo_file.signature == 0x67655250
    assert gpo_file.version == 1
    settings = only(gpo_file.settings, RegistrySetting)
    assert len(settings) == 2

    installer = settings[0]
    assert installer.hive == RegHive.HKEY_LOCAL_MACHINE
    # The leading "Software" component is dropped by String.Join(Skip(1)).
    assert installer.key == "Policies\\Microsoft\\Windows\\Installer"
    assert installer.values[0].value_name == "AlwaysInstallElevated"
    assert installer.values[0].reg_key_val_type == RegKeyValType.REG_DWORD
    assert installer.values[0].value_string == "1"
    assert installer.values[0].value_bytes == struct.pack("<i", 1)

    rds = settings[1]
    assert rds.key == "Policies\\Microsoft\\Windows NT\\Terminal Services"
    assert rds.values[0].reg_key_val_type == RegKeyValType.REG_SZ
    # NULs in REG_SZ/REG_MULTI_SZ values are scrubbed to spaces.
    assert rds.values[0].value_string == "yes "


def test_user_registry_pol_gets_hkcu(sysvol):
    root, fs = sysvol
    path = (
        root / "Policies" / "{31B2F340-016D-11D2-945F-00C04FB984F9}" / "User" / "Registry.pol"
    )
    settings = only(parse(path, fs).settings, RegistrySetting)
    assert [s.hive for s in settings] == [RegHive.HKEY_CURRENT_USER]
    assert settings[0].key == "Policies\\Example"
    assert settings[0].values[0].value_string == "7"


def test_registry_pol_hive_detection_accepts_both_separators(tmp_path):
    """Regression: "/Machine/Registry.pol" used to hit the NotImplementedError."""
    fs = LocalFsProvider()
    for parent, expected in (("Machine", RegHive.HKEY_LOCAL_MACHINE), ("User", RegHive.HKEY_CURRENT_USER)):
        directory = tmp_path / parent
        directory.mkdir()
        target = directory / "Registry.pol"
        target.write_bytes(USER_POL)
        assert only(parse(target, fs).settings, RegistrySetting)[0].hive == expected


def test_registry_pol_with_no_hive_in_path_raises(tmp_path):
    target = tmp_path / "Registry.pol"
    target.write_bytes(USER_POL)
    with pytest.raises(NotImplementedError) as excinfo:
        parse(target, LocalFsProvider())
    assert str(excinfo.value) == (
        "Something went wrong trying to figure out the hive associated with this registry.pol file:"
        + str(target)
    )


def test_registry_pol_bad_signature(tmp_path):
    directory = tmp_path / "Machine"
    directory.mkdir()
    target = directory / "Registry.pol"
    target.write_bytes(b"NOPE" + struct.pack("<I", 1))
    with pytest.raises(ValueError) as excinfo:
        parse(target, LocalFsProvider())
    assert str(excinfo.value) == "File format is not supported"


# --------------------------------------------------------------------------- #
# whole-SYSVOL runs
# --------------------------------------------------------------------------- #


def test_sysvol_sorts_settings_into_policy_types(sysvol):
    root, fs = sysvol
    logger = RecordingLogger()
    parsed = Sysvol(str(root), fs, logger)
    assert len(parsed.gpos) == 1
    settings = parsed.gpos[0].settings
    computer = [s for s in settings if s.policy_type == PolicyType.Computer]
    user = [s for s in settings if s.policy_type == PolicyType.User]
    assert computer and user
    assert all(s.policy_type is not None for s in settings)
    # Both Registry.pol files contributed.
    hives = {
        s.hive
        for s in settings
        if isinstance(s, RegistrySetting) and str(s.source).endswith("Registry.pol")
    }
    assert hives == {RegHive.HKEY_LOCAL_MACHINE, RegHive.HKEY_CURRENT_USER}


@pytest.mark.skipif(
    not os.path.isdir(TEST_SYSVOL), reason="upstream TestSysvol fixture not present"
)
def test_upstream_testsysvol_offline():
    """Pins the real upstream fixture, including the registry.pol regression."""
    logger = RecordingLogger()
    parsed = Sysvol(TEST_SYSVOL, LocalFsProvider(), logger)
    settings = [s for gpo in parsed.gpos for s in gpo.settings]
    counts = {}
    for setting in settings:
        counts[type(setting).__name__] = counts.get(type(setting).__name__, 0) + 1

    assert counts["RegistrySetting"] == 263
    assert counts["PrivRightSetting"] == 104
    assert counts["SystemAccessSetting"] == 40
    assert counts["SchedTaskSetting"] == 17
    assert counts["KerbPolicySetting"] == 15
    assert counts["ScriptSetting"] == 14
    assert counts["GroupSetting"] == 11
    assert counts["NtServiceSetting"] == 6
    assert len(settings) == 499

    # No file should have failed to work out its hive.
    assert not [m for m in logger.degubs if m.startswith("Something went wrong trying")]
    assert logger.errors == []

    pol_settings = [
        s
        for s in settings
        if isinstance(s, RegistrySetting) and str(s.source).lower().endswith("registry.pol")
    ]
    assert len(pol_settings) == 93
    # Every registry.pol in the fixture lives under a Machine directory.
    assert {s.hive for s in pol_settings} == {RegHive.HKEY_LOCAL_MACHINE}
    assert all(s.policy_type == PolicyType.Computer for s in pol_settings)
    # Spot-check one real value that only exists because registry.pol parses.
    firewall = [
        s
        for s in pol_settings
        if s.key == "Policies\\Microsoft\\WindowsFirewall"
        and s.values[0].value_name == "PolicyVersion"
    ]
    assert firewall and firewall[0].values[0].value_string == "538"
    assert firewall[0].values[0].reg_key_val_type == RegKeyValType.REG_DWORD


@pytest.mark.skipif(
    not os.path.isdir(TEST_SYSVOL), reason="upstream TestSysvol fixture not present"
)
def test_upstream_testsysvol_inf_sddl():
    """The .inf SDDL sections feed the Sddl parser, not just raw strings."""
    parsed = Sysvol(TEST_SYSVOL, LocalFsProvider(), None)
    settings = [s for gpo in parsed.gpos for s in gpo.settings]
    keyed = [
        s for s in settings if isinstance(s, RegistrySetting) and s.key_sddl_string
    ]
    assert keyed and all(s.parsed_key_sddl is not None for s in keyed)
    services = [s for s in settings if isinstance(s, NtServiceSetting) and s.sddl]
    assert services and all(s.parsed_sddl is not None for s in services)
