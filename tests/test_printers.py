"""Golden-output tests for the ported output layer.

`NiceGpoPrinter` produces Group3r's default report, so these tests pin the exact
bytes it emits (CRLF line endings, indent widths, `\\___` tail markers, table
padding and all) rather than just poking at fields. If one of these fails, the
report has drifted from the C# original.
"""

import datetime
import json

import pytest

from group3rpy.ad.gpo import GPOAttributes, GPOLink, PolicyType, ScriptType, SettingAction
from group3rpy.assessment.finding import GpoFinding, GpoResult, SettingResult
from group3rpy.classifiers.constants import Triage
from group3rpy.options.grouper_options import GrouperOptions
from group3rpy.settings.kerb_policy_setting import KerbPolicySetting
from group3rpy.settings.registry_setting import RegistrySetting, RegistryValue
from group3rpy.settings.registry_types import RegHive, RegKeyValType
from group3rpy.settings.script_setting import ScriptSetting
from group3rpy.settings.user_setting import UserSetting
from group3rpy.view.json_gpo_printer import JsonGpoPrinter
from group3rpy.view.nice_gpo_printer import NiceGpoPrinter

GPO_UID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
SYSVOL_PATH = "\\\\contoso.local\\sysvol\\contoso.local\\Policies\\" + GPO_UID


def _attributes() -> GPOAttributes:
    return GPOAttributes(
        display_name="Test Policy",
        uid=GPO_UID,
        created_date=datetime.datetime(2021, 3, 14, 16, 5, 0),
        modified_date=datetime.datetime(2022, 11, 2, 9, 30, 15),
        path_in_sysvol=SYSVOL_PATH,
        computer_policy_enabled=True,
        user_policy_enabled=False,
        gpo_links=[
            GPOLink(
                link_path="OU=Workstations,DC=contoso,DC=local",
                link_enforced="Link Enabled, Not Enforced",
            )
        ],
    )


def _script_setting() -> ScriptSetting:
    return ScriptSetting(
        policy_type=PolicyType.Computer,
        script_type=ScriptType.Startup,
        cmd_line="\\\\contoso.local\\netlogon\\setup.bat",
        parameters="-quiet",
    )


def _user_setting() -> UserSetting:
    return UserSetting(
        policy_type=PolicyType.User,
        name="Administrator (built-in)",
        action=SettingAction.Update,
        user_name="Administrator",
        cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw",
        password="Local*Password1",
        pw_never_expires=True,
    )


def _kerb_setting() -> KerbPolicySetting:
    return KerbPolicySetting(policy_type=PolicyType.Computer, key="MaxTicketAge", value="10")


@pytest.fixture
def gpo_result():
    """A GpoResult carrying three settings and findings at all four triage levels."""
    options = GrouperOptions()
    result = GpoResult(options.assessment_options, _attributes())
    result.setting_results = [
        SettingResult(
            setting=_script_setting(),
            findings=[
                GpoFinding(
                    finding_reason="Startup script in a writable path.",
                    finding_detail="Matched Path: \\\\contoso.local\\netlogon\\setup.bat",
                    triage=Triage.Black,
                ),
                GpoFinding(
                    finding_reason="Script has args.",
                    finding_detail="-quiet",
                    triage=Triage.Red,
                ),
            ],
        ),
        SettingResult(
            setting=_user_setting(),
            findings=[
                GpoFinding(
                    finding_reason=(
                        "Found a cpassword, which means we can get a plaintext password. "
                        "This is the jackpot, pretty much."
                    ),
                    finding_detail="Password: Local*Password1",
                    triage=Triage.Yellow,
                ),
            ],
        ),
        SettingResult(
            setting=_kerb_setting(),
            findings=[
                GpoFinding(
                    finding_reason="Kerberos policy setting.",
                    finding_detail="MaxTicketAge 10",
                    triage=Triage.Green,
                ),
            ],
        ),
    ]
    return options, result


# The default report, exactly. Written as LF-delimited lines and joined with CRLF
# because that is what StringBuilder.AppendLine gives the original on Windows.
EXPECTED_NICE_LINES = [
    "",
    "| GPO             | Test Policy {31B2F340-016D-11D2-945F-00C04FB984F9} Current                           |",
    "|-----------------|--------------------------------------------------------------------------------------|",
    "| Date Created    | 3/14/2021 4:05:00 PM                                                                 |",
    "| Date Modified   | 11/2/2022 9:30:15 AM                                                                 |",
    "| Path in SYSVOL  | \\\\contoso.local\\sysvol\\contoso.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9} |",
    "| Computer Policy | Enabled                                                                              |",
    "| User Policy     | Disabled                                                                             |",
    "| Link            | OU=Workstations,DC=contoso,DC=local (Link Enabled, Not Enforced)                     |",
    "\\___",
    "    | Setting - Computer Policy | Script                             |",
    "    |---------------------------|------------------------------------|",
    "    | Script Type               | Startup                            |",
    "    | CmdLine                   | \\\\contoso.local\\netlogon\\setup.bat |",
    "    | Args                      | -quiet                             |",
    "    \\___",
    "        | Finding | Black                                            |",
    "        |---------|--------------------------------------------------|",
    "        | Reason  | Startup script in a writable path.               |",
    "        | Detail  | Matched Path: \\\\contoso.local\\netlogon\\setup.bat |",
    "    \\___",
    "        | Finding | Red              |",
    "        |---------|------------------|",
    "        | Reason  | Script has args. |",
    "        | Detail  | -quiet           |",
    "",
    "\\___",
    "    | Setting - User Policy | User                                        |",
    "    |-----------------------|---------------------------------------------|",
    "    | Name                  | Administrator (built-in)                    |",
    "    | Action                | Update                                      |",
    "    | UserName              | Administrator                               |",
    "    | Cpassword             | j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw |",
    "    | Password              | Local*Password1                             |",
    "    | PwNeverExpires        | True                                        |",
    "    \\___",
    "        | Finding | Yellow                                                                      |",
    "        |---------|-----------------------------------------------------------------------------|",
    "        | Reason  | Found a cpassword, which means we can get a plaintext password. This is the |",
    "        |         | jackpot, pretty much.                                                       |",
    "        | Detail  | Password: Local*Password1                                                   |",
    "",
    "\\___",
    "    | Setting - Computer Policy | Kerberos Policy |",
    "    |---------------------------|-----------------|",
    "    | MaxTicketAge              | 10              |",
    "    \\___",
    "        | Finding | Green                    |",
    "        |---------|--------------------------|",
    "        | Reason  | Kerberos policy setting. |",
    "        | Detail  | MaxTicketAge 10          |",
    "",
    "",
]

EXPECTED_NICE = "\r\n".join(EXPECTED_NICE_LINES)


def test_nice_printer_matches_default_report(gpo_result):
    options, result = gpo_result
    assert NiceGpoPrinter(options).output_gpo_result(result) == EXPECTED_NICE


def test_nice_printer_uses_crlf_only(gpo_result):
    options, result = gpo_result
    out = NiceGpoPrinter(options).output_gpo_result(result)
    assert "\n" not in out.replace("\r\n", "")


def test_nice_printer_renders_every_triage_label(gpo_result):
    options, result = gpo_result
    out = NiceGpoPrinter(options).output_gpo_result(result)
    for triage in ("Green", "Yellow", "Red", "Black"):
        assert "| Finding | " + triage in out


def test_nice_printer_wraps_at_eighty_columns(gpo_result):
    """TableAdd word-wraps anything over 80 chars and blanks the label column."""
    options, result = gpo_result
    out = NiceGpoPrinter(options).output_gpo_result(result)
    assert "        | Reason  | Found a cpassword, which means we can get a plaintext password. This is the |\r\n" in out
    assert "        |         | jackpot, pretty much.                                                       |\r\n" in out


def test_nice_printer_current_pol_only_drops_morphed_gpo(gpo_result):
    options, result = gpo_result
    options.current_pol_only = True
    result.attributes.is_morphed_gpo = True
    assert NiceGpoPrinter(options).output_gpo_result(result) == ""


def test_nice_printer_enabled_pol_only_drops_disabled_gpo(gpo_result):
    options, result = gpo_result
    options.enabled_pol_only = True
    result.attributes.computer_policy_enabled = False
    result.attributes.user_policy_enabled = False
    assert NiceGpoPrinter(options).output_gpo_result(result) == ""


def test_nice_printer_findings_only_skips_settings_without_findings(gpo_result):
    options, result = gpo_result
    options.findings_only = True
    result.setting_results.append(SettingResult(setting=_kerb_setting(), findings=[]))
    out = NiceGpoPrinter(options).output_gpo_result(result)
    assert out.count("Kerberos Policy") == 1


def test_nice_printer_morphed_setting_is_labelled(gpo_result):
    options, result = gpo_result
    result.setting_results[0].setting.is_morphed = True
    out = NiceGpoPrinter(options).output_gpo_result(result)
    assert "| Setting - Computer Policy - Morphed | Script" in out


def test_nice_printer_registry_setting_also_goes_to_the_console(gpo_result, capsys):
    """The C# has a stray Console.WriteLine in the RegistrySetting branch; the
    table therefore shows up on the console as well as in the report."""
    options, result = gpo_result
    setting = RegistrySetting(
        policy_type=PolicyType.Computer,
        name="AlwaysInstallElevated",
        action=SettingAction.Update,
        hive=RegHive.HKEY_LOCAL_MACHINE,
        key="Software\\Policies\\Microsoft\\Windows\\Installer",
        values=[
            RegistryValue(
                value_name="AlwaysInstallElevated",
                reg_key_val_type=RegKeyValType.REG_DWORD,
                value_string="1",
            )
        ],
    )
    result.setting_results = [SettingResult(setting=setting, findings=[])]

    out = NiceGpoPrinter(options).output_gpo_result(result)
    console = capsys.readouterr().out

    expected_table = "\r\n".join(
        [
            "| Setting - Computer Policy | Registry                                                         |",
            "|---------------------------|------------------------------------------------------------------|",
            "| Name                      | AlwaysInstallElevated                                            |",
            "| Action                    | Update                                                           |",
            "| Key                       | HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer |",
            "| Value Name                | AlwaysInstallElevated                                            |",
            "| Value Type                | REG_DWORD                                                        |",
            "| Value String              | 1                                                                |",
            "",
        ]
    )
    assert expected_table in console
    assert "    | Value Type                | REG_DWORD" in out


def test_nice_printer_output_gpo_returns_empty_string(gpo_result):
    options, _ = gpo_result
    from group3rpy.ad.gpo import GPO

    assert NiceGpoPrinter(options).output_gpo(GPO()) == ""


def test_json_printer_emits_valid_json(gpo_result):
    options, result = gpo_result
    out = JsonGpoPrinter(options).output_gpo_result(result)
    parsed = json.loads(out)

    assert parsed["attributes"]["display_name"] == "Test Policy"
    assert parsed["attributes"]["uid"] == GPO_UID
    assert parsed["attributes"]["path_in_sysvol"] == SYSVOL_PATH
    assert len(parsed["setting_results"]) == 3


def test_json_printer_writes_enum_names_and_drops_nulls(gpo_result):
    options, result = gpo_result
    parsed = json.loads(JsonGpoPrinter(options).output_gpo_result(result))

    first = parsed["setting_results"][0]
    assert first["setting"]["policy_type"] == "Computer"
    assert first["setting"]["script_type"] == "Startup"
    assert [f["triage"] for f in first["findings"]] == ["Black", "Red"]

    # NullValueHandling.Ignore: nothing serialises as null.
    assert ": null" not in JsonGpoPrinter(options).output_gpo_result(result)


def test_json_printer_is_indented(gpo_result):
    options, result = gpo_result
    out = JsonGpoPrinter(options).output_gpo_result(result)
    assert out.startswith("{\n  ")
