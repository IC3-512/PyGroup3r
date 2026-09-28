"""Fidelity tests for the nine *active* analysers ported from
Group3r/Assessment/Analysers/ in this batch, plus a guard that the eight
analysers which are commented out of AnalyserFactory upstream stay unregistered.

Every asserted string is copied from the C# source; if a reason or triage level
drifts, these tests fail.
"""

import types

import pytest

from group3rpy.ad.trustee import Trustee
from group3rpy.assessment.analyser_factory import AnalyserFactory
from group3rpy.assessment.analysers.data_source import DataSourceAnalyser
from group3rpy.assessment.analysers.file_sec import FileSecAnalyser
from group3rpy.assessment.analysers.kerb_policy import KerbPolicyAnalyser
from group3rpy.assessment.analysers.net_option import NetOptionAnalyser
from group3rpy.assessment.analysers.network_share import NetworkShareAnalyser
from group3rpy.assessment.analysers.nt_service import NtServiceAnalyser
from group3rpy.assessment.analysers import package as package_module
from group3rpy.assessment.analysers.package import PackageAnalyser
from group3rpy.assessment.analysers.printer import PrinterAnalyser
from group3rpy.assessment.analysers.priv_right import PrivRightAnalyser
from group3rpy.assessment.finding import ACEType, DirPathResult, FilePathResult
from group3rpy.classifiers.constants import Triage
from group3rpy.options.assessment_options import AssessmentOptions, TrusteeOption
from group3rpy.settings import (
    DataSourceSetting,
    DeviceSetting,
    DriveSetting,
    EnvVarSetting,
    EventAuditSetting,
    FileSecuritySetting,
    FolderSetting,
    IniFileSetting,
    KerbPolicySetting,
    NetOptionSetting,
    NetworkShareSetting,
    NtServiceSetting,
    PackageSetting,
    PrinterSetting,
    PrivRightSetting,
    SystemAccessSetting,
    UserSetting,
)
from group3rpy.smb.provider import NullFsProvider

# A real GPP cpassword blob and the plaintext it decrypts to.
CPASSWORD = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
CLEARTEXT = "Local*P4ssword!"
GPP_REASON = "Group Policy Preferences password found:" + CLEARTEXT
GPP_DETAIL = "Refer to MS14-025 and https://adsecurity.org/?p=63"


@pytest.fixture(scope="module")
def options():
    opts = AssessmentOptions()
    opts.fs = NullFsProvider()
    return opts


def reasons(result):
    return [f.finding_reason for f in result.findings]


# --------------------------------------------------------------- PrivRight.cs


def test_priv_right_low_priv_trustee_is_black(options):
    setting = PrivRightSetting(
        source="\\\\dc\\sysvol\\d\\Policies\\{G}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf",
        privilege="SeTakeOwnershipPrivilege",
        trustees=[Trustee(sid="S-1-1-0", display_name="Everyone")],
    )
    result = PrivRightAnalyser(setting).analyse(options)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.finding_reason == (
        "Well-known low-priv user/group assigned an interesting OS privilege."
    )
    assert finding.finding_detail == (
        "SeTakeOwnershipPrivilege was assigned to Everyone - S-1-1-0"
    )
    assert finding.triage == Triage.Black


def test_priv_right_boring_privilege_gives_no_findings(options):
    # SeShutdownPrivilege is neither GrantsRemoteAccess nor LocalPrivesc.
    setting = PrivRightSetting(
        source="sysvol",
        privilege="SeShutdownPrivilege",
        trustees=[Trustee(sid="S-1-1-0", display_name="Everyone")],
    )
    result = PrivRightAnalyser(setting).analyse(options)
    assert result.findings == []


def test_priv_right_high_priv_trustee_is_boring(options):
    setting = PrivRightSetting(
        source="sysvol",
        privilege="SeTakeOwnershipPrivilege",
        trustees=[Trustee(sid="S-1-5-21-1-2-3-512", display_name="Domain Admins")],
    )
    result = PrivRightAnalyser(setting).analyse(options)
    assert result.findings == []


def test_priv_right_service_account_impersonate_is_suppressed(options):
    # NETWORK SERVICE holding SeImpersonatePrivilege is normal, so the low-priv
    # branch breaks out before adding a finding.
    setting = PrivRightSetting(
        source="sysvol",
        privilege="SeImpersonatePrivilege",
        trustees=[Trustee(sid="S-1-5-20", display_name="NT Authority\\Network Service")],
    )
    result = PrivRightAnalyser(setting).analyse(options)
    assert result.findings == []

    # ... but the same trustee with a different interesting privilege is reported.
    setting = PrivRightSetting(
        source="sysvol",
        privilege="SeTakeOwnershipPrivilege",
        trustees=[Trustee(sid="S-1-5-20", display_name="NT Authority\\Network Service")],
    )
    result = PrivRightAnalyser(setting).analyse(options)
    assert reasons(result) == [
        "Well-known low-priv user/group assigned an interesting OS privilege."
    ]


def test_priv_right_unremarkable_trustee_is_green(options):
    setting = PrivRightSetting(
        source="sysvol",
        privilege="SeTakeOwnershipPrivilege",
        trustees=[Trustee(sid="S-1-5-32-547", display_name="Power Users")],
    )
    result = PrivRightAnalyser(setting).analyse(options)

    assert len(result.findings) == 1
    finding = result.findings[0]
    # Note the trailing space in the original reason string.
    assert finding.finding_reason == "User/group assigned an interesting OS privilege. "
    assert finding.finding_detail == (
        "SeTakeOwnershipPrivilege was assigned to Power Users - S-1-5-32-547"
    )
    assert finding.triage == Triage.Green


def test_priv_right_green_finding_suppressed_at_min_triage_red(options):
    setting = PrivRightSetting(
        source="sysvol",
        privilege="SeTakeOwnershipPrivilege",
        trustees=[Trustee(sid="S-1-5-32-547", display_name="Power Users")],
    )
    analyser = PrivRightAnalyser(setting)
    analyser.min_triage = Triage.Red
    assert analyser.analyse(options).findings == []


def test_priv_right_targeted_trustee_is_red():
    opts = AssessmentOptions()
    opts.fs = NullFsProvider()
    # Insert at the front so the first-match-wins loop hits it before the
    # canonical entry for the same SID.
    opts.trustee_options.insert(
        0, TrusteeOption(sid="S-1-5-21-1-2-3-1234", display_name="pwned", target=True)
    )
    setting = PrivRightSetting(
        source="sysvol",
        privilege="SeTakeOwnershipPrivilege",
        trustees=[Trustee(sid="S-1-5-21-1-2-3-1234", display_name="pwned")],
    )
    result = PrivRightAnalyser(setting).analyse(opts)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.finding_reason == (
        "Targeted user/group assigned an interesting OS privilege."
    )
    assert finding.finding_detail == (
        "SeTakeOwnershipPrivilege was assigned to pwned - S-1-5-21-1-2-3-1234"
    )
    assert finding.triage == Triage.Red


def test_priv_right_ntfrs_source_marks_morphed(options):
    setting = PrivRightSetting(source="\\\\dc\\sysvol\\NTFRS_0123\\thing", privilege="x")
    PrivRightAnalyser(setting).analyse(options)
    assert setting.is_morphed is True


# --------------------------------------------------------------- NtService.cs


def _fake_sddl(alias, sid, rights, ace_type="OBJECT_ACCESS_ALLOWED"):
    """Minimal stand-in for a parsed Sddl, shaped as SddlAnalyser expects."""
    ace = types.SimpleNamespace(
        ace_sid=types.SimpleNamespace(alias=alias, raw=sid),
        ace_type=ace_type,
        rights=list(rights),
    )
    return types.SimpleNamespace(
        owner=None, dacl=types.SimpleNamespace(aces=[ace])
    )


def test_nt_service_writable_acl_for_low_priv_trustee_is_red(options):
    setting = NtServiceSetting(
        source="sysvol",
        service_name='"MyService\\"',
        parsed_sddl=_fake_sddl("Everyone", "S-1-1-0", ["WRITE_DAC"]),
    )
    result = NtServiceAnalyser(setting).analyse(options)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.finding_reason == (
        "A Windows service's ACL is being configured to grant abusable "
        "permissions to a target trustee."
    )
    assert finding.finding_detail == (
        "This should allow local privilege escalation on affected hosts. "
        "Service: MyService, Trustee: Everyone - S-1-1-0"
    )
    assert finding.triage == Triage.Red


def test_nt_service_read_only_acl_gives_no_finding(options):
    setting = NtServiceSetting(
        source="sysvol",
        service_name="MyService",
        parsed_sddl=_fake_sddl("Everyone", "S-1-1-0", ["SERVICE_QUERY_CONFIG"]),
    )
    assert NtServiceAnalyser(setting).analyse(options).findings == []


def test_nt_service_deny_ace_is_skipped(options):
    setting = NtServiceSetting(
        source="sysvol",
        service_name="MyService",
        parsed_sddl=_fake_sddl(
            "Everyone", "S-1-1-0", ["WRITE_DAC"], ace_type="OBJECT_ACCESS_DENIED"
        ),
    )
    assert NtServiceAnalyser(setting).analyse(options).findings == []


def test_nt_service_administrators_ace_is_skipped(options):
    setting = NtServiceSetting(
        source="sysvol",
        service_name="MyService",
        parsed_sddl=_fake_sddl("Administrators", "S-1-5-32-544", ["WRITE_OWNER"]),
    )
    assert NtServiceAnalyser(setting).analyse(options).findings == []


def test_nt_service_cpassword_is_black(options):
    setting = NtServiceSetting(source="sysvol", cpassword=CPASSWORD)
    result = NtServiceAnalyser(setting).analyse(options)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.finding_reason == GPP_REASON
    assert finding.finding_detail == GPP_DETAIL
    assert finding.triage == Triage.Black
    assert setting.password == CLEARTEXT


def test_nt_service_no_sddl_no_cpassword_is_quiet(options):
    setting = NtServiceSetting(source="sysvol")
    result = NtServiceAnalyser(setting).analyse(options)
    assert result.findings == []
    assert result.setting is setting


# -------------------------------------------------------------- KerbPolicy.cs


@pytest.mark.parametrize(
    "key,value,reason",
    [
        (
            "MaxTicketAge",
            "11",
            "Non-default maximum Kerberos ticket age configured. 11",
        ),
        (
            "MaxRenewAge",
            "14",
            "Non-default maximum Kerberos renewal period configured. 14",
        ),
        (
            "MaxServiceAge",
            "1200",
            "Non-default maximum Kerberos service ticket age configured. 1200",
        ),
        (
            "MaxClockSkew",
            "60",
            "Non-default maximum Kerberos clock skew setting. 60",
        ),
        (
            "TicketValidateClient",
            "0",
            "Kerberos 'Enforce user logon restrictions' setting is disabled.",
        ),
    ],
)
def test_kerb_policy_non_default_values(options, key, value, reason):
    setting = KerbPolicySetting(source="sysvol", key=key, value=value)
    result = KerbPolicyAnalyser(setting).analyse(options)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.finding_reason == reason
    assert finding.triage == Triage.Green
    if key == "TicketValidateClient":
        assert finding.finding_detail == (
            "Probably no significant impact, read here for more details: "
            "https://docs.microsoft.com/en-us/windows/security/threat-protection/"
            "security-policy-settings/enforce-user-logon-restrictions"
        )
    else:
        assert finding.finding_detail == "Dunno, bit interesting."


@pytest.mark.parametrize(
    "key,value",
    [
        ("MaxTicketAge", "10"),
        ("MaxRenewAge", "7"),
        ("MaxServiceAge", "600"),
        ("MaxClockSkew", "5"),
        ("TicketValidateClient", "1"),
        ("SomeUnknownKerbKey", "whatever"),
    ],
)
def test_kerb_policy_default_values_are_quiet(options, key, value):
    setting = KerbPolicySetting(source="sysvol", key=key, value=value)
    assert KerbPolicyAnalyser(setting).analyse(options).findings == []


def test_kerb_policy_has_no_min_triage_guard(options):
    """The C# original deliberately has no MinTriage guards in KerbPolicy."""
    setting = KerbPolicySetting(source="sysvol", key="MaxTicketAge", value="11")
    analyser = KerbPolicyAnalyser(setting)
    analyser.min_triage = Triage.Black
    assert len(analyser.analyse(options).findings) == 1


# ----------------------------------------------------------------- Package.cs


class _StubPathAnalyser:
    """Returns a canned PathResult so the MSI findings can be exercised without
    a live filesystem."""

    result = None

    def __init__(self, assessment_options):
        pass

    def analyse_path(self, path):
        return self.result


@pytest.fixture
def stub_path_analyser(monkeypatch):
    monkeypatch.setattr(package_module, "PathAnalyser", _StubPathAnalyser)
    return _StubPathAnalyser


def test_package_local_path_is_ignored(options):
    setting = PackageSetting(source="sysvol", msi_file_list=["C:\\temp\\thing.msi"])
    assert PackageAnalyser(setting).analyse(options).findings == []


def test_package_blank_and_missing_paths_are_ignored(options):
    setting = PackageSetting(source="sysvol", msi_file_list=["", "   ", None])
    assert PackageAnalyser(setting).analyse(options).findings == []


def test_package_unwritable_unc_path_gives_no_finding(options):
    # NullFsProvider reports nothing exists, so AnalysePath yields None.
    setting = PackageSetting(source="sysvol", msi_file_list=["\\\\srv\\share\\x.msi"])
    assert PackageAnalyser(setting).analyse(options).findings == []


def test_package_writable_file_is_red(options, stub_path_analyser):
    result = FilePathResult()
    result.file_exists = True
    result.file_writable = True
    stub_path_analyser.result = result

    setting = PackageSetting(source="sysvol", msi_file_list=["\\\\srv\\share\\x.msi"])
    findings = PackageAnalyser(setting).analyse(options).findings

    assert len(findings) == 1
    assert findings[0].finding_reason == (
        "MSI package installer setting points at a file that you can modify."
    )
    assert findings[0].finding_detail == (
        "It points to \\\\srv\\share\\x.msi so maybe see what happens if you "
        "replace that file with something fun."
    )
    assert findings[0].triage == Triage.Red


def test_package_writable_dir_missing_file_is_red(options, stub_path_analyser):
    result = DirPathResult()
    result.file_exists = False
    result.directory_exists = True
    result.directory_writable = True
    stub_path_analyser.result = result

    setting = PackageSetting(source="sysvol", msi_file_list=["\\\\srv\\share\\x.msi"])
    findings = PackageAnalyser(setting).analyse(options).findings

    assert len(findings) == 1
    assert findings[0].finding_reason == (
        "MSI package installer points to a file that doesn't exist, in a "
        "directory that you can write to."
    )
    assert findings[0].finding_detail == (
        "It points to \\\\srv\\share\\x.msi so maybe see what happens if you "
        "put something fun in there."
    )
    assert findings[0].triage == Triage.Red


def test_package_writable_parent_dir_is_red(options, stub_path_analyser):
    result = DirPathResult()
    result.file_exists = False
    result.directory_exists = False
    result.parent_directory_exists = "\\\\srv\\share"
    result.parent_directory_writable = True
    stub_path_analyser.result = result

    setting = PackageSetting(source="sysvol", msi_file_list=["\\\\srv\\share\\x.msi"])
    findings = PackageAnalyser(setting).analyse(options).findings

    assert len(findings) == 1
    assert findings[0].finding_reason == (
        "MSI package installer points to a file that doesn't exist, in a "
        "directory that ALSO doesn't exist, but there's a parent directory that "
        "DOES exist that you can write to."
    )
    assert findings[0].finding_detail == (
        "It points to \\\\srv\\share\\x.msi so maybe see what happens if you "
        "create that file."
    )
    assert findings[0].triage == Triage.Red


def test_package_existing_unwritable_file_is_quiet(options, stub_path_analyser):
    result = FilePathResult()
    result.file_exists = True
    result.file_writable = False
    stub_path_analyser.result = result

    setting = PackageSetting(source="sysvol", msi_file_list=["\\\\srv\\share\\x.msi"])
    assert PackageAnalyser(setting).analyse(options).findings == []


# -------------------------------------------------------------- DataSource.cs


def test_data_source_always_reports_connection_info(options):
    setting = DataSourceSetting(source="sysvol", dsn="thedsn")
    result = DataSourceAnalyser(setting).analyse(options)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.finding_reason == (
        "Potentially useful database connection info identified."
    )
    assert finding.finding_detail == "Could be helpful for targeting other attacks."
    assert finding.triage == Triage.Green


def test_data_source_cpassword_then_connection_info(options):
    setting = DataSourceSetting(source="sysvol", cpassword=CPASSWORD)
    result = DataSourceAnalyser(setting).analyse(options)

    assert reasons(result) == [
        GPP_REASON,
        "Potentially useful database connection info identified.",
    ]
    assert [f.triage for f in result.findings] == [Triage.Black, Triage.Green]
    assert setting.password == CLEARTEXT


def test_data_source_green_finding_suppressed_at_min_triage_red(options):
    setting = DataSourceSetting(source="sysvol", cpassword=CPASSWORD)
    analyser = DataSourceAnalyser(setting)
    analyser.min_triage = Triage.Red
    assert reasons(analyser.analyse(options)) == [GPP_REASON]


# ----------------------------------------------------------------- Printer.cs


def test_printer_cpassword_is_black(options):
    setting = PrinterSetting(source="sysvol", cpassword=CPASSWORD)
    result = PrinterAnalyser(setting).analyse(options)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.finding_reason == GPP_REASON
    assert finding.finding_detail == GPP_DETAIL
    assert finding.triage == Triage.Black
    assert setting.password == CLEARTEXT


@pytest.mark.parametrize("cpassword", [None, "", "   "])
def test_printer_without_cpassword_is_quiet(options, cpassword):
    setting = PrinterSetting(source="sysvol", cpassword=cpassword)
    result = PrinterAnalyser(setting).analyse(options)
    assert result.findings == []
    assert result.setting is setting


# --------------------------------------- NetOption.cs / NetworkShare.cs / FileSec.cs


@pytest.mark.parametrize(
    "analyser_cls,setting_cls",
    [
        (NetOptionAnalyser, NetOptionSetting),
        (NetworkShareAnalyser, NetworkShareSetting),
        (FileSecAnalyser, FileSecuritySetting),
    ],
)
def test_inert_analysers_produce_no_findings(options, analyser_cls, setting_cls):
    setting = setting_cls(source="\\\\dc\\sysvol\\d\\Policies\\{G}\\Machine\\thing")
    result = analyser_cls(setting).analyse(options)
    assert result.findings == []
    assert result.setting is setting
    assert setting.is_morphed is False


@pytest.mark.parametrize(
    "analyser_cls,setting_cls",
    [
        (NetOptionAnalyser, NetOptionSetting),
        (NetworkShareAnalyser, NetworkShareSetting),
        (FileSecAnalyser, FileSecuritySetting),
    ],
)
def test_inert_analysers_still_flag_morphed(options, analyser_cls, setting_cls):
    setting = setting_cls(source="\\\\dc\\sysvol\\NTFRS_00ff\\Machine\\thing")
    analyser_cls(setting).analyse(options)
    assert setting.is_morphed is True


# ------------------------------------------------ the eight disabled analysers


DISABLED_SETTINGS = [
    DeviceSetting,
    DriveSetting,
    EnvVarSetting,
    EventAuditSetting,
    FolderSetting,
    IniFileSetting,
    SystemAccessSetting,
    UserSetting,
]


@pytest.mark.parametrize(
    "setting_cls", DISABLED_SETTINGS, ids=[c.__name__ for c in DISABLED_SETTINGS]
)
def test_disabled_analysers_stay_unregistered(setting_cls):
    """These eight are commented out of AnalyserFactory upstream, so the factory
    must return None for them -- the ported classes exist but are unreachable."""
    assert AnalyserFactory().get_analyser(setting_cls(source="sysvol")) is None
