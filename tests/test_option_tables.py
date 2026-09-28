"""Fidelity checks for the ported AssessmentOptions static data tables.

Counts come from the C# source:
    grep -c 'new PrivRightOption' PrivRights.cs   -> 42
    grep -c 'new TrusteeOption'   Trustees.cs     -> 106
    grep -c 'new RegKey'          RegKeys.cs      -> 112
"""

import pytest

from group3rpy.classifiers.constants import Triage
from group3rpy.options.assessment_options import (
    INTERESTING_RIGHTS,
    AssessmentOptions,
    InterestingIf,
    PrivRightOption,
    RegKey,
    TrusteeOption,
)
from group3rpy.options.file_extensions import (
    load_config_file_extensions,
    load_exe_and_script_extensions,
    load_office_macro_extensions,
)
from group3rpy.options.priv_rights import load_priv_rights
from group3rpy.options.reg_keys import load_reg_keys
from group3rpy.options.trustees import load_trustee_options
from group3rpy.settings.registry_types import RegHive, RegKeyValType


@pytest.fixture(scope="module")
def opts():
    return AssessmentOptions()


# --------------------------------------------------------------------------
# entry counts
# --------------------------------------------------------------------------


def test_priv_rights_count():
    assert len(load_priv_rights()) == 42


def test_trustee_options_count():
    assert len(load_trustee_options()) == 106


def test_reg_keys_count():
    assert len(load_reg_keys()) == 112


def test_file_extension_counts():
    assert len(load_exe_and_script_extensions()) == 12
    assert len(load_config_file_extensions()) == 7
    assert len(load_office_macro_extensions()) == 12


def test_interesting_rights_count_and_duplicates():
    assert len(INTERESTING_RIGHTS) == 29
    # the C# original really does list these twice
    assert INTERESTING_RIGHTS.count("CREATE_CHILD") == 2
    assert INTERESTING_RIGHTS.count("SET_VALUE") == 2
    assert INTERESTING_RIGHTS[0] == "Owner"
    assert INTERESTING_RIGHTS[-1] == "SET_VALUE"


def test_assessment_options_wires_everything_up(opts):
    assert len(opts.priv_rights) == 42
    assert len(opts.trustee_options) == 106
    assert len(opts.reg_keys) == 112
    assert len(opts.exe_and_script_extentions) == 12
    assert len(opts.config_file_extensions) == 7
    assert len(opts.office_macro_extensions) == 12
    assert opts.suck_it_and_see is False
    assert opts.target_trustees is None
    assert opts.min_triage is Triage.Green
    assert opts.fs is None


# --------------------------------------------------------------------------
# PrivRights.cs spot checks
# --------------------------------------------------------------------------


def test_priv_rights_spot_checks():
    pr = load_priv_rights()
    by_name = {p.priv_right_name: p for p in pr}

    # first entry, order matters
    assert pr[0] == PrivRightOption(
        priv_right_name="SeTakeOwnershipPrivilege",
        grants_remote_access=False,
        remote_access_desc="",
        local_privesc=True,
        local_privesc_desc="Can be used to grant yourself ownership on any file, registry key, etc.",
        ms_description="Take ownership of files or other objects",
    )
    # last entry
    assert pr[-1] == PrivRightOption(
        priv_right_name="SeManageVolumePrivilege",
        grants_remote_access=False,
        remote_access_desc="",
        local_privesc=False,
        local_privesc_desc="",
        ms_description="Perform volume maintenance tasks",
    )
    # the only entry with GrantsRemoteAccess = true and an empty desc
    assert by_name["SeSyncAgentPrivilege"].grants_remote_access is True
    assert by_name["SeSyncAgentPrivilege"].ms_description == "Synchronize directory service data"
    # non-empty RemoteAccessDesc
    assert by_name["SeRemoteInteractiveLogonRight"].remote_access_desc == (
        "It's RDP. Good old RDP."
    )
    # long MsDescription with the author's aside baked in
    assert by_name["SeMachineAccountPrivilege"].ms_description == (
        "Add workstations to domain - l0ss note: This can be leveraged as one part"
        " of that Resource Based Constrained Delegation kerberos backflip attack."
    )
    assert by_name["SeTcbPrivilege"].local_privesc_desc == "Lets you impersonate any other user."
    # RelabelPrivilege has an empty MsDescription in the original
    assert by_name["SeRelabelPrivilege"].ms_description == ""


# --------------------------------------------------------------------------
# Trustees.cs spot checks
# --------------------------------------------------------------------------


def test_trustee_options_spot_checks():
    ts = load_trustee_options()
    by_sid = {t.sid: t for t in ts}

    assert ts[0] == TrusteeOption(
        sid="S-1-0",
        display_name="Null Authority",
        description="An identifier authority.",
        domain_sid=False,
        local_sid=False,
        high_priv=False,
        low_priv=False,
    )
    # "Everyone" is the one entry with no Description assignment at all -> null
    assert ts[3] == TrusteeOption(
        sid="S-1-1-0",
        display_name="Everyone",
        description=None,
        domain_sid=False,
        local_sid=False,
        high_priv=False,
        low_priv=True,
    )
    assert by_sid["S-1-2-0"].display_name == "Local"
    assert by_sid["S-1-2-0"].local_sid is True
    assert by_sid["S-1-2-0"].low_priv is True
    # escaped backslash in the display name survives
    assert by_sid["S-1-5-32-578"].display_name == "BUILTIN\\Hyper-V Administrators"
    assert by_sid["S-1-5-32-578"].high_priv is True
    assert by_sid["S-1-5-32-578"].description == (
        "A Builtin Local group. Members of this group have complete and "
        "unrestricted access to all features of Hyper-V."
    )
    # last entry, order matters
    assert ts[-1] == TrusteeOption(
        sid="S-1-5-32-580",
        display_name="BUILTIN\\Remote Management Users",
        description=(
            "A Builtin Local group. Members of this group can access WMI resources"
            " over management protocols (such as WS-Management via the Windows"
            " Remote Management service). This applies only to WMI namespaces that"
            " grant access to the user."
        ),
        domain_sid=False,
        local_sid=True,
        high_priv=True,
        low_priv=False,
    )
    # Target is never assigned in the C# table
    assert all(t.target is False for t in ts)


# --------------------------------------------------------------------------
# RegKeys.cs spot checks
# --------------------------------------------------------------------------


def test_reg_keys_spot_checks():
    rk = load_reg_keys()

    # first entry: no RegHive/ValueType/ValueName assigned -> C# defaults
    assert rk[0] == RegKey(
        ms_desc="",
        friendly_description=(
            "Automatic Certificate Request Settings (ACRS) provides a method to"
            " automatically distribute certificates to Windows 2000, Windows XP,"
            " and Windows Server 2003 computers that are domain members. ACRS is"
            " useful for distributing Computer or IPSec certificates to all"
            " computers in a domain."
        ),
        reg_hive=RegHive.HKEY_CLASSES_ROOT,
        key="Policies\\Microsoft\\SystemCertificates\\ACRS",
        value_name=None,
        value_type=RegKeyValType.REG_NONE,
        interesting_if=InterestingIf.Present,
        triage=Triage.Green,
    )
    # the single-space MsDesc typo in entry 2 must survive
    assert rk[1].ms_desc == " "
    assert rk[1].key == "Policies\\Microsoft\\SystemCertificates\\CA\\Certificates"
    # "locataion" typo
    assert rk[4].friendly_description.startswith(
        "Registry locataion of the Bitlocker Network Unlock certificate."
    )

    by_key = {}
    for k in rk:
        by_key.setdefault((k.key, k.value_name), k)

    # REG_SZ entry with a DefaultSz
    cached = by_key[
        ("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "CachedLogonsCount")
    ]
    assert cached.reg_hive is RegHive.HKEY_LOCAL_MACHINE
    assert cached.value_type is RegKeyValType.REG_SZ
    assert cached.default_sz == "10"
    assert cached.interesting_if is InterestingIf.NotDefault
    assert cached.triage is Triage.Green
    assert cached.ms_desc == (
        "Interactive logon: Number of previous logons to cache (in case domain"
        " controller is not available)"
    )

    # AutoAdminLogon: InterestingIf.Present with no Triage assignment -> Green
    auto = by_key[("Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "AutoAdminLogon")]
    assert auto.ms_desc == "Turn on automatic logon in Windows: Automatic Admin Logon"
    assert auto.friendly_description == "Allows automatic logon for Admin users."
    assert auto.interesting_if is InterestingIf.Present
    assert auto.triage is Triage.Green

    # last entry, order matters
    assert rk[-1] == RegKey(
        ms_desc="WinSCP Stored Creds",
        friendly_description="",
        key="Software\\Martin Prikryl\\WinSCP 2\\Sessions",
        interesting_if=InterestingIf.Present,
        triage=Triage.Yellow,
    )

    # the LmCompatibilityLevel entry: only LessThanGood in the whole table
    less_than_good = [k for k in rk if k.interesting_if is InterestingIf.LessThanGood]
    assert len(less_than_good) == 1
    assert "crack.sh" in less_than_good[0].friendly_description

    # enum-usage census, straight out of the C# source
    assert sum(1 for k in rk if k.interesting_if is InterestingIf.Present) == 49
    assert sum(1 for k in rk if k.interesting_if is InterestingIf.NotDefault) == 60
    assert sum(1 for k in rk if k.interesting_if is InterestingIf.Bad) == 1
    assert sum(1 for k in rk if k.interesting_if is InterestingIf.NotGood) == 1
    assert sum(1 for k in rk if k.reg_hive is RegHive.HKEY_LOCAL_MACHINE) == 63
    assert sum(1 for k in rk if k.reg_hive is RegHive.HKEY_CURRENT_USER) == 2
    assert sum(1 for k in rk if k.value_type is RegKeyValType.REG_DWORD) == 64
    assert sum(1 for k in rk if k.value_type is RegKeyValType.REG_MULTI_SZ) == 7
    assert sum(1 for k in rk if k.value_type is RegKeyValType.REG_SZ) == 5
    assert sum(1 for k in rk if k.value_type is RegKeyValType.REG_BINARY) == 1
    assert sum(1 for k in rk if k.triage is Triage.Black) == 1
    assert sum(1 for k in rk if k.triage is Triage.Red) == 10
    assert sum(1 for k in rk if k.triage is Triage.Yellow) == 9


# --------------------------------------------------------------------------
# FileExtensions.cs spot checks
# --------------------------------------------------------------------------


def test_file_extensions_spot_checks():
    assert load_exe_and_script_extensions() == [
        "exe", "msi", "bat", "cmd", "hta", "ps1",
        "vbs", "scr", "com", "psd1", "psm1", "lnk",
    ]
    assert load_config_file_extensions() == [
        "config", "xml", "json", "ini", "rdp", "conf", "cnf",
    ]
    assert load_office_macro_extensions() == [
        "dot", "dotm", "doc", "docm", "xlt", "xls",
        "xltm", "xlsm", "pot", "potm", "ppt", "pptm",
    ]
