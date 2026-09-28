"""Tests for group3rpy.sddl -- the port of LibSnaffle/Sddl.Parser.

Every expected value in this file was produced by compiling the upstream C#
parser (upstream/LibSnaffle/Sddl.Parser/*.cs) and running the same SDDL strings
through it, so the assertions below are the C# tool's actual output rather than
a reading of the tables.
"""

import pytest

from group3rpy.sddl.sddl import Sddl, SecurableObjectType
from group3rpy.sddl.binary import sddl_from_binary, sddl_string_from_binary


# --------------------------------------------------------------------------
# a real GPO nTSecurityDescriptor
# --------------------------------------------------------------------------

GPO_SDDL = (
    "O:DAG:DAD:PAI"
    "(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)"
    "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
    "(A;;RPLCLORC;;;AU)"
    "(A;CIIO;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
    "S:AI(OU;CIIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;"
    "bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
)

DS_FULL_CONTROL_RIGHTS = [
    "READ_PROPERTY",
    "WRITE_PROPERTY",
    "CONTROL_ACCESS",
    "CREATE_CHILD",
    "DELETE_CHILD",
    "LIST_CHILDREN",
    "LIST_OBJECT",
    "READ_CONTROL",
    "WRITE_OWNER",
    "WRITE_DAC",
    "STANDARD_DELETE",
    "DELETE_TREE",
    "SELF_WRITE",
]


def test_gpo_ntsecuritydescriptor_sddl():
    sddl = Sddl(GPO_SDDL, SecurableObjectType.DirectoryServiceObject)

    assert sddl.is_valid
    assert sddl.owner is not None
    assert sddl.owner.alias == "Domain Admins"
    assert sddl.owner.raw == "DA"
    assert sddl.group.alias == "Domain Admins"

    assert sddl.dacl is not None
    assert sddl.dacl.flags == ["PROTECTED", "AUTO_INHERITED"]
    assert len(sddl.dacl.aces) == 4

    ace0 = sddl.dacl.aces[0]
    assert ace0.ace_type == "OBJECT_ACCESS_ALLOWED"
    assert ace0.ace_flags == ["CONTAINER_INHERIT"]
    assert ace0.rights == ["CONTROL_ACCESS"]
    assert ace0.object_guid == "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
    assert ace0.inherit_object_guid is None
    assert ace0.ace_sid.alias == "Authenticated Users"
    assert ace0.ace_sid.raw == "AU"

    ace1 = sddl.dacl.aces[1]
    assert ace1.ace_type == "ACCESS_ALLOWED"
    assert ace1.ace_flags is None
    assert ace1.rights == DS_FULL_CONTROL_RIGHTS
    assert ace1.ace_sid.alias == "Domain Admins"

    ace2 = sddl.dacl.aces[2]
    assert ace2.rights == [
        "READ_PROPERTY", "LIST_CHILDREN", "LIST_OBJECT", "READ_CONTROL"]
    assert ace2.ace_sid.alias == "Authenticated Users"

    ace3 = sddl.dacl.aces[3]
    assert ace3.ace_flags == ["CONTAINER_INHERIT", "INHERIT_ONLY"]
    assert ace3.rights == DS_FULL_CONTROL_RIGHTS
    assert ace3.ace_sid.alias == "Creator Owner"

    # SACL
    assert sddl.sacl is not None
    assert sddl.sacl.flags == ["AUTO_INHERITED"]
    assert len(sddl.sacl.aces) == 1
    sace = sddl.sacl.aces[0]
    assert sace.ace_type == "OBJECT_AUDIT"
    assert sace.ace_flags == ["CONTAINER_INHERIT", "INHERITED", "AUDIT_SUCCESS"]
    assert sace.rights == ["WRITE_PROPERTY"]
    assert sace.object_guid == "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
    assert sace.inherit_object_guid == "bf967aa5-0de6-11d0-a285-00aa003049e2"
    assert sace.ace_sid.alias == "Everyone"


def test_object_ace_type_literals_used_by_the_analysers():
    """SddlAnalyser.SimplifyAC switches on these two literals."""
    from group3rpy.sddl.ace import AceTypesDict

    assert AceTypesDict["OA"] == "OBJECT_ACCESS_ALLOWED"
    assert AceTypesDict["OD"] == "OBJECT_ACCESS_DENIED"
    assert AceTypesDict["A"] == "ACCESS_ALLOWED"
    assert AceTypesDict["D"] == "ACCESS_DENIED"

    sddl = Sddl("D:(OA;;CR;;;WD)(OD;;GA;;;AN)",
                SecurableObjectType.DirectoryServiceObject)
    assert [a.ace_type for a in sddl.dacl.aces] == [
        "OBJECT_ACCESS_ALLOWED", "OBJECT_ACCESS_DENIED"]


# --------------------------------------------------------------------------
# file / directory
# --------------------------------------------------------------------------

def test_file_sddl():
    sddl = Sddl(
        "O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
        "(A;OICIIO;GA;;;CO)(D;;FW;;;WD)",
        SecurableObjectType.File)

    assert sddl.owner.alias == "Administrators"
    assert sddl.group.alias == "Local System"
    assert sddl.dacl.flags == ["PROTECTED", "AUTO_INHERITED"]

    aces = sddl.dacl.aces
    assert len(aces) == 5

    assert aces[0].rights == ["FILE_ALL"]
    assert aces[0].ace_sid.alias == "Local System"

    assert aces[1].rights == ["FILE_ALL"]
    assert aces[1].ace_sid.alias == "Administrators"

    # numeric mask, resolved through the File-specific table then the generic one
    assert aces[2].rights == ["GENERIC_EXECUTE", "READ_PROPERTIES", "READ_DATA"]
    assert aces[2].ace_sid.alias == "Users"

    assert aces[3].ace_flags == ["OBJECT_INHERIT", "CONTAINER_INHERIT", "INHERIT_ONLY"]
    assert aces[3].rights == ["GENERIC_ALL"]
    assert aces[3].ace_sid.alias == "Creator Owner"

    # the deny ACE
    assert aces[4].ace_type == "ACCESS_DENIED"
    assert aces[4].rights == ["FILE_WRITE"]
    assert aces[4].ace_sid.alias == "Everyone"


def test_directory_sddl_has_directory_specific_right_names():
    sddl = Sddl(
        "D:PAI(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICIID;FA;;;SY)"
        "(D;OICI;FW;;;AN)",
        SecurableObjectType.Directory)

    assert sddl.owner is None
    assert sddl.group is None
    aces = sddl.dacl.aces

    assert aces[0].rights == ["FILE_ALL"]
    # LIST_DIRECTORY, not READ_DATA -- this is the Directory table
    assert aces[1].rights == ["GENERIC_EXECUTE", "READ_PROPERTIES", "LIST_DIRECTORY"]
    assert aces[2].ace_flags == ["OBJECT_INHERIT", "CONTAINER_INHERIT", "INHERITED"]
    assert aces[3].ace_type == "ACCESS_DENIED"
    assert aces[3].rights == ["FILE_WRITE"]
    assert aces[3].ace_sid.alias == "Anonymous"


def test_file_and_directory_tables_differ_on_the_low_bits():
    f = Sddl("D:(A;;0x7;;;WD)", SecurableObjectType.File)
    d = Sddl("D:(A;;0x7;;;WD)", SecurableObjectType.Directory)
    assert f.dacl.aces[0].rights == ["APPEND_DATA", "WRITE_DATA", "READ_DATA"]
    assert d.dacl.aces[0].rights == ["ADD_SUBDIRECTORY", "ADD_FILE", "LIST_DIRECTORY"]


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------

def test_registry_sddl():
    sddl = Sddl(
        "O:BAG:BAD:P(A;CI;KA;;;BA)(A;CI;KR;;;BU)(A;CI;0x2001f;;;AU)"
        "(D;CI;KW;;;WD)",
        SecurableObjectType.RegistryKey)

    assert sddl.owner.alias == "Administrators"
    assert sddl.dacl.flags == ["PROTECTED"]

    aces = sddl.dacl.aces
    assert aces[0].rights == ["KEY_ALL"]
    assert aces[1].rights == ["KEY_READ"]
    # numeric mask, resolved through the RegistryKey-specific table
    assert aces[2].rights == ["READ", "NOTIFY", "CREATE_SUB_KEY", "SET_VALUE",
                              "QUERY_VALUE"]
    assert aces[3].ace_type == "ACCESS_DENIED"
    assert aces[3].rights == ["KEY_WRITE"]
    assert aces[3].ace_sid.alias == "Everyone"


def test_registry_wow64_combined_bit():
    sddl = Sddl("D:(A;;0x300;;;WD)", SecurableObjectType.RegistryKey)
    assert sddl.dacl.aces[0].rights == ["WOW64_RES"]


# --------------------------------------------------------------------------
# service
# --------------------------------------------------------------------------

def test_windows_service_sddl_uses_the_service_alias_table():
    sddl = Sddl(
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)"
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
        "(A;;RPWPDTLO;;;BU)",
        SecurableObjectType.WindowsService)

    aces = sddl.dacl.aces
    assert aces[0].rights == [
        "SERVICE_QUERY_CONFIG",
        "SERVICE_QUERY_STATUS",
        "SERVICE_ENUMERATE_DEPENDENTS",
        "SERVICE_START",
        "SERVICE_STOP",
        "SERVICE_PAUSE_CONTINUE",
        "SERVICE_INTERROGATE",
        "SERVICE_USER_DEFINED_CONTROL",
        "READ_CONTROL",
    ]
    assert aces[1].rights == [
        "SERVICE_QUERY_CONFIG",
        "SERVICE_CHANGE_CONFIG",
        "SERVICE_QUERY_STATUS",
        "SERVICE_ENUMERATE_DEPENDENTS",
        "SERVICE_START",
        "SERVICE_STOP",
        "SERVICE_PAUSE_CONTINUE",
        "SERVICE_INTERROGATE",
        "SERVICE_USER_DEFINED_CONTROL",
        "DELETE",
        "READ_CONTROL",
        "WRITE_DAC",
        "WRITE_OWNER",
    ]
    assert aces[2].rights == ["SERVICE_START", "SERVICE_STOP",
                              "SERVICE_PAUSE_CONTINUE", "SERVICE_INTERROGATE"]


def test_same_aliases_mean_different_things_off_the_service_table():
    """CC on a service is SERVICE_QUERY_CONFIG, everywhere else CREATE_CHILD."""
    svc = Sddl("D:(A;;CCDC;;;WD)", SecurableObjectType.WindowsService)
    other = Sddl("D:(A;;CCDC;;;WD)", SecurableObjectType.File)
    assert svc.dacl.aces[0].rights == ["SERVICE_QUERY_CONFIG", "SERVICE_CHANGE_CONFIG"]
    assert other.dacl.aces[0].rights == ["CREATE_CHILD", "DELETE_CHILD"]


# --------------------------------------------------------------------------
# owner / generic rights / unknowns
# --------------------------------------------------------------------------

def test_owner_and_generic_rights():
    sddl = Sddl("O:S-1-5-21-1-2-3-1105G:DUD:(A;;GAGRGWGX;;;WD)(D;;GA;;;AN)",
                SecurableObjectType.Unknown)

    # a plain user SID has no alias entry; the parser reports it and wraps it
    assert sddl.owner.raw == "S-1-5-21-1-2-3-1105"
    assert sddl.owner.alias == "Unknown(S-1-5-21-1-2-3-1105)"
    assert sddl.owner.is_valid is False
    assert [e.code for e in sddl.owner.errors] == ["SDP001"]

    assert sddl.group.alias == "Domain Users"
    assert sddl.group.raw == "DU"

    assert sddl.dacl.aces[0].rights == [
        "GENERIC_ALL", "GENERIC_READ", "GENERIC_WRITE", "GENERIC_EXECUTE"]
    assert sddl.dacl.aces[1].ace_type == "ACCESS_DENIED"
    assert sddl.dacl.aces[1].rights == ["GENERIC_ALL"]


def test_unknown_leftovers_are_wrapped_not_dropped():
    sddl = Sddl("D:(QQ;ZZ;FAQQ;;;XX)", SecurableObjectType.File)
    ace = sddl.dacl.aces[0]
    assert ace.ace_type == "Unknown(QQ)"
    assert ace.ace_flags == ["Unknown(ZZ)"]
    assert ace.rights == ["FILE_ALL", "Unknown(QQ)"]
    assert ace.ace_sid.alias == "Unknown(XX)"
    assert ace.ace_sid.raw == "XX"


def test_leftover_access_mask_bits_are_reported_in_uppercase_hex():
    sddl = Sddl("D:(A;;0xffffffff;;;WD)", SecurableObjectType.File)
    assert sddl.dacl.aces[0].rights == [
        "ALL_ACCESS",
        "GENERIC_READ",
        "GENERIC_WRITE",
        "GENERIC_EXECUTE",
        "GENERIC_ALL",
        "MAXIMUM_ALLOWED",
        "ACCESS_SYSTEM_SECURITY",
        "Unknown(0xCE0FE00)",
    ]


def test_sid_aliases_with_backslashes():
    sddl = Sddl("D:(A;;GA;;;RU)(A;;GA;;;RD)(A;;GA;;;S-1-5-83-0)",
                SecurableObjectType.Unknown)
    aliases = [a.ace_sid.alias for a in sddl.dacl.aces]
    assert aliases == [
        "BUILTIN\\Pre-Windows 2000 Compatible Access",
        "BUILTIN\\Remote Desktop Users",
        "NT VIRTUAL MACHINE\\Virtual Machines",
    ]


def test_domain_relative_sid_regexes():
    sddl = Sddl(
        "D:(A;;GA;;;S-1-5-21-111-222-333-512)(A;;GA;;;S-1-5-21-111-222-333-519)"
        "(A;;GA;;;S-1-5-21-111-222-333-500)(A;;GA;;;S-1-5-32-544)",
        SecurableObjectType.Unknown)
    assert [a.ace_sid.alias for a in sddl.dacl.aces] == [
        "Domain Admins", "Enterprise Admins", "Administrator", "Administrators"]


def test_empty_sddl_raises_like_the_clr():
    with pytest.raises(ValueError):
        Sddl("", SecurableObjectType.Unknown)


def test_owner_only_and_null_acl():
    assert Sddl("O:BA").owner.alias == "Administrators"
    assert Sddl("O:BA").dacl is None
    assert Sddl("D:NO_ACCESS_CONTROL").dacl.flags == ["NULL_ACL"]


# --------------------------------------------------------------------------
# binary security descriptors (Linux path)
# --------------------------------------------------------------------------

def _build_binary_sd(owner, group, aces, control=0x8004):
    from impacket.ldap import ldaptypes

    def mkace(ace_type, mask, sid, flags=0, object_guid=None):
        a = ldaptypes.ACE()
        a["AceType"] = ace_type
        a["AceFlags"] = flags
        body = ldaptypes.ACE_TYPE_MAP[ace_type]()
        body["Mask"] = ldaptypes.ACCESS_MASK()
        body["Mask"]["Mask"] = mask
        if ace_type in (5, 6):
            body["Flags"] = 0
            body["ObjectType"] = object_guid if object_guid else b""
            body["InheritedObjectType"] = b""
        body["Sid"] = ldaptypes.LDAP_SID()
        body["Sid"].fromCanonical(sid)
        a["Ace"] = body
        return a

    dacl = ldaptypes.ACL()
    dacl["AclRevision"] = 4
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = [mkace(*a) for a in aces]

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = control
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical(owner)
    sd["GroupSid"] = ldaptypes.LDAP_SID()
    sd["GroupSid"].fromCanonical(group)
    sd["Dacl"] = dacl
    sd["Sacl"] = b""
    return sd.getData()


def test_binary_descriptor_emits_the_expected_sddl_text():
    data = _build_binary_sd(
        "S-1-5-32-544",
        "S-1-5-18",
        [
            (0, 0x001F01FF, "S-1-5-18", 0x13),
            (0, 0x000F01FF, "S-1-5-32-544", 0),
            (1, 0x00120116, "S-1-1-0", 0),
            (0, 0x001200A9, "S-1-5-32-545", 0),
        ],
        control=0x8004 | 0x1000,
    )
    assert sddl_string_from_binary(data) == (
        "O:S-1-5-32-544G:S-1-5-18D:P"
        "(A;OICIID;FA;;;S-1-5-18)"
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-32-544)"
        "(D;;FW;;;S-1-1-0)"
        "(A;;0x1200a9;;;S-1-5-32-545)"
    )


def test_binary_descriptor_parses_to_the_same_right_names_as_the_string_path():
    data = _build_binary_sd(
        "S-1-5-32-544",
        "S-1-5-18",
        [
            (0, 0x001F01FF, "S-1-5-18", 0x13),
            (1, 0x00120116, "S-1-1-0", 0),
            (0, 0x001200A9, "S-1-5-32-545", 0),
        ],
        control=0x8004 | 0x1000,
    )
    from_binary = sddl_from_binary(data, SecurableObjectType.File)
    from_string = Sddl(sddl_string_from_binary(data), SecurableObjectType.File)

    assert from_binary.owner.alias == "Administrators"
    assert from_binary.group.alias == "Local System"
    assert from_binary.dacl.flags == ["PROTECTED"]

    aces = from_binary.dacl.aces
    assert aces[0].ace_type == "ACCESS_ALLOWED"
    assert aces[0].ace_flags == ["OBJECT_INHERIT", "CONTAINER_INHERIT", "INHERITED"]
    assert aces[0].rights == ["FILE_ALL"]
    assert aces[0].ace_sid.alias == "Local System"
    assert aces[0].ace_sid.raw == "S-1-5-18"

    assert aces[1].ace_type == "ACCESS_DENIED"
    assert aces[1].rights == ["FILE_WRITE"]
    assert aces[1].ace_sid.alias == "Everyone"

    assert aces[2].rights == ["GENERIC_EXECUTE", "READ_PROPERTIES", "READ_DATA"]

    # identical to what the string path yields
    assert [a.rights for a in from_binary.dacl.aces] == \
           [a.rights for a in from_string.dacl.aces]
    assert [a.ace_sid.alias for a in from_binary.dacl.aces] == \
           [a.ace_sid.alias for a in from_string.dacl.aces]


def test_binary_directory_service_object_gives_ds_right_names():
    """A GPO nTSecurityDescriptor fetched as binary over LDAP."""
    data = _build_binary_sd(
        "S-1-5-21-111-222-333-512",
        "S-1-5-21-111-222-333-512",
        [
            (0, 0x000F01FF, "S-1-5-21-111-222-333-512", 0),
            (0, 0x00020014, "S-1-5-11", 0),
            (0, 0x10000000, "S-1-5-18", 0),
            (5, 0x00000100, "S-1-5-11", 0x02,
             bytes.fromhex("8ffdacedb3ffd111b41d00a0c968f939")),
        ],
        control=0x8004 | 0x1000,
    )
    sddl = sddl_from_binary(data, SecurableObjectType.DirectoryServiceObject)

    assert sddl.owner.alias == "Domain Admins"
    aces = sddl.dacl.aces
    # .NET's GetSddlForm emits 0x000f01ff as the alias run
    # "CCDCLCSWRPWPDTLOCRSDRCWDWO", so these names come out of
    # AceAliasRightsDict in that run's order -- exactly as in the C# tool.
    assert aces[0].rights == [
        "CREATE_CHILD", "DELETE_CHILD", "LIST_CHILDREN", "SELF_WRITE",
        "READ_PROPERTY", "WRITE_PROPERTY", "DELETE_TREE", "LIST_OBJECT",
        "CONTROL_ACCESS", "STANDARD_DELETE", "READ_CONTROL", "WRITE_DAC",
        "WRITE_OWNER",
    ]
    assert aces[0].ace_sid.alias == "Domain Admins"
    assert aces[1].rights == ["LIST_CHILDREN", "READ_PROPERTY", "READ_CONTROL"]
    assert aces[1].ace_sid.alias == "Authenticated Users"
    assert aces[2].rights == ["GENERIC_ALL"]
    assert aces[3].ace_type == "OBJECT_ACCESS_ALLOWED"
    assert aces[3].rights == ["CONTROL_ACCESS"]
    assert aces[3].object_guid == "edacfd8f-ffb3-11d1-b41d-00a0c968f939"


def test_binary_registry_key_gives_registry_right_names():
    data = _build_binary_sd(
        "S-1-5-32-544",
        "S-1-5-32-544",
        [
            (0, 0x000F003F, "S-1-5-32-544", 0x02),
            (0, 0x00020019, "S-1-5-32-545", 0x02),
            (0, 0x0002001F, "S-1-5-11", 0x02),
            (1, 0x00020006, "S-1-1-0", 0x02),
        ],
        control=0x8004 | 0x1000,
    )
    sddl = sddl_from_binary(data, SecurableObjectType.RegistryKey)
    aces = sddl.dacl.aces
    assert aces[0].rights == ["KEY_ALL"]
    assert aces[1].rights == ["KEY_READ"]
    # 0x0002001f is not one of .NET's combined aliases, so it goes out as the
    # alias run "CCDCLCSWRPRC" and parses through AceAliasRightsDict. Same as C#.
    assert aces[2].rights == [
        "CREATE_CHILD", "DELETE_CHILD", "LIST_CHILDREN", "SELF_WRITE",
        "READ_PROPERTY", "READ_CONTROL",
    ]
    assert aces[3].ace_type == "ACCESS_DENIED"
    assert aces[3].rights == ["KEY_WRITE"]


# --------------------------------------------------------------------------
# table integrity -- these exact strings are what the analysers match on
# --------------------------------------------------------------------------

@pytest.mark.parametrize("token,name", [
    ("GA", "GENERIC_ALL"), ("GR", "GENERIC_READ"), ("GW", "GENERIC_WRITE"),
    ("GX", "GENERIC_EXECUTE"), ("RC", "READ_CONTROL"), ("SD", "STANDARD_DELETE"),
    ("WD", "WRITE_DAC"), ("WO", "WRITE_OWNER"), ("RP", "READ_PROPERTY"),
    ("WP", "WRITE_PROPERTY"), ("CC", "CREATE_CHILD"), ("DC", "DELETE_CHILD"),
    ("LC", "LIST_CHILDREN"), ("SW", "SELF_WRITE"), ("LO", "LIST_OBJECT"),
    ("DT", "DELETE_TREE"), ("CR", "CONTROL_ACCESS"), ("FA", "FILE_ALL"),
    ("FR", "FILE_READ"), ("FW", "FILE_WRITE"), ("FX", "FILE_EXECUTE"),
    ("KA", "KEY_ALL"), ("KR", "KEY_READ"), ("KW", "KEY_WRITE"),
    ("KX", "KEY_EXECUTE"), ("NR", "NO_READ_UP"), ("NW", "NO_WRITE_UP"),
    ("NX", "NO_EXECUTE_UP"),
])
def test_ace_alias_rights_table(token, name):
    from group3rpy.sddl.ace import AceAliasRightsDict
    assert AceAliasRightsDict[token] == name


def test_generic_uint_rights_table_order_matters():
    """STANDARD_RIGHTS_ALL is matched before its constituent bits."""
    sddl = Sddl("D:(A;;0x1f0000;;;WD)", SecurableObjectType.Unknown)
    assert sddl.dacl.aces[0].rights == ["STANDARD_RIGHTS_ALL"]
    sddl = Sddl("D:(A;;0xf0000;;;WD)", SecurableObjectType.Unknown)
    assert sddl.dacl.aces[0].rights == [
        "WRITE_OWNER", "WRITE_DAC", "READ_CONTROL", "DELETE"]


def test_ace_type_prefix_matching_prefers_the_longer_token():
    """AU must beat A; SortedDictionary<StringLengthComparer> guarantees it."""
    assert Sddl("S:(AU;;GA;;;WD)").sacl.aces[0].ace_type == "AUDIT"
    assert Sddl("D:(A;;GA;;;WD)").dacl.aces[0].ace_type == "ACCESS_ALLOWED"
    assert Sddl("D:(AL;;GA;;;WD)").dacl.aces[0].ace_type == "ALARM"
