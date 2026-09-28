"""Binary security descriptor -> Sddl bridge.

PORT NOTE: this module has NO counterpart in LibSnaffle/Sddl.Parser. Group3r
(C#, Windows) obtains security descriptors as SDDL *strings*, either straight
out of a GPO .inf file or by handing the raw ntSecurityDescriptor bytes to
`new RawSecurityDescriptor(bytes, 0).GetSddlForm(AccessControlSections.All)`
(see LibSnaffle/ActiveDirectory/ActiveDirectory.cs around line 389 and
Group3r/Assessment/FsAclAnalyser.cs). On Linux there is no
System.Security.AccessControl, so this module reimplements exactly that one
Windows call: it parses the binary descriptor with
impacket.ldap.ldaptypes.SR_SECURITY_DESCRIPTOR, re-emits it as an SDDL string
using .NET's emission rules, and feeds the result through the ported parser.
Every right-name string therefore comes out of the same tables as the
string-parsing path.

The emission rules below were recovered empirically by round-tripping binary
descriptors through a real System.Security.AccessControl implementation
(`RawSecurityDescriptor(byte[], 0).GetSddlForm(AccessControlSections.All)`) and
diffing the output, so that the SDDL text this module produces is the same text
the C# tool would have parsed:

  * access mask: if the mask is exactly one of the combined aliases
    (FA/FR/FW/FX/KA/KR/KW/KX) that alias is emitted; otherwise the single-bit
    aliases are consumed greedily in the fixed order below and, if any bit is
    left over, the whole mask is emitted as lowercase "0x%x" instead.
  * ace flags: OI, CI, NP, IO, ID, SA, FA -- in that order.
  * acl flags: P, AR, AI -- in that order.
  * sections: O:, G:, D:, S: -- in that order, each omitted when absent.

DIFFERENCE FROM .NET, DELIBERATE: .NET shortens a handful of non
domain-relative well known SIDs to their two letter SDDL alias ("BA", "SY",
"WD", ...). This module always emits the canonical "S-1-..." form. Sid.Alias is
identical either way (every aliased SID has both a bigram and an "^S-1-...$"
regex in Sid.KNOWN_ALIASES_LIST), so no finding text changes; only Sid.Raw
differs, and there it is strictly better -- Group3r compares Ace.AceSid.Raw
against the operator supplied SID list (Group3r/Assessment/FsAclAnalyser.cs
`trusteeopt.SID == simpleAce.Trustee.Sid`), which contains real SIDs.
"""

from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string

from .securable_object_type import SecurableObjectType

# SECURITY_DESCRIPTOR_CONTROL bits (MS-DTYP 2.4.6).
SE_DACL_PRESENT = 0x0004
SE_SACL_PRESENT = 0x0010
SE_DACL_AUTO_INHERIT_REQ = 0x0100
SE_SACL_AUTO_INHERIT_REQ = 0x0200
SE_DACL_AUTO_INHERITED = 0x0400
SE_SACL_AUTO_INHERITED = 0x0800
SE_DACL_PROTECTED = 0x1000
SE_SACL_PROTECTED = 0x2000

# ACE_HEADER AceFlags bits (MS-DTYP 2.4.4.1), in .NET emission order.
_ACE_FLAG_TOKENS: list[tuple[int, str]] = [
    (0x01, "OI"),   # OBJECT_INHERIT_ACE
    (0x02, "CI"),   # CONTAINER_INHERIT_ACE
    (0x04, "NP"),   # NO_PROPAGATE_INHERIT_ACE
    (0x08, "IO"),   # INHERIT_ONLY_ACE
    (0x10, "ID"),   # INHERITED_ACE
    (0x40, "SA"),   # SUCCESSFUL_ACCESS_ACE_FLAG
    (0x80, "FA"),   # FAILED_ACCESS_ACE_FLAG
]

# ACE_HEADER AceType values -> SDDL ace type token. The tokens are exactly the
# keys of Ace.AceTypesDict; an AceType with no SDDL token is emitted as its
# decimal value so that the parser turns it into "Unknown(<n>)" rather than
# silently dropping the ACE.
_ACE_TYPE_TOKENS: dict[int, str] = {
    0x00: "A",    # ACCESS_ALLOWED_ACE_TYPE
    0x01: "D",    # ACCESS_DENIED_ACE_TYPE
    0x02: "AU",   # SYSTEM_AUDIT_ACE_TYPE
    0x03: "AL",   # SYSTEM_ALARM_ACE_TYPE
    0x05: "OA",   # ACCESS_ALLOWED_OBJECT_ACE_TYPE
    0x06: "OD",   # ACCESS_DENIED_OBJECT_ACE_TYPE
    0x07: "OU",   # SYSTEM_AUDIT_OBJECT_ACE_TYPE
    0x08: "OL",   # SYSTEM_ALARM_OBJECT_ACE_TYPE
    0x09: "XA",   # ACCESS_ALLOWED_CALLBACK_ACE_TYPE
    0x0A: "XD",   # ACCESS_DENIED_CALLBACK_ACE_TYPE
    0x0B: "ZA",   # ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    0x0D: "XU",   # SYSTEM_AUDIT_CALLBACK_ACE_TYPE
    0x11: "ML",   # SYSTEM_MANDATORY_LABEL_ACE_TYPE
    0x12: "RA",   # SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
    0x13: "SP",   # SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
    0x14: "TL",   # SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE
}

# Combined access mask aliases, matched by exact equality and in this order
# (KR and KX share a value, KR wins).
_COMBINED_MASK_ALIASES: list[tuple[int, str]] = [
    (0x001F01FF, "FA"),
    (0x00120089, "FR"),
    (0x00120116, "FW"),
    (0x001200A0, "FX"),
    (0x000F003F, "KA"),
    (0x00020019, "KR"),
    (0x00020006, "KW"),
    (0x00020019, "KX"),
]

# Single bit access mask aliases, consumed greedily in this order.
_SINGLE_BIT_MASK_ALIASES: list[tuple[int, str]] = [
    (0x00000001, "CC"),
    (0x00000002, "DC"),
    (0x00000004, "LC"),
    (0x00000008, "SW"),
    (0x00000010, "RP"),
    (0x00000020, "WP"),
    (0x00000040, "DT"),
    (0x00000080, "LO"),
    (0x00000100, "CR"),
    (0x00010000, "SD"),
    (0x00020000, "RC"),
    (0x00040000, "WD"),
    (0x00080000, "WO"),
    (0x10000000, "GA"),
    (0x20000000, "GX"),
    (0x40000000, "GW"),
    (0x80000000, "GR"),
]

_ACE_OBJECT_TYPE_PRESENT = 0x01
_ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02


def access_mask_to_sddl(mask: int) -> str:
    """Emit an access mask the way .NET's GetSddlForm does."""
    mask &= 0xFFFFFFFF

    if mask == 0:
        # An empty mask has no alias; .NET writes the hex form.
        return "0x0"

    for value, name in _COMBINED_MASK_ALIASES:
        if mask == value:
            return name

    remaining = mask
    tokens: list[str] = []
    for value, name in _SINGLE_BIT_MASK_ALIASES:
        if (remaining & value) == value:
            tokens.append(name)
            remaining &= ~value
            remaining &= 0xFFFFFFFF

    if remaining != 0:
        # Unrepresentable as aliases; the whole mask goes out as hex.
        return f"0x{mask:x}"

    return "".join(tokens)


def ace_flags_to_sddl(flags: int) -> str:
    return "".join(name for bit, name in _ACE_FLAG_TOKENS if flags & bit)


def _acl_flags_to_sddl(control: int, protected_bit: int, auto_inherit_req_bit: int,
                       auto_inherited_bit: int) -> str:
    tokens: list[str] = []
    if control & protected_bit:
        tokens.append("P")
    if control & auto_inherit_req_bit:
        tokens.append("AR")
    if control & auto_inherited_bit:
        tokens.append("AI")
    return "".join(tokens)


def _guid_to_sddl(raw: bytes) -> str:
    if raw is None or raw == b"" or len(raw) != 16:
        return ""
    return bin_to_string(raw).lower()


def _ace_to_sddl(ace) -> str:
    ace_type = ace["AceType"]
    body = ace["Ace"]

    type_token = _ACE_TYPE_TOKENS.get(ace_type, str(ace_type))
    flags_token = ace_flags_to_sddl(ace["AceFlags"])

    mask = 0
    if "Mask" in body.fields:
        mask = body["Mask"]["Mask"]
    rights_token = access_mask_to_sddl(mask)

    object_guid = ""
    inherit_object_guid = ""
    if "Flags" in body.fields:
        object_flags = body["Flags"]
        if object_flags & _ACE_OBJECT_TYPE_PRESENT:
            object_guid = _guid_to_sddl(body["ObjectType"])
        if object_flags & _ACE_INHERITED_OBJECT_TYPE_PRESENT:
            inherit_object_guid = _guid_to_sddl(body["InheritedObjectType"])

    sid = ""
    if "Sid" in body.fields:
        sid = body["Sid"].formatCanonical()

    return (
        f"({type_token};{flags_token};{rights_token};"
        f"{object_guid};{inherit_object_guid};{sid})"
    )


def _acl_to_sddl(acl, flags_token: str) -> str:
    aces = "".join(_ace_to_sddl(ace) for ace in acl.aces)
    return f"{flags_token}{aces}"


def sddl_string_from_binary(sd_bytes: bytes) -> str:
    """Convert a binary (self-relative) security descriptor to its SDDL string.

    PORT NOTE: stands in for
    `new RawSecurityDescriptor(sd_bytes, 0).GetSddlForm(AccessControlSections.All)`.
    """
    if sd_bytes is None or len(sd_bytes) == 0:
        raise ValueError("Empty security descriptor.")

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    control = sd["Control"]

    # PORT NOTE: impacket's SR_SECURITY_DESCRIPTOR.fromString has a bug -- when
    # OffsetDacl is 0 it clears self['Sacl'] instead of self['Dacl'] -- so the
    # sub-structures are re-read here straight from the offsets rather than
    # trusted from the parsed object.
    owner_offset = sd["OffsetOwner"]
    group_offset = sd["OffsetGroup"]
    sacl_offset = sd["OffsetSacl"]
    dacl_offset = sd["OffsetDacl"]

    parts: list[str] = []

    if owner_offset != 0:
        owner = ldaptypes.LDAP_SID(data=sd_bytes[owner_offset:])
        parts.append(f"O:{owner.formatCanonical()}")

    if group_offset != 0:
        group = ldaptypes.LDAP_SID(data=sd_bytes[group_offset:])
        parts.append(f"G:{group.formatCanonical()}")

    if dacl_offset != 0:
        dacl = ldaptypes.ACL(data=sd_bytes[dacl_offset:])
        flags_token = _acl_flags_to_sddl(
            control, SE_DACL_PROTECTED, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED)
        parts.append(f"D:{_acl_to_sddl(dacl, flags_token)}")
    elif control & SE_DACL_PRESENT:
        # A NULL DACL. .NET's RawSecurityDescriptor leaves DiscretionaryAcl null
        # and emits no D: section at all, so neither do we.
        pass

    if sacl_offset != 0:
        sacl = ldaptypes.ACL(data=sd_bytes[sacl_offset:])
        flags_token = _acl_flags_to_sddl(
            control, SE_SACL_PROTECTED, SE_SACL_AUTO_INHERIT_REQ, SE_SACL_AUTO_INHERITED)
        parts.append(f"S:{_acl_to_sddl(sacl, flags_token)}")

    return "".join(parts)


def sddl_from_binary(sd_bytes: bytes,
                     object_type: SecurableObjectType = SecurableObjectType.Unknown):
    """PORT NOTE: Linux-only helper with no C# counterpart.

    Turns a *binary* security descriptor (as fetched over SMB or LDAP with
    impacket) into the very same `Sddl` object shape the string parser produces,
    by first rendering it as SDDL text exactly as .NET's
    RawSecurityDescriptor.GetSddlForm would and then parsing that text with the
    ported parser. All right names, ace types and SID aliases therefore come
    from the ported tables, identical to the string-parsing path.
    """
    # Imported here to keep group3rpy.sddl.sddl importable from either direction.
    from .sddl import Sddl

    return Sddl(sddl_string_from_binary(sd_bytes), object_type)
