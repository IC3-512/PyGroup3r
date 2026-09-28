"""Port of LibSnaffle/Sddl.Parser/Ace.cs."""

from .acm import Acm
from .errors import Error
from .format import Format
from .match import Match
from .securable_object_type import SecurableObjectType
from .sid import Sid
from .string_builder_extensions import append_indent_env, append_line_env
from .string_length_comparer import sorted_by_string_length

BEGIN_TOKEN = "("
END_TOKEN = ")"
SEPARATOR_TOKEN = ";"


class Ace(Acm):
    """Port of the Sddl.Parser.Ace class."""

    def __init__(self, ace: str, type: SecurableObjectType = SecurableObjectType.Unknown):
        super().__init__()

        self._raw = ace
        self._ace_type: str | None = None
        self._ace_flags: list[str] | None = None
        self._rights: list[str] | None = None
        self._object_guid: str | None = None
        self._inherit_object_guid: str | None = None
        self._ace_sid: Sid | None = None

        parts = self._raw.split(SEPARATOR_TOKEN)

        if len(parts) < 6:
            self.report(Error.SDP003.format(str(len(parts))))

        # ace_type
        if len(parts) > 0 and len(parts[0]) > 0:
            ace_type, reminder = Match.one_by_prefix(parts[0], AceTypesDict)

            if ace_type is None or not (reminder is None or reminder == ""):
                ace_type = Format.unknown(parts[0])

            self._ace_type = ace_type

        # ace_flags
        if len(parts) > 1 and len(parts[1]) > 0:
            flags, reminder = Match.many_by_prefix(parts[1], AceFlagsDict)

            if not (reminder is None or reminder == ""):
                flags.append(Format.unknown(reminder))

            self._ace_flags = list(flags)

        # rights
        if len(parts) > 2 and len(parts[2]) > 0:
            ok, access_mask = self._try_parse_hex(parts[2])
            if ok:
                rights: list[str] = []

                ace_uint_specific_rights_for_type = AceUintSpecificRightsDict.get(type)
                if ace_uint_specific_rights_for_type is not None:
                    matched, access_mask = Match.many_by_uint(
                        access_mask, ace_uint_specific_rights_for_type)
                    rights = rights + matched

                matched, access_mask = Match.many_by_uint(access_mask, AceUintRightsDict)
                rights = rights + matched

                if access_mask > 0:
                    rights = rights + [Format.unknown(f"0x{access_mask:X}")]

                self._rights = list(rights)
            else:
                if type == SecurableObjectType.WindowsService:
                    rights, reminder = Match.many_by_prefix(
                        parts[2], NtServiceAceAliasRightsDict)
                    if not (reminder is None or reminder == ""):
                        rights.append(Format.unknown(reminder))

                    self._rights = list(rights)
                else:
                    rights, reminder = Match.many_by_prefix(parts[2], AceAliasRightsDict)
                    if not (reminder is None or reminder == ""):
                        rights.append(Format.unknown(reminder))

                    self._rights = list(rights)

        # object_guid
        if len(parts) > 3 and len(parts[3]) > 0:
            self._object_guid = parts[3]

        # inherit_object_guid
        if len(parts) > 4 and len(parts[4]) > 0:
            self._inherit_object_guid = parts[4]

        # account_sid
        if len(parts) > 5 and len(parts[5]) > 0:
            self._ace_sid = Sid(parts[5])

        # resource_attribute
        if len(parts) > 6:
            # unsupported
            pass

    @property
    def raw(self) -> str:
        return self._raw

    @property
    def ace_type(self) -> str | None:
        return self._ace_type

    @property
    def ace_flags(self) -> list[str] | None:
        return self._ace_flags

    @property
    def rights(self) -> list[str] | None:
        return self._rights

    @property
    def object_guid(self) -> str | None:
        return self._object_guid

    @property
    def inherit_object_guid(self) -> str | None:
        return self._inherit_object_guid

    @property
    def ace_sid(self) -> Sid | None:
        return self._ace_sid

    @staticmethod
    def _try_parse_hex(hex: str) -> tuple[bool, int]:
        """Port of Ace.TryParseHex. Returns (success, result)."""
        if hex.lower().startswith("0x") or hex.lower().startswith("&h"):
            hex = hex[2:]
        else:
            return False, 0

        # uint.TryParse(hex, NumberStyles.HexNumber, null, out result) allows
        # leading and trailing whitespace and nothing else.
        stripped = hex.strip(" \t\n\r\f\v")
        if stripped == "":
            return False, 0
        for c in stripped:
            if c not in "0123456789abcdefABCDEF":
                return False, 0
        value = int(stripped, 16)
        if value > 0xFFFFFFFF:
            return False, 0
        return True, value

    def __str__(self) -> str:
        sb: list[str] = []

        if self._ace_sid is not None:
            append_line_env(sb, f"AceSid: {str(self._ace_sid)}")

        if self._ace_type is not None:
            append_line_env(sb, f"AceType: {str(self._ace_type)}")

        if self._ace_flags is not None and len(self._ace_flags) > 0:
            append_line_env(sb, f"AceFlags: {', '.join(self._ace_flags)}")

        if self._rights is not None and len(self._rights) > 0:
            append_line_env(sb, "Rights:")
            for i in range(len(self._rights)):
                append_indent_env(sb, self._rights[i])

        if self._object_guid is not None:
            append_line_env(sb, f"ObjectGuid: {str(self._object_guid)}")

        if self._inherit_object_guid is not None:
            append_line_env(sb, f"InheritObjectGuid: {str(self._inherit_object_guid)}")

        return "".join(sb)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ace):
            return False
        return (
            self._ace_type == other._ace_type
            and (
                (self._ace_flags is None and other._ace_flags is None)
                or (
                    self._ace_flags is not None
                    and other._ace_flags is not None
                    and len(set(self._ace_flags) - set(other._ace_flags)) == 0
                    and len(set(other._ace_flags) - set(self._ace_flags)) == 0
                )
            )
            and (
                (self._rights is None and other._rights is None)
                or (
                    self._rights is not None
                    and other._rights is not None
                    and len(set(self._rights) - set(other._rights)) == 0
                    and len(set(other._rights) - set(self._rights)) == 0
                )
            )
            and self._object_guid == other._object_guid
            and self._inherit_object_guid == other._inherit_object_guid
            and self._ace_sid == other._ace_sid
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self._ace_type, self._object_guid, self._inherit_object_guid))


# A dictionary of ace type strings as defined in https://msdn.microsoft.com/en-us/library/windows/desktop/aa374928(v=vs.85).aspx#ace_types
AceTypesDict: dict[str, str] = sorted_by_string_length({
    "A": "ACCESS_ALLOWED",
    "D": "ACCESS_DENIED",
    "OA": "OBJECT_ACCESS_ALLOWED",
    "OD": "OBJECT_ACCESS_DENIED",
    "AU": "AUDIT",
    "AL": "ALARM",
    "OU": "OBJECT_AUDIT",
    "OL": "OBJECT_ALARM",
    "ML": "MANDATORY_LABEL",
    "TL": "PROCESS_TRUST_LABEL",
    "XA": "CALLBACK_ACCESS_ALLOWED",
    "XD": "CALLBACK_ACCESS_DENIED",
    "RA": "RESOURCE_ATTRIBUTE",
    "SP": "SCOPED_POLICY_ID",
    "XU": "CALLBACK_AUDIT",
    "ZA": "CALLBACK_OBJECT_ACCESS_ALLOWED",
})

# A dictionary of ace flag strings as defined in https://msdn.microsoft.com/en-us/library/windows/desktop/aa374928(v=vs.85).aspx#ace_flags
AceFlagsDict: dict[str, str] = {
    "CI": "CONTAINER_INHERIT",
    "OI": "OBJECT_INHERIT",
    "NP": "NO_PROPAGATE",
    "IO": "INHERIT_ONLY",
    "ID": "INHERITED",
    "SA": "AUDIT_SUCCESS",
    "FA": "AUDIT_FAILURE",
}

# A dictionary of access right alias strings as defined in https://msdn.microsoft.com/en-us/library/windows/desktop/aa374928(v=vs.85).aspx#rights
AceAliasRightsDict: dict[str, str] = {
    # Generic access rights
    "GA": "GENERIC_ALL",
    "GR": "GENERIC_READ",
    "GW": "GENERIC_WRITE",
    "GX": "GENERIC_EXECUTE",

    # Standard access rights
    "RC": "READ_CONTROL",
    "SD": "STANDARD_DELETE",
    "WD": "WRITE_DAC",
    "WO": "WRITE_OWNER",

    # Directory service object access rights
    "RP": "READ_PROPERTY",
    "WP": "WRITE_PROPERTY",
    "CC": "CREATE_CHILD",
    "DC": "DELETE_CHILD",
    "LC": "LIST_CHILDREN",
    "SW": "SELF_WRITE",
    "LO": "LIST_OBJECT",
    "DT": "DELETE_TREE",
    "CR": "CONTROL_ACCESS",

    # File access rights
    "FA": "FILE_ALL",
    "FR": "FILE_READ",
    "FW": "FILE_WRITE",
    "FX": "FILE_EXECUTE",

    # Registry access rights
    "KA": "KEY_ALL",
    "KR": "KEY_READ",
    "KW": "KEY_WRITE",
    "KX": "KEY_EXECUTE",

    # Mandatory label rights
    "NR": "NO_READ_UP",
    "NW": "NO_WRITE_UP",
    "NX": "NO_EXECUTE_UP",
}

NtServiceAceAliasRightsDict: dict[str, str] = {
    # Generic access rights
    "CC": "SERVICE_QUERY_CONFIG",
    "LC": "SERVICE_QUERY_STATUS",
    "SW": "SERVICE_ENUMERATE_DEPENDENTS",
    "LO": "SERVICE_INTERROGATE",
    "RC": "READ_CONTROL",
    "RP": "SERVICE_START",
    "DT": "SERVICE_PAUSE_CONTINUE",
    "CR": "SERVICE_USER_DEFINED_CONTROL",
    "WD": "WRITE_DAC",
    "WO": "WRITE_OWNER",
    "WP": "SERVICE_STOP",
    "DC": "SERVICE_CHANGE_CONFIG",
    "SD": "DELETE",
}

# A dictionary of access right alias strings as defined in winnt.h.
# The numeric layout of AccessMask is explained here https://msdn.microsoft.com/pl-pl/library/windows/desktop/aa374896(v=vs.85).aspx.
AceUintRightsDict: dict[int, str] = {
    # Generic access rights
    0x80000000: "GENERIC_READ",
    0x40000000: "GENERIC_WRITE",
    0x20000000: "GENERIC_EXECUTE",
    0x10000000: "GENERIC_ALL",

    # Reserved access rights
    0x02000000: "MAXIMUM_ALLOWED",
    0x01000000: "ACCESS_SYSTEM_SECURITY",

    # Standard access rights
    0x001f0000: "STANDARD_RIGHTS_ALL",
    0x00100000: "SYNCHRONIZE",
    0x00080000: "WRITE_OWNER",
    0x00040000: "WRITE_DAC",
    0x00020000: "READ_CONTROL",
    0x00010000: "DELETE",
}

# A dictionary of object-specific access right alias strings as defined in winnt.h.
# Sample winnt.h definition can be found here: https://source.winehq.org/source/include/winnt.h.
AceUintSpecificRightsDict: dict[SecurableObjectType, dict[int, str]] = {
    SecurableObjectType.File: {
        # combined
        0x001f01ff: "ALL_ACCESS",
        0x001200a0: "GENERIC_EXECUTE",
        0x00120116: "GENERIC_WRITE",
        0x00120089: "GENERIC_READ",

        0x00000100: "WRITE_ATTRIBUTES",
        0x00000080: "READ_ATTRIBUTES",
        0x00000020: "EXECUTE",
        0x00000010: "WRITE_PROPERTIES",
        0x00000008: "READ_PROPERTIES",
        0x00000004: "APPEND_DATA",
        0x00000002: "WRITE_DATA",
        0x00000001: "READ_DATA",
    },
    SecurableObjectType.Directory: {
        # combined
        0x001f01ff: "ALL_ACCESS",
        0x001200a0: "GENERIC_EXECUTE",
        0x00120116: "GENERIC_WRITE",
        0x00120089: "GENERIC_READ",

        0x00000100: "WRITE_ATTRIBUTES",
        0x00000080: "READ_ATTRIBUTES",
        0x00000040: "DELETE_CHILD",
        0x00000020: "TRAVERSE",
        0x00000010: "WRITE_PROPERTIES",
        0x00000008: "READ_PROPERTIES",
        0x00000004: "ADD_SUBDIRECTORY",
        0x00000002: "ADD_FILE",
        0x00000001: "LIST_DIRECTORY",
    },
    SecurableObjectType.Pipe: {
        # combined
        0x001f01ff: "ALL_ACCESS",
        0x001200a0: "GENERIC_EXECUTE",
        0x00120116: "GENERIC_WRITE",
        0x00120089: "GENERIC_READ",

        0x00000100: "WRITE_ATTRIBUTES",
        0x00000080: "READ_ATTRIBUTES",
        0x00000004: "CREATE_PIPE_INSTANCE",
        0x00000002: "WRITE_DATA",
        0x00000001: "READ_DATA",
    },
    SecurableObjectType.Process: {
        # combined
        0x0012ffff: "ALL_ACCESS",

        0x00002000: "SET_LIMITED_INFORMATION",
        0x00001000: "QUERY_LIMITED_INFORMATION",
        0x00000800: "SUSPEND_RESUME",
        0x00000400: "QUERY_INFORMATION",
        0x00000200: "SET_INFORMATION",
        0x00000100: "SET_QUOTA",
        0x00000080: "CREATE_PROCESS",
        0x00000040: "DUP_HANDLE",
        0x00000020: "VM_WRITE",
        0x00000010: "VM_READ",
        0x00000008: "VM_OPERATION",
        0x00000002: "CREATE_THREAD",
        0x00000001: "TERMINATE",
    },
    SecurableObjectType.Thread: {
        # combined
        0x0012ffff: "ALL_ACCESS",

        0x00001000: "RESUME",
        0x00000800: "QUERY_LIMITED_INFORMATION",
        0x00000400: "SET_LIMITED_INFORMATION",
        0x00000200: "DIRECT_IMPERSONATION",
        0x00000100: "IMPERSONATE",
        0x00000080: "SET_THREAD_TOKEN",
        0x00000040: "QUERY_INFORMATION",
        0x00000020: "SET_INFORMATION",
        0x00000010: "SET_CONTEXT",
        0x00000008: "GET_CONTEXT",
        0x00000002: "SUSPEND_RESUME",
        0x00000001: "TERMINATE",
    },
    SecurableObjectType.AccessToken: {
        # combined
        0x000201ff: "ALL_ACCESS",
        0x000200e0: "WRITE",
        0x00020008: "READ",
        0x00020000: "EXECUTE",

        0x00000100: "ADJUST_SESSIONID",
        0x00000080: "ADJUST_DEFAULT",
        0x00000040: "ADJUST_GROUPS",
        0x00000020: "ADJUST_PRIVILEGES",
        0x00000010: "QUERY_SOURCE",
        0x00000008: "QUERY",
        0x00000004: "IMPERSONATE",
        0x00000002: "DUPLICATE",
        0x00000001: "ASSIGN_PRIMARY",
    },
    SecurableObjectType.RegistryKey: {
        # combined
        0x000201ff: "ALL_ACCESS",
        0x000200e0: "WRITE",
        0x00020008: "READ",
        0x00020000: "EXECUTE",

        0x00000300: "WOW64_RES",
        0x00000200: "WOW64_32KEY",
        0x00000100: "WOW64_64KEY",
        0x00000020: "CREATE_LINK",
        0x00000010: "NOTIFY",
        0x00000008: "ENUMERATE_SUB_KEYS",
        0x00000004: "CREATE_SUB_KEY",
        0x00000002: "SET_VALUE",
        0x00000001: "QUERY_VALUE",
    },
}
