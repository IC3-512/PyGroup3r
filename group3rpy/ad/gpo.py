"""Port of LibSnaffle/ActiveDirectory/GPO/GPO.cs and GpoSetting.cs

Holds the GPO model plus the `GpoSetting` base class that all 25 setting types
inherit from, including the GPP cpassword decryption routine.
"""

import base64
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, List, Optional

from Cryptodome.Cipher import AES

if TYPE_CHECKING:  # pragma: no cover
    from ..sddl.sddl import Sddl


class ScriptType(Enum):
    Logon = "Logon"
    Logoff = "Logoff"
    Startup = "Startup"
    Shutdown = "Shutdown"


class SettingAction(Enum):
    Update = "Update"
    Create = "Create"
    Remove = "Remove"
    Add = "Add"
    Unknown = "Unknown"


class PolicyType(Enum):
    Computer = "Computer"
    User = "User"
    Package = "Package"


# Literal port of the AES key in GpoSetting.DecryptCpassword. This is the
# statically published Microsoft key from MS-GPPREF, the same one @obscuresec's
# Get-GPPPassword uses; it exists so that auditors can flag GPP passwords as
# recoverable, which is the whole point of the MS14-025 finding.
_GPP_AES_KEY = bytes(
    [
        0x4E, 0x99, 0x06, 0xE8, 0xFC, 0xB6, 0x6C, 0xC9,
        0xFA, 0xF4, 0x93, 0x10, 0x62, 0x0F, 0xFE, 0xE8,
        0xF4, 0x96, 0xE8, 0x06, 0xCC, 0x05, 0x79, 0x90,
        0x20, 0x9B, 0x09, 0xA4, 0x33, 0xB6, 0x6C, 0x1B,
    ]
)


def parse_setting_action(action_string: Optional[str]) -> SettingAction:
    """Literal port of GpoSetting.ParseSettingAction."""
    return {
        "C": SettingAction.Create,
        "U": SettingAction.Update,
        "R": SettingAction.Remove,
        "ADD": SettingAction.Add,
    }.get(action_string, SettingAction.Unknown)


def decrypt_cpassword(cpassword: Optional[str]) -> Optional[str]:
    """Literal port of GpoSetting.DecryptCpassword.

    The odd padding table (mod 1 -> "=") is reproduced from the original rather
    than corrected, so that malformed cpassword values fail the same way.
    """
    if cpassword is None:
        return None

    cpass_mod = len(cpassword) % 4
    padding = {1: "=", 2: "==", 3: "="}.get(cpass_mod, "")
    cpassword_padded = cpassword + padding

    decoded = base64.b64decode(cpassword_padded)
    cipher = AES.new(_GPP_AES_KEY, AES.MODE_CBC, iv=b"\x00" * 16)
    decrypted = cipher.decrypt(decoded)
    # The original uses TransformFinalBlock, which strips PKCS7 padding.
    if decrypted:
        pad_len = decrypted[-1]
        if 1 <= pad_len <= 16 and decrypted[-pad_len:] == bytes([pad_len]) * pad_len:
            decrypted = decrypted[:-pad_len]
    return decrypted.decode("utf-16-le", errors="replace")


@dataclass
class GpoSetting:
    """Port of LibSnaffle.ActiveDirectory.GpoSetting.

    Base class for all setting types. `source` is the sysvol path the setting was
    parsed out of; `policy_type` and `is_morphed` are set by the parsers.
    """

    source: Optional[str] = None
    policy_type: Optional[PolicyType] = None
    is_morphed: bool = False

    # Exposed as methods too, so ported analysers can call them as the C# does.
    parse_setting_action = staticmethod(parse_setting_action)
    decrypt_cpassword = staticmethod(decrypt_cpassword)


@dataclass
class GPOLink:
    """Port of LibSnaffle.ActiveDirectory.GPOLink."""

    link_path: Optional[str] = None
    link_enforced: Optional[str] = None


@dataclass
class GPOAttributes:
    """Port of LibSnaffle.ActiveDirectory.GPOAttributes."""

    is_morphed_gpo: bool = False
    gpo_links: List[GPOLink] = field(default_factory=list)
    ads_path: Optional[str] = None
    display_name: Optional[str] = None
    created_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    nt_security_descriptor: Optional[str] = None
    nt_security_descriptor_sddl: Optional["Sddl"] = None
    distinguished_name: Optional[str] = None
    path_in_sysvol: Optional[str] = None
    uid: Optional[str] = None
    version_number: Optional[str] = None
    computer_policy_enabled: bool = False
    user_policy_enabled: bool = False
    # ADDITION (not in the C# GPOAttributes): the gPCWQLFilter link, so a
    # WMI-filtered GPO can be reported as having a possibly narrower scope rather
    # than being silently treated as applying everywhere it is linked.
    wmi_filter: Optional[str] = None


@dataclass
class GPO:
    """Port of LibSnaffle.ActiveDirectory.GPO."""

    attributes: GPOAttributes = field(default_factory=GPOAttributes)
    gpo_files: List[str] = field(default_factory=list)
    settings: List[Any] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        uid: Optional[str] = None,
        path_in_sysvol: Optional[str] = None,
        morphed: bool = False,
    ) -> "GPO":
        """Covers the three C# constructor overloads."""
        gpo = cls()
        if uid is not None:
            gpo.attributes.uid = uid
        if path_in_sysvol is not None:
            gpo.attributes.path_in_sysvol = path_in_sysvol
            gpo.attributes.is_morphed_gpo = morphed
        return gpo
