"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/RegistrySetting.cs

The `RegHive` and `RegKeyValType` enums declared in the same C# file live in
`registry_types.py` and are re-exported here.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from ..ad.gpo import GpoSetting, SettingAction
from .registry_types import RegHive, RegKeyValType

if TYPE_CHECKING:  # pragma: no cover
    from ..sddl.sddl import Sddl

__all__ = ["RegistryValue", "RegistrySetting", "RegHive", "RegKeyValType"]


@dataclass
class RegistryValue:
    """Port of LibSnaffle.ActiveDirectory.RegistryValue."""

    value_name: str | None = None  # gpp reg settings
    # gpp reg settings "type", registry.pol
    reg_key_val_type: RegKeyValType = RegKeyValType.REG_NONE
    value_sddl_string: str | None = None  #
    parsed_value_sddl: "Sddl | None" = None  #
    value_bytes: bytes | None = None  # registry.pol
    value_string: str | None = None


@dataclass
class RegistrySetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.RegistrySetting."""

    name: str | None = None  # gpp reg settings
    status: str | None = None  # gpp reg settings
    action: SettingAction = SettingAction.Update  # gpp reg settings
    registry_action: str | None = None
    display_decimal: str | None = None  # gpp reg settings
    default: str | None = None  # gpp reg settings
    # PORT NOTE: C# `DateTime` defaults to DateTime.MinValue; Python has no
    # equivalent value-type sentinel, so unset is None.
    changed: datetime | None = None

    # hive and key
    hive: RegHive = RegHive.HKEY_CLASSES_ROOT  # gpp reg settings
    key: str | None = None  # gpp reg settings
    key_sddl_string: str | None = None  # .inf "registry keys"
    parsed_key_sddl: "Sddl | None" = None  # .inf "registry keys"
    inheritance: str | None = None  # .inf "registry keys"
    values: list[RegistryValue] = field(default_factory=list)  #

    def reg_hive_from_string(self, hive_string: str) -> None:
        """Port of RegistrySetting.RegHiveFromString."""
        if hive_string == "MACHINE":
            self.hive = RegHive.HKEY_LOCAL_MACHINE
        else:
            raise NotImplementedError(
                "Found a registry hive short name I don't recognise in RegHiveFromString"
            )
