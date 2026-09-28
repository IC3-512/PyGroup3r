"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/IniFileSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class IniFileSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.IniFileSetting."""

    name: str | None = None
    path: str | None = None
    action: SettingAction = SettingAction.Update
    ini_file_action: str | None = None
    section: str | None = None
    value: str | None = None
    property: str | None = None
