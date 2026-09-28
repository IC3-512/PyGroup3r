"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/FileSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class FileSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.FileSetting."""

    file_name: str = ""
    status: str = ""
    action: SettingAction = SettingAction.Update
    file_action: str | None = None
    target_path: str = ""
    from_path: str = ""
