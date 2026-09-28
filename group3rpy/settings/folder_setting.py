"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/FolderSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class FolderSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.FolderSetting."""

    name: str | None = None
    status: str | None = None
    image: str | None = None
    action: SettingAction = SettingAction.Update
    folder_action: str | None = None
    path: str | None = None
    read_only: bool = False
    archive: bool = False
    hidden: bool = False
