"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/DriveSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class DriveSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.DriveSetting."""

    name: str | None = None
    action: SettingAction = SettingAction.Update
    drive_action: str | None = None
    this_drive: str | None = None
    all_drives: str | None = None
    user_name: str | None = None
    cpassword: str | None = None
    password: str | None = None
    path: str | None = None
    label: str | None = None
    persistent: str | None = None
    letter: str | None = None
    drive_letter: str | None = None
