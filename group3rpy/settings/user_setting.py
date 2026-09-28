"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/UserSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class UserSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.UserSetting."""

    name: str | None = None
    new_name: str | None = None
    full_name: str | None = None
    user_name: str | None = None
    cpassword: str | None = None
    password: str | None = None
    account_disabled: bool = False
    pw_never_expires: bool = False
    action: SettingAction = SettingAction.Update
    user_action: str | None = None
    description: str | None = None
