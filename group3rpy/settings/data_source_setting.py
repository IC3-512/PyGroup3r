"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/DataSourceSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class DataSourceSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.DataSourceSetting."""

    name: str = ""
    action: SettingAction = SettingAction.Update
    user_name: str = ""
    cpassword: str = ""
    password: str = ""
    dsn: str = ""
    driver: str = ""
    description: str = ""
    # C# `Dictionary<string, string> Attributes` has no initialiser, so it
    # defaults to null.
    attributes: dict[str, str] | None = None
