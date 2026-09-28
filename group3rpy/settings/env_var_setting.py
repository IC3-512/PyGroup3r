"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/EnvVarSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class EnvVarSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.EnvVarSetting."""

    name: str = ""
    status: str = ""
    action: SettingAction = SettingAction.Update
    env_var_action: str | None = None
