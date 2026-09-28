"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/SystemAccessSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting


@dataclass
class SystemAccessSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.SystemAccessSetting."""

    setting_name: str = ""
    value_string: str = ""
