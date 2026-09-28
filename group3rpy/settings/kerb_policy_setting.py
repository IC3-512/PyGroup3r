"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/KerbPolicySetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting


@dataclass
class KerbPolicySetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.KerbPolicySetting."""

    key: str = ""
    value: str = ""
