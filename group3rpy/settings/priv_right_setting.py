"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/PrivRightSetting.cs"""

from dataclasses import dataclass, field

from ..ad.gpo import GpoSetting
from ..ad.trustee import Trustee


@dataclass
class PrivRightSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.PrivRightSetting."""

    privilege: str | None = None
    trustee_sids: list[str] = field(default_factory=list)
    trustees: list[Trustee] = field(default_factory=list)
    description: str | None = None
