"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/NetOptionSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting


@dataclass
class NetOptionSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.NetOptionSetting."""

    # TODO better sample data. Feels like there's something missing.
