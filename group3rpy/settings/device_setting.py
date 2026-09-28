"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/DeviceSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting


@dataclass
class DeviceSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.DeviceSetting."""

    name: str | None = None
    device_action: str | None = None
    device_class: str | None = None
    device_class_guid: str | None = None
    device_type: str | None = None
    device_type_id: str | None = None
