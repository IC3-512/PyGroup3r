"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/NetworkShareSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class NetworkShareSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.NetworkShareSetting."""

    name: str | None = None
    action: SettingAction = SettingAction.Update
    network_share_action: str | None = None
    path: str | None = None
    limit_users: str | None = None
    abe: str | None = None
    all_regular: str | None = None
    all_hidden: str | None = None
    all_admin_drive: str | None = None
    comment: str | None = None
