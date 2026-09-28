"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/GroupSetting.cs"""

from dataclasses import dataclass, field

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class GroupSettingMember:
    """Port of LibSnaffle.ActiveDirectory.GroupSettingMember."""

    name: str | None = None
    action: SettingAction = SettingAction.Update
    sid: str | None = None
    resolved_name: str | None = None


@dataclass
class GroupSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.GroupSetting."""

    name: str = ""
    new_name: str = ""
    description: str | None = None
    group_sid: str | None = None
    delete_all_groups: bool = False
    delete_all_users: bool = False
    remove_accounts: bool = False
    action: SettingAction = SettingAction.Update
    group_action: str | None = None
    members: list[GroupSettingMember] = field(default_factory=list)
