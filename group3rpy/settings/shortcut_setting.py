"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/ShortCutSetting.cs

The original file is named ShortCutSetting.cs but declares `ShortcutSetting`;
the class name is kept exactly as the C# has it.
"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class ShortcutSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.ShortcutSetting."""

    name: str | None = None
    status: str | None = None
    action: SettingAction = SettingAction.Update
    shortcut_action: str | None = None
    target_type: str | None = None
    arguments: str | None = None
    icon_path: str | None = None
    icon_index: str | None = None
    start_in: str | None = None
    comment: str | None = None
    shortcut_path: str | None = None
    target_path: str | None = None
