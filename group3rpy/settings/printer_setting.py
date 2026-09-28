"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/PrinterSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, SettingAction


@dataclass
class PrinterSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.PrinterSetting."""

    name: str | None = None
    action: SettingAction = SettingAction.Update
    printer_action: str | None = None
    path: str | None = None
    comment: str | None = None
    user_name: str | None = None
    cpassword: str | None = None
    password: str | None = None
    port: str | None = None
