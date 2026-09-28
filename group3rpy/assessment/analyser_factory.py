"""Port of Group3r/Assessment/AnalyserFactory.cs

Maps a setting type to its analyser. The dispatch order and -- crucially -- the
set of *disabled* analysers are reproduced exactly: the original has
DeviceAnalyser, DriveAnalyser, EnvVarAnalyser, EventAuditAnalyser, FolderAnalyser,
IniFileAnalyser, SystemAccessAnalyser and UserAnalyser commented out, so those
setting types fall through to `None` and produce no findings at all. Enabling any
of them would make this port report findings the original does not.
"""

from typing import Optional

from ..settings import (
    DataSourceSetting,
    FileSecuritySetting,
    FileSetting,
    GroupSetting,
    KerbPolicySetting,
    NetOptionSetting,
    NetworkShareSetting,
    NtServiceSetting,
    PackageSetting,
    PrinterSetting,
    PrivRightSetting,
    RegistrySetting,
    SchedTaskSetting,
    ScriptSetting,
    ShortcutSetting,
)
from .analysers.analyser import Analyser


class AnalyserFactory:
    """Port of Group3r.Assessment.AnalyserFactory."""

    def get_analyser(self, setting) -> Optional[Analyser]:
        """Port of AnalyserFactory.GetAnalyser.

        The original uses exact type equality (`setting.GetType() == typeof(X)`),
        not an `is`-style subtype test, so `type(setting) is X` is the faithful
        translation.
        """
        # Imported here so a partially-ported analyser package cannot break import
        # of the whole assessment module.
        from .analysers.data_source import DataSourceAnalyser
        from .analysers.file import FileAnalyser
        from .analysers.file_sec import FileSecAnalyser
        from .analysers.group import GroupAnalyser
        from .analysers.kerb_policy import KerbPolicyAnalyser
        from .analysers.net_option import NetOptionAnalyser
        from .analysers.network_share import NetworkShareAnalyser
        from .analysers.nt_service import NtServiceAnalyser
        from .analysers.package import PackageAnalyser
        from .analysers.printer import PrinterAnalyser
        from .analysers.priv_right import PrivRightAnalyser
        from .analysers.registry import RegistryAnalyser
        from .analysers.sched_task import SchedTaskAnalyser
        from .analysers.script import ScriptAnalyser
        from .analysers.shortcut import ShortcutAnalyser

        setting_type = type(setting)

        if setting_type is DataSourceSetting:
            return DataSourceAnalyser(setting)
        if setting_type is FileSecuritySetting:
            return FileSecAnalyser(setting)
        # else if (setting.GetType() == typeof(DeviceSetting))
        # {
        #     return new DeviceAnalyser() { setting = castSetting };
        # }
        # else if (setting.GetType() == typeof(DriveSetting))
        # {
        #     return new DriveAnalyser() { setting = castSetting };
        # }
        # else if (setting.GetType() == typeof(EnvVarSetting))
        # {
        #     return new EnvVarAnalyser() { setting = castSetting };
        # }
        # else if (setting.GetType() == typeof(EventAuditSetting))
        # {
        #     return new EventAuditAnalyser() { setting = castSetting };
        # }
        if setting_type is FileSetting:
            return FileAnalyser(setting)
        # else if (setting.GetType() == typeof(FolderSetting))
        # {
        #     return new FolderAnalyser() { setting = castSetting };
        # }
        if setting_type is GroupSetting:
            return GroupAnalyser(setting)
        # else if (setting.GetType() == typeof(IniFileSetting))
        # {
        #     return new IniFileAnalyser() { setting = castSetting };
        # }
        if setting_type is KerbPolicySetting:
            return KerbPolicyAnalyser(setting)
        if setting_type is NetOptionSetting:
            return NetOptionAnalyser(setting)
        if setting_type is NetworkShareSetting:
            return NetworkShareAnalyser(setting)
        if setting_type is NtServiceSetting:
            return NtServiceAnalyser(setting)
        if setting_type is PackageSetting:
            return PackageAnalyser(setting)
        if setting_type is PrinterSetting:
            return PrinterAnalyser(setting)
        if setting_type is PrivRightSetting:
            return PrivRightAnalyser(setting)
        if setting_type is RegistrySetting:
            return RegistryAnalyser(setting)
        if setting_type is SchedTaskSetting:
            return SchedTaskAnalyser(setting)
        if setting_type is ScriptSetting:
            return ScriptAnalyser(setting)
        if setting_type is ShortcutSetting:
            return ShortcutAnalyser(setting)
        # else if (setting.GetType() == typeof(SystemAccessSetting))
        # {
        #     return new SystemAccessAnalyser() { setting = castSetting };
        # }
        # else if (setting.GetType() == typeof(UserSetting))
        # {
        #     return new UserAnalyser() { setting = castSetting };
        # }
        return None
        # throw new NotImplementedException("Group3r doesn't have an analyser for
        # the type of setting found in " + setting.Source);
