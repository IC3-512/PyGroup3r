"""Ports of LibSnaffle/ActiveDirectory/GPO/GpoSettings/*.cs

One module per C# file. Every setting class, nested class and enum declared in
those files is re-exported here under its exact C# name so that AnalyserFactory
can import them from one place. `GpoSetting` itself lives in
`group3rpy.ad.gpo` and is re-exported for convenience.
"""

from ..ad.gpo import GpoSetting, PolicyType, ScriptType, SettingAction
from .data_source_setting import DataSourceSetting
from .device_setting import DeviceSetting
from .drive_setting import DriveSetting
from .env_var_setting import EnvVarSetting
from .event_audit_setting import EventAuditSetting
from .file_security import FileSecuritySetting, SecurityInheritanceType
from .file_setting import FileSetting
from .folder_setting import FolderSetting
from .group_setting import GroupSetting, GroupSettingMember
from .ini_file_setting import IniFileSetting
from .kerb_policy_setting import KerbPolicySetting
from .net_option_setting import NetOptionSetting
from .network_share_setting import NetworkShareSetting
from .nt_service_setting import NtServiceSetting
from .package_setting import PackageSetting
from .printer_setting import PrinterSetting
from .priv_right_setting import PrivRightSetting
from .registry_setting import RegistrySetting, RegistryValue
from .registry_types import RegHive, RegKeyValType
from .sched_task_setting import (
    SchedTaskAction,
    SchedTaskEmailAction,
    SchedTaskExecAction,
    SchedTaskPrincipal,
    SchedTaskSetting,
    SchedTaskShowMessageAction,
    SchedTaskType,
    TaskTrigger,
)
from .script_setting import ScriptSetting
from .shortcut_setting import ShortcutSetting
from .system_access_setting import SystemAccessSetting
from .user_setting import UserSetting

__all__ = [
    # base + shared enums, from group3rpy.ad.gpo
    "GpoSetting",
    "PolicyType",
    "ScriptType",
    "SettingAction",
    # settings
    "DataSourceSetting",
    "DeviceSetting",
    "DriveSetting",
    "EnvVarSetting",
    "EventAuditSetting",
    "FileSecuritySetting",
    "FileSetting",
    "FolderSetting",
    "GroupSetting",
    "IniFileSetting",
    "KerbPolicySetting",
    "NetOptionSetting",
    "NetworkShareSetting",
    "NtServiceSetting",
    "PackageSetting",
    "PrinterSetting",
    "PrivRightSetting",
    "RegistrySetting",
    "SchedTaskSetting",
    "ScriptSetting",
    "ShortcutSetting",
    "SystemAccessSetting",
    "UserSetting",
    # nested classes and enums declared in the same C# files
    "GroupSettingMember",
    "RegHive",
    "RegKeyValType",
    "RegistryValue",
    "SchedTaskAction",
    "SchedTaskEmailAction",
    "SchedTaskExecAction",
    "SchedTaskPrincipal",
    "SchedTaskShowMessageAction",
    "SchedTaskType",
    "SecurityInheritanceType",
    "TaskTrigger",
]
