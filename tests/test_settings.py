"""Tests for group3rpy.settings -- the ports of
LibSnaffle/ActiveDirectory/GPO/GpoSettings/*.cs

Every setting class must be constructible with no arguments (all C# properties
have implicit or explicit defaults), and the four representative settings below
must expose exactly the property set of the C# original, snake_cased.
"""

import dataclasses

import pytest

import group3rpy.settings as settings
from group3rpy.ad.gpo import GpoSetting, ScriptType, SettingAction
from group3rpy.settings import (
    DataSourceSetting,
    DeviceSetting,
    DriveSetting,
    EnvVarSetting,
    EventAuditSetting,
    FileSecuritySetting,
    FileSetting,
    FolderSetting,
    GroupSetting,
    GroupSettingMember,
    IniFileSetting,
    KerbPolicySetting,
    NetOptionSetting,
    NetworkShareSetting,
    NtServiceSetting,
    PackageSetting,
    PrinterSetting,
    PrivRightSetting,
    RegHive,
    RegistrySetting,
    RegistryValue,
    RegKeyValType,
    SchedTaskAction,
    SchedTaskEmailAction,
    SchedTaskExecAction,
    SchedTaskPrincipal,
    SchedTaskSetting,
    SchedTaskShowMessageAction,
    SchedTaskType,
    ScriptSetting,
    SecurityInheritanceType,
    ShortcutSetting,
    SystemAccessSetting,
    TaskTrigger,
    UserSetting,
)

# The 23 GpoSetting subclasses, one per C# file in GpoSettings/.
SETTING_CLASSES = [
    DataSourceSetting,
    DeviceSetting,
    DriveSetting,
    EnvVarSetting,
    EventAuditSetting,
    FileSecuritySetting,
    FileSetting,
    FolderSetting,
    GroupSetting,
    IniFileSetting,
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
    SystemAccessSetting,
    UserSetting,
]

# Nested (non-GpoSetting) classes declared inside the same C# files.
NESTED_CLASSES = [
    GroupSettingMember,
    RegistryValue,
    SchedTaskAction,
    SchedTaskExecAction,
    SchedTaskEmailAction,
    SchedTaskShowMessageAction,
    SchedTaskPrincipal,
    TaskTrigger,
]

# Base-class fields contributed by GpoSetting; excluded when comparing against
# the C# property list of a subclass.
BASE_FIELDS = {f.name for f in dataclasses.fields(GpoSetting)}


def own_fields(cls) -> set[str]:
    """The dataclass fields a setting declares itself, minus GpoSetting's."""
    return {f.name for f in dataclasses.fields(cls)} - BASE_FIELDS


def test_all_23_setting_classes_present():
    assert len(SETTING_CLASSES) == 23
    assert len({c.__name__ for c in SETTING_CLASSES}) == 23


@pytest.mark.parametrize("cls", SETTING_CLASSES, ids=lambda c: c.__name__)
def test_setting_class_is_gposetting_subclass(cls):
    assert issubclass(cls, GpoSetting)


@pytest.mark.parametrize(
    "cls", SETTING_CLASSES + NESTED_CLASSES, ids=lambda c: c.__name__
)
def test_instantiable_with_no_args(cls):
    instance = cls()
    assert dataclasses.is_dataclass(instance)


@pytest.mark.parametrize("cls", SETTING_CLASSES, ids=lambda c: c.__name__)
def test_base_fields_default_as_gposetting_does(cls):
    instance = cls()
    assert instance.source is None
    assert instance.policy_type is None
    assert instance.is_morphed is False


def test_exports_match_all():
    for name in settings.__all__:
        assert hasattr(settings, name), name


# ---------------------------------------------------------------------------
# Exact property-set checks against the C# source.
# ---------------------------------------------------------------------------

# RegistrySetting.cs -- class RegistrySetting : GpoSetting (13 properties)
CS_REGISTRY_SETTING = {
    "name",              # Name
    "status",            # Status
    "action",            # Action
    "registry_action",   # RegistryAction
    "display_decimal",   # DisplayDecimal
    "default",           # Default
    "changed",           # Changed
    "hive",              # Hive
    "key",               # Key
    "key_sddl_string",   # KeySddlString
    "parsed_key_sddl",   # ParsedKeySddl
    "inheritance",       # Inheritance
    "values",            # Values
}

# SchedTaskSetting.cs -- class SchedTaskSetting : GpoSetting (27 properties)
CS_SCHED_TASK_SETTING = {
    "name",                             # Name
    "type",                             # Type
    "changed",                          # Changed
    "task_type",                        # TaskType
    "setting_action",                   # SettingAction
    "sched_task_action",                # SchedTaskAction
    "author",                           # Author
    "principals",                       # Principals
    "description1",                     # Description1
    "comment",                          # Comment
    "duration",                         # Duration
    "wait_timeout",                     # WaitTimeout
    "start_only_if_idle",               # StartOnlyIfIdle
    "stop_on_idle_end",                 # StopOnIdleEnd
    "restart_on_idle",                  # RestartOnIdle
    "multiple_instances_policy",        # MultipleInstancesPolicy
    "disallow_start_if_on_batteries",   # DisallowStartIfOnBatteries
    "stop_if_going_on_batteries",       # StopIfGoingOnBatteries
    "system_required",                  # SystemRequired
    "allow_hard_terminate",             # AllowHardTerminate
    "allow_start_on_demand",            # AllowStartOnDemand
    "enabled",                          # Enabled
    "hidden",                           # Hidden
    "execution_time_limit",             # ExecutionTimeLimit
    "priority",                         # Priority
    "actions",                          # Actions
    "triggers",                         # Triggers
}

# GroupSetting.cs -- class GroupSetting : GpoSetting (10 properties)
CS_GROUP_SETTING = {
    "name",                 # Name
    "new_name",             # NewName
    "description",          # Description
    "group_sid",            # GroupSid
    "delete_all_groups",    # DeleteAllGroups
    "delete_all_users",     # DeleteAllUsers
    "remove_accounts",      # RemoveAccounts
    "action",               # Action
    "group_action",         # GroupAction
    "members",              # Members
}

# ScriptSetting.cs -- class ScriptSetting : GpoSetting (3 properties)
CS_SCRIPT_SETTING = {
    "script_type",   # ScriptType
    "cmd_line",      # CmdLine
    "parameters",    # Parameters
}


@pytest.mark.parametrize(
    "cls,expected,count",
    [
        (RegistrySetting, CS_REGISTRY_SETTING, 13),
        (SchedTaskSetting, CS_SCHED_TASK_SETTING, 27),
        (GroupSetting, CS_GROUP_SETTING, 10),
        (ScriptSetting, CS_SCRIPT_SETTING, 3),
    ],
    ids=["RegistrySetting", "SchedTaskSetting", "GroupSetting", "ScriptSetting"],
)
def test_property_set_matches_csharp(cls, expected, count):
    assert len(expected) == count
    assert own_fields(cls) == expected


# ---------------------------------------------------------------------------
# Enums ported verbatim.
# ---------------------------------------------------------------------------


def test_reg_key_val_type_members_and_values():
    assert [m.name for m in RegKeyValType] == [
        "REG_NONE",
        "REG_SZ",
        "REG_EXPAND_SZ",
        "REG_BINARY",
        "REG_DWORD",
        "REG_DWORD_BIG_ENDIAN",
        "REG_LINK",
        "REG_MULTI_SZ",
        "REG_RESOURCE_LIST",
        "REG_FULL_RESOURCE_DESCRIPTOR",
        "REG_RESOURCE_REQUIREMENTS_LIST",
        "REG_QWORD",
    ]
    assert [int(m) for m in RegKeyValType] == list(range(0, 12))


def test_reg_hive_members():
    assert [m.name for m in RegHive] == [
        "HKEY_CLASSES_ROOT",
        "HKEY_CURRENT_USER",
        "HKEY_LOCAL_MACHINE",
        "HKEY_USERS",
        "HKEY_CURRENT_CONFIG",
    ]


def test_registry_types_module_is_the_import_site():
    """options/reg_keys.py imports these from group3rpy.settings.registry_types."""
    from group3rpy.settings import registry_types

    assert registry_types.RegHive is RegHive
    assert registry_types.RegKeyValType is RegKeyValType


def test_sched_task_type_members():
    assert [m.name for m in SchedTaskType] == [
        "Task",
        "TaskV2",
        "ImmediateTask",
        "ImmediateTaskV2",
    ]


def test_security_inheritance_type_members():
    assert [m.name for m in SecurityInheritanceType] == [
        "NO_REPLACE",
        "CONFIGURE_THEN_INHERIT",
        "CONFIGURE_THEN_PROPAGATE",
    ]


# ---------------------------------------------------------------------------
# C# value-type defaults.
# ---------------------------------------------------------------------------


def test_csharp_enum_zero_defaults():
    # default(SettingAction) == SettingAction.Update, default(ScriptType) == Logon,
    # default(RegHive) == HKEY_CLASSES_ROOT, default(SchedTaskType) == Task.
    assert RegistrySetting().action is SettingAction.Update
    assert RegistrySetting().hive is RegHive.HKEY_CLASSES_ROOT
    assert RegistryValue().reg_key_val_type is RegKeyValType.REG_NONE
    assert ScriptSetting().script_type is ScriptType.Logon
    assert SchedTaskSetting().task_type is SchedTaskType.Task
    assert SchedTaskSetting().setting_action is SettingAction.Update
    assert FileSecuritySetting().security_inheritance_type is (
        SecurityInheritanceType.NO_REPLACE
    )


def test_collection_initialiser_defaults():
    # These C# properties carry `= new List<...>()` initialisers.
    assert GroupSetting().members == []
    assert RegistrySetting().values == []
    assert PrivRightSetting().trustee_sids == []
    assert PrivRightSetting().trustees == []
    assert PackageSetting().msi_file_list == []
    assert SchedTaskEmailAction().attachments == []
    # ...and these have none, so they default to null/None.
    assert DataSourceSetting().attributes is None
    assert SchedTaskSetting().principals is None
    assert SchedTaskSetting().actions is None
    assert SchedTaskSetting().triggers is None
    # Each instance gets its own list.
    assert GroupSetting().members is not GroupSetting().members


def test_string_initialiser_defaults():
    # `= ""` in the C# vs implicit null.
    assert DataSourceSetting().name == ""
    assert KerbPolicySetting().key == ""
    assert KerbPolicySetting().value == ""
    assert SystemAccessSetting().setting_name == ""
    assert ScriptSetting().cmd_line == ""
    assert FileSetting().file_name == ""
    assert EnvVarSetting().status == ""
    assert GroupSetting().new_name == ""
    assert DeviceSetting().name is None
    assert UserSetting().name is None


def test_sddl_fields_default_to_none():
    assert RegistrySetting().parsed_key_sddl is None
    assert RegistryValue().parsed_value_sddl is None
    assert NtServiceSetting().parsed_sddl is None
    assert FileSecuritySetting().parsed_sddl is None


# ---------------------------------------------------------------------------
# RegistrySetting.RegHiveFromString
# ---------------------------------------------------------------------------


def test_reg_hive_from_string_machine():
    setting = RegistrySetting()
    setting.reg_hive_from_string("MACHINE")
    assert setting.hive is RegHive.HKEY_LOCAL_MACHINE


def test_reg_hive_from_string_unknown_raises():
    setting = RegistrySetting()
    with pytest.raises(NotImplementedError) as excinfo:
        setting.reg_hive_from_string("USER")
    assert str(excinfo.value) == (
        "Found a registry hive short name I don't recognise in RegHiveFromString"
    )


def test_sched_task_action_hierarchy():
    for cls in (SchedTaskExecAction, SchedTaskEmailAction, SchedTaskShowMessageAction):
        assert issubclass(cls, SchedTaskAction)


def test_sched_task_email_action_from_property():
    # C# `From`; `from` is a Python keyword so the port uses `from_`.
    action = SchedTaskEmailAction(from_="a@b.c", to="d@e.f")
    assert action.from_ == "a@b.c"
    assert own_fields(SchedTaskEmailAction) == {
        "from_",
        "to",
        "subject",
        "body",
        "header_fields",
        "attachments",
        "server",
    }


def test_shortcut_and_file_security_class_names():
    # Filename/classname mismatches in the C# are preserved.
    assert ShortcutSetting.__name__ == "ShortcutSetting"
    assert FileSecuritySetting.__name__ == "FileSecuritySetting"


def test_net_option_setting_has_no_properties():
    assert own_fields(NetOptionSetting) == set()


@pytest.mark.parametrize(
    "cls,count",
    [
        (DataSourceSetting, 9),
        (DeviceSetting, 6),
        (DriveSetting, 13),
        (EnvVarSetting, 4),
        (EventAuditSetting, 2),
        (FileSecuritySetting, 4),
        (FileSetting, 6),
        (FolderSetting, 9),
        (GroupSetting, 10),
        (IniFileSetting, 7),
        (KerbPolicySetting, 2),
        (NetOptionSetting, 0),
        (NetworkShareSetting, 10),
        (NtServiceSetting, 17),
        (PackageSetting, 12),
        (PrinterSetting, 9),
        (PrivRightSetting, 4),
        (RegistrySetting, 13),
        (SchedTaskSetting, 27),
        (ScriptSetting, 3),
        (ShortcutSetting, 12),
        (SystemAccessSetting, 2),
        (UserSetting, 11),
    ],
    ids=lambda v: v.__name__ if isinstance(v, type) else str(v),
)
def test_property_counts_match_csharp(cls, count):
    """C# property count per GpoSettings/*.cs vs ported attribute count."""
    assert len(own_fields(cls)) == count
