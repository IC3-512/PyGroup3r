"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/SchedTaskSetting.cs"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from ..ad.gpo import GpoSetting, SettingAction


class SchedTaskType(Enum):
    """Port of LibSnaffle.ActiveDirectory.SchedTaskType."""

    Task = 0
    TaskV2 = 1
    ImmediateTask = 2
    ImmediateTaskV2 = 3


@dataclass
class SchedTaskPrincipal:
    """Port of LibSnaffle.ActiveDirectory.SchedTaskPrincipal."""

    id: str | None = None
    user_id: str | None = None
    cpassword: str | None = None
    password: str | None = None
    logon_type: str | None = None
    run_level: str | None = None


@dataclass
class SchedTaskAction:
    """Port of LibSnaffle.ActiveDirectory.SchedTaskAction (empty base class)."""


@dataclass
class SchedTaskExecAction(SchedTaskAction):
    """Port of LibSnaffle.ActiveDirectory.SchedTaskExecAction."""

    command: str | None = None
    args: str | None = None
    working_dir: str | None = None


@dataclass
class SchedTaskEmailAction(SchedTaskAction):
    """Port of LibSnaffle.ActiveDirectory.SchedTaskEmailAction."""

    # PORT NOTE: C# property `From`; `from` is a Python keyword, so the
    # trailing-underscore form is used.
    from_: str | None = None
    to: str | None = None
    subject: str | None = None
    body: str | None = None
    header_fields: str | None = None
    attachments: list[str] = field(default_factory=list)
    server: str | None = None


@dataclass
class SchedTaskShowMessageAction(SchedTaskAction):
    """Port of LibSnaffle.ActiveDirectory.SchedTaskShowMessageAction."""

    title: str | None = None
    body: str | None = None


@dataclass
class TaskTrigger:
    """Port of LibSnaffle.ActiveDirectory.TaskTrigger."""

    type: str | None = None
    start_hour: int = 0
    start_minutes: int = 0
    begin_year: int = 0
    begin_month: int = 0
    has_end_date: bool = False
    repeat_task: bool = False
    interval: bool = False


@dataclass
class SchedTaskSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.SchedTaskSetting."""

    # Properties
    name: str | None = None
    type: str | None = None
    # PORT NOTE: C# `DateTime` defaults to DateTime.MinValue; unset is None here.
    changed: datetime | None = None

    task_type: SchedTaskType = SchedTaskType.Task
    setting_action: SettingAction = SettingAction.Update
    sched_task_action: str | None = None
    author: str | None = None
    principals: list[SchedTaskPrincipal] | None = None
    description1: str | None = None
    comment: str | None = None
    duration: str | None = None
    wait_timeout: str | None = None
    start_only_if_idle: bool = False
    stop_on_idle_end: bool = False
    restart_on_idle: bool = False
    multiple_instances_policy: str | None = None
    disallow_start_if_on_batteries: bool = False
    stop_if_going_on_batteries: bool = False
    system_required: bool = False
    allow_hard_terminate: bool = False
    allow_start_on_demand: bool = False
    enabled: bool = False
    hidden: bool = False
    execution_time_limit: str | None = None
    priority: int = 0

    actions: list[SchedTaskAction] | None = None
    # PORT NOTE: C# `XmlNodeList`; the parsers hand over a list of XML element
    # nodes (xml.etree.ElementTree.Element) instead.
    triggers: list[Any] | None = None
