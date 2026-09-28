"""Port of LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/Parsers/SchedTaskParser.cs

Parses the v1 (`Task` / `ImmediateTask`) Group Policy Preferences scheduled task
elements, where everything lives in attributes on `Properties`.
"""

import xml.etree.ElementTree as ET

from ...settings import (
    SchedTaskExecAction,
    SchedTaskPrincipal,
    SchedTaskSetting,
    SchedTaskType,
)
from ..dotnet_compat import try_parse_bool, try_parse_datetime


class SchedTaskParser:
    """Port of LibSnaffle.ActiveDirectory.SchedTaskParser."""

    # TODO - STILL NOT FINISHED

    def parse_sched_task(
        self, task_type: SchedTaskType, sched_task: ET.Element
    ) -> SchedTaskSetting:
        sts = SchedTaskSetting(task_type=task_type)
        st_attributes = sched_task
        st_properties = sched_task.find("Properties")
        # `stProperties.Attributes` throws when Properties is missing, as here.
        if st_properties is None:
            raise AttributeError
        st_prop_atts = st_properties

        # basic atts
        sts.name = st_attributes.get("name")
        parsed, changed = try_parse_datetime(st_attributes.get("changed"))
        if parsed:
            sts.changed = changed
        # detailed properties
        # these older v1 ones are single action
        sts.setting_action = sts.parse_setting_action(st_prop_atts.get("action"))
        st_action = SchedTaskExecAction(
            command=st_prop_atts.get("appName"),
            args=st_prop_atts.get("args"),
            working_dir=st_prop_atts.get("startIn"),
        )
        sts_actions = [st_action]
        sts.actions = sts_actions
        sts.comment = st_prop_atts.get("comment")

        parsed, no_if_batt = try_parse_bool(st_prop_atts.get("noStartIfOnBatteries"))
        if parsed:
            sts.disallow_start_if_on_batteries = no_if_batt

        parsed, start_if_idle = try_parse_bool(st_prop_atts.get("startOnlyIfIdle"))
        if parsed:
            sts.start_only_if_idle = start_if_idle

        parsed, stop_on_idle_end = try_parse_bool(st_prop_atts.get("stopOnIdleEnd"))
        if parsed:
            sts.stop_on_idle_end = stop_on_idle_end

        parsed, stop_go_batt = try_parse_bool(st_prop_atts.get("stopIfGoingOnBatteries"))
        if parsed:
            sts.stop_if_going_on_batteries = stop_go_batt

        parsed, system_required = try_parse_bool(st_prop_atts.get("systemRequired"))
        if parsed:
            sts.system_required = system_required

        # runas details
        sts.principals = []
        st_principal = SchedTaskPrincipal(
            user_id=st_prop_atts.get("runAs"),
            logon_type=st_prop_atts.get("logonType"),
            cpassword=st_prop_atts.get("cpassword"),
        )
        sts.principals.append(st_principal)
        parsed, enabled = try_parse_bool(st_prop_atts.get("enabled"))
        if parsed:
            sts.enabled = enabled
        # triggers
        sts.triggers = st_properties.findall("Triggers/Trigger")
        return sts
