"""Port of LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/Parsers/SchedTaskV2Parser.cs

Parses the v2 (`TaskV2` / `ImmediateTaskV2`) Group Policy Preferences scheduled
task elements, where the real task definition is a nested `Task` element.

PORT NOTE: the XPath queries below are unprefixed, so in .NET they only match
elements in no namespace -- which is also exactly how ElementTree's `find`
behaves. GPP writes the inner `<Task>` tree without a namespace declaration, so
both match. If a `TaskV2` ever carried the task-scheduler default namespace,
`SelectSingleNode("Task/RegistrationInfo")` would return null in .NET and
`GetXmlValueSafe` would then throw a NullReferenceException on it; the Python
`find` returns None and `node.find(...)` raises AttributeError at the same point,
so the failure is equivalent and the caller logs it the same way.
"""

import xml.etree.ElementTree as ET
from typing import List, Optional

from ...settings import (
    SchedTaskAction,
    SchedTaskEmailAction,
    SchedTaskExecAction,
    SchedTaskPrincipal,
    SchedTaskSetting,
    SchedTaskShowMessageAction,
    SchedTaskType,
)
from ..dotnet_compat import try_parse_bool, try_parse_datetime, try_parse_int


class SchedTaskV2Parser:
    """Port of LibSnaffle.ActiveDirectory.SchedTaskV2Parser."""

    def get_xml_value_safe(self, node: ET.Element, x_path_query: str) -> Optional[str]:
        """Port of SchedTaskV2Parser.GetXmlValueSafe.

        `node` is dereferenced without a null check, as in the original, so a
        missing parent element raises here rather than yielding None.
        """
        selected_node = node.find(x_path_query)
        if selected_node is not None:
            # XmlNode.InnerText is the concatenated text of all descendants.
            return "".join(selected_node.itertext())
        else:
            return None

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
            # TODO put this in all the other settings parsers
            sts.changed = changed
        # detailed properties
        sts.setting_action = sts.parse_setting_action(st_prop_atts.get("action"))
        # Registration Info
        reg_info = st_properties.find("Task/RegistrationInfo")
        sts.author = self.get_xml_value_safe(reg_info, "Author")
        sts.description1 = self.get_xml_value_safe(reg_info, "Description")
        # Principals
        principals = st_properties.findall("Task/Principals/Principal")
        sts.principals = []
        for principal in principals:
            st_principal = SchedTaskPrincipal(
                id=principal.get("id"),
                user_id=self.get_xml_value_safe(principal, "UserId"),
                logon_type=self.get_xml_value_safe(principal, "LogonType"),
                run_level=self.get_xml_value_safe(principal, "RunLevel"),
                cpassword=self.get_xml_value_safe(principal, "Cpassword"),
            )
            sts.principals.append(st_principal)
        # Settings
        # Idle Settings

        sts.duration = self.get_xml_value_safe(
            st_properties, "Task/Settings/IdleSettings/Duration"
        )
        sts.wait_timeout = self.get_xml_value_safe(
            st_properties, "Task/Settings/IdleSettings/WaitTimeout"
        )

        parsed, stop_on_idle_end = try_parse_bool(
            self.get_xml_value_safe(
                st_properties, "Task/Settings/IdleSettings/StopOnIdleEnd"
            )
        )
        if parsed:
            sts.stop_on_idle_end = stop_on_idle_end

        parsed, restart_on_idle = try_parse_bool(
            self.get_xml_value_safe(
                st_properties, "Task/Settings/IdleSettings/RestartOnIdle"
            )
        )
        if parsed:
            sts.restart_on_idle = restart_on_idle

        sts.multiple_instances_policy = self.get_xml_value_safe(
            st_properties, "Task/Settings/MultipleInstancesPolicy"
        )
        parsed, no_if_batt = try_parse_bool(
            self.get_xml_value_safe(
                st_properties, "Task/Settings/DisallowStartIfOnBatteries"
            )
        )
        if parsed:
            sts.disallow_start_if_on_batteries = no_if_batt

        parsed, stop_go_batt = try_parse_bool(
            self.get_xml_value_safe(
                st_properties, "Task/Settings/StopIfGoingOnBatteries"
            )
        )
        if parsed:
            sts.stop_if_going_on_batteries = stop_go_batt

        parsed, allow_hard_terminate = try_parse_bool(
            self.get_xml_value_safe(st_properties, "Task/Settings/AllowHardTerminate")
        )
        if parsed:
            sts.allow_hard_terminate = allow_hard_terminate

        parsed, allow_start_on_demand = try_parse_bool(
            self.get_xml_value_safe(st_properties, "Task/Settings/AllowStartOnDemand")
        )
        if parsed:
            sts.allow_start_on_demand = allow_start_on_demand

        parsed, enabled = try_parse_bool(
            self.get_xml_value_safe(st_properties, "Task/Settings/Enabled")
        )
        if parsed:
            sts.enabled = enabled

        parsed, hidden = try_parse_bool(
            self.get_xml_value_safe(st_properties, "Task/Settings/Hidden")
        )
        if parsed:
            sts.hidden = hidden

        sts.execution_time_limit = self.get_xml_value_safe(
            st_properties, "Task/Settings/ExecutionTimeLimit"
        )

        parsed, priority = try_parse_int(
            self.get_xml_value_safe(st_properties, "Task/Settings/Priority")
        )
        if parsed:
            sts.priority = priority

        sts.triggers = st_properties.findall("Task/Triggers/*")

        # V2 can have multiple actions
        st_actions: List[SchedTaskAction] = []
        message_actions = st_properties.findall("Task/Actions/ShowMessage")
        for message_action in message_actions:
            message_action_setting = SchedTaskShowMessageAction(
                title=self.get_xml_value_safe(message_action, "Title"),
                body=self.get_xml_value_safe(message_action, "Body"),
            )
            st_actions.append(message_action_setting)

        exec_actions = st_properties.findall("Task/Actions/Exec")
        for exec_action in exec_actions:
            exec_action_setting = SchedTaskExecAction(
                command=self.get_xml_value_safe(exec_action, "Command"),
                args=self.get_xml_value_safe(exec_action, "Arguments"),
                working_dir=self.get_xml_value_safe(exec_action, "WorkingDirectory"),
            )
            st_actions.append(exec_action_setting)

        email_actions = st_properties.findall("Task/Actions/SendEmail")
        for email_action in email_actions:
            email_action_setting = SchedTaskEmailAction(
                from_=self.get_xml_value_safe(email_action, "From"),
                to=self.get_xml_value_safe(email_action, "To"),
                subject=self.get_xml_value_safe(email_action, "Subject"),
                body=self.get_xml_value_safe(email_action, "Body"),
                header_fields=self.get_xml_value_safe(email_action, "HeaderFields"),
            )
            xml_attachments = email_action.findall("Attachments/*")
            if len(xml_attachments) >= 1:
                email_action_setting.attachments = []

                for node in xml_attachments:
                    email_action_setting.attachments.append(
                        "".join(node.itertext())
                    )

            email_action_setting.server = self.get_xml_value_safe(email_action, "Server")
            st_actions.append(email_action_setting)
        sts.actions = st_actions

        # comment
        sts.comment = st_prop_atts.get("comment")

        parsed, system_required = try_parse_bool(st_prop_atts.get("systemRequired"))
        if parsed:
            sts.system_required = system_required

        return sts
