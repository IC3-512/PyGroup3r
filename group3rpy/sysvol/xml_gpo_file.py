"""Port of LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/XmlGpoFile.cs

Represents an .inf file found within a GPO directory.
(The C# doc comment says .inf; the class actually handles the Group Policy
Preferences .xml files. Comment preserved as written.)

PORT NOTE (XML): `XmlDocument`/`XmlNode` become `xml.etree.ElementTree`.
  * `doc.Load(path)` becomes `ET.fromstring(bytes)`, which -- like XmlDocument --
    honours the encoding declared in the XML prolog and any BOM.
  * `node.SelectNodes("Foo")` becomes `node.findall("Foo")` and
    `node.SelectSingleNode("Foo")` becomes `node.find("Foo")`. Both XPath engines
    match unprefixed names only against elements in no namespace, so behaviour is
    identical for namespaced documents (neither matches).
  * `root.Name` becomes `root.tag`. For the unnamespaced GPP files this is the
    same string; a namespaced root would come through as `{uri}Local` here and as
    `Local` in .NET, but in both cases every `SelectNodes` below returns nothing,
    so no settings are produced either way.
  * `Attributes?["x"]?.Value` becomes `_attr(node, "x")`, which yields None for a
    missing attribute. Where the C# dereferences without a null check
    (`Attributes?["name"].Value`, `GetNamedItem("name").Value`, `x.Attributes`
    where x may be null) the port raises, as the original does, and the caller's
    `except` logs it.
"""

import xml.etree.ElementTree as ET
from typing import Optional

from ..settings import (
    DataSourceSetting,
    DeviceSetting,
    DriveSetting,
    EnvVarSetting,
    FileSetting,
    FolderSetting,
    GroupSetting,
    GroupSettingMember,
    IniFileSetting,
    NetOptionSetting,
    NetworkShareSetting,
    NtServiceSetting,
    PrinterSetting,
    RegHive,
    RegistrySetting,
    RegistryValue,
    RegKeyValType,
    SchedTaskType,
    ShortcutSetting,
    UserSetting,
)
from .dotnet_compat import enum_try_parse, try_parse_bool, try_parse_datetime
from .gpo_file import GpoFile
from .parsers.sched_task_parser import SchedTaskParser
from .parsers.sched_task_v2_parser import SchedTaskV2Parser


def _attributes(node: Optional[ET.Element]) -> ET.Element:
    """Stands in for `node.Attributes`, which throws when `node` is null."""
    if node is None:
        raise AttributeError
    return node


def _attr(node: Optional[ET.Element], name: str) -> Optional[str]:
    """Stands in for `Attributes?[name]?.Value`."""
    if node is None:
        return None
    return node.get(name)


def _attr_strict(node: Optional[ET.Element], name: str) -> Optional[str]:
    """Stands in for `Attributes?[name].Value` / `GetNamedItem(name).Value`.

    A missing attribute is a NullReferenceException in the original, so it raises
    here too instead of quietly producing None.
    """
    if node is None:
        return None
    value = node.get(name)
    if value is None:
        raise AttributeError
    return value


def _child_element(node: Optional[ET.Element], name: str) -> Optional[ET.Element]:
    """Stands in for the `node?[name]` element indexer."""
    if node is None:
        return None
    return node.find(name)


class XmlGpoFile(GpoFile):
    """Port of LibSnaffle.ActiveDirectory.XmlGpoFile."""

    def parse(self) -> None:
        self.get_settings()

    def content_xml(self) -> ET.Element:
        """Port of XmlGpoFile.ContentXML.

        Returns the document element rather than the document, since
        ElementTree has no separate document node.
        """
        return ET.fromstring(self.fs.read_file(self.file_path))

    def get_settings(self) -> None:
        try:
            # Load the document and set the root element.
            root = self.content_xml()

            name = root.tag
            if name == "Groups":
                group_node_list = root.findall("Group")
                for group in group_node_list:
                    group_setting = GroupSetting(source=self.file_path)
                    group_attributes = _attributes(group)
                    group_setting.name = _attr_strict(group_attributes, "name")
                    group_properties = group.find("Properties")
                    group_properties_attributes = _attributes(group_properties)
                    group_setting.new_name = _attr(group_properties_attributes, "newName")
                    group_setting.action = group_setting.parse_setting_action(
                        _attr(group_properties_attributes, "action")
                    )
                    parsed, thing = try_parse_bool(
                        _attr(group_properties_attributes, "deleteAllGroups")
                    )
                    if parsed:
                        group_setting.delete_all_groups = thing
                    parsed, thing2 = try_parse_bool(
                        _attr(group_properties_attributes, "deleteAllUsers")
                    )
                    if parsed:
                        group_setting.delete_all_users = thing2
                    parsed, thing3 = try_parse_bool(
                        _attr(group_properties_attributes, "removeAccounts")
                    )
                    if parsed:
                        group_setting.remove_accounts = thing3
                    group_setting.description = _attr(
                        group_properties_attributes, "description"
                    )
                    group_setting.group_sid = _attr(group_properties_attributes, "groupSid")
                    members_node = _child_element(group_properties, "Members")
                    group_members = None if members_node is None else list(members_node)
                    if group_members is not None:
                        for group_member in group_members:
                            group_member_attributes = group_member
                            group_setting_member = GroupSettingMember(
                                action=group_setting.parse_setting_action(
                                    _attr(group_member_attributes, "action")
                                ),
                                name=_attr(group_member_attributes, "name"),
                                sid=_attr(group_member_attributes, "sid"),
                            )
                            group_setting.members.append(group_setting_member)
                    self.settings.append(group_setting)

                user_node_list = root.findall("User")
                for user in user_node_list:
                    user_setting = UserSetting(source=self.file_path)
                    user_attributes = _attributes(user)
                    user_setting.name = _attr(user_attributes, "name")
                    user_properties = user.find("Properties")
                    user_properties_attributes = _attributes(user_properties)
                    user_setting.new_name = _attr(user_properties_attributes, "newName")
                    user_setting.action = user_setting.parse_setting_action(
                        _attr(user_properties_attributes, "action")
                    )
                    user_setting.full_name = _attr(user_properties_attributes, "fullName")
                    user_setting.cpassword = _attr(user_properties_attributes, "cpassword")
                    user_setting.password = user_setting.decrypt_cpassword(
                        user_setting.cpassword
                    )
                    user_setting.description = _attr(
                        user_properties_attributes, "description"
                    )
                    user_setting.user_name = _attr(user_properties_attributes, "userName")
                    parsed, thing4 = try_parse_bool(
                        _attr(user_properties_attributes, "acctDisabled")
                    )
                    if parsed:
                        user_setting.account_disabled = thing4
                    parsed, thing5 = try_parse_bool(
                        _attr(user_properties_attributes, "neverExpires")
                    )
                    if parsed:
                        user_setting.pw_never_expires = thing5
                    self.settings.append(user_setting)
                return
            elif name == "DataSources":
                ds_node_list = root.findall("DataSource")
                for ds in ds_node_list:
                    ds_setting = DataSourceSetting(source=self.file_path)
                    ds_attributes = _attributes(ds)
                    ds_properties = ds.find("Properties")
                    ds_prop_atts = _attributes(ds_properties)

                    ds_setting.name = _attr_strict(ds_attributes, "name")
                    ds_setting.action = ds_setting.parse_setting_action(
                        _attr(ds_prop_atts, "action")
                    )
                    ds_setting.dsn = _attr(ds_prop_atts, "dsn")
                    ds_setting.cpassword = _attr(ds_prop_atts, "cpassword")
                    ds_setting.password = ds_setting.decrypt_cpassword(ds_setting.cpassword)
                    ds_setting.description = _attr(ds_prop_atts, "description")
                    ds_setting.driver = _attr(ds_prop_atts, "driver")
                    ds_setting.user_name = _attr(ds_prop_atts, "username")
                    self.settings.append(ds_setting)

                return
            elif name == "Drives":
                drive_node_list = root.findall("Drive")
                for drive in drive_node_list:
                    drive_setting = DriveSetting(source=self.file_path)
                    drive_attributes = _attributes(drive)
                    drive_properties = drive.find("Properties")
                    drive_prop_atts = _attributes(drive_properties)
                    drive_setting.name = _attr_strict(drive_attributes, "name")
                    drive_setting.action = drive_setting.parse_setting_action(
                        _attr(drive_prop_atts, "action")
                    )
                    drive_setting.drive_letter = _attr(drive_prop_atts, "useLetter")
                    drive_setting.this_drive = _attr(drive_prop_atts, "thisDrive")
                    drive_setting.all_drives = _attr(drive_prop_atts, "allDrives")
                    drive_setting.user_name = _attr(drive_prop_atts, "userName")
                    drive_setting.cpassword = _attr(drive_prop_atts, "cpassword")
                    drive_setting.password = drive_setting.decrypt_cpassword(
                        drive_setting.cpassword
                    )
                    drive_setting.path = _attr(drive_prop_atts, "path")
                    drive_setting.label = _attr(drive_prop_atts, "label")
                    drive_setting.persistent = _attr(drive_prop_atts, "persistent")
                    drive_setting.letter = _attr(drive_prop_atts, "letter")
                    self.settings.append(drive_setting)
            elif name == "EnvironmentVariables":
                ev_node_list = root.findall("EnvironmentVariable")
                for ev in ev_node_list:
                    ev_setting = EnvVarSetting(source=self.file_path)
                    ev_attributes = _attributes(ev)
                    ev_properties = ev.find("Properties")
                    ev_prop_atts = _attributes(ev_properties)

                    ev_setting.name = _attr(ev_attributes, "name")
                    ev_setting.status = _attr(ev_attributes, "status")
                    ev_setting.action = ev_setting.parse_setting_action(
                        _attr(ev_prop_atts, "action")
                    )
                    self.settings.append(ev_setting)
            elif name == "Files":
                file_node_list = root.findall("File")
                for file in file_node_list:
                    file_setting = FileSetting(source=self.file_path)
                    file_attributes = _attributes(file)
                    file_properties = file.find("Properties")
                    file_prop_atts = _attributes(file_properties)
                    file_setting.file_name = _attr(file_attributes, "name")
                    file_setting.status = _attr(file_attributes, "status")
                    file_setting.action = file_setting.parse_setting_action(
                        _attr(file_prop_atts, "action")
                    )
                    file_setting.from_path = _attr(file_prop_atts, "fromPath")
                    file_setting.target_path = _attr(file_prop_atts, "targetPath")
                    self.settings.append(file_setting)
            elif name == "IniFiles":
                if_node_list = root.findall("Ini")
                for ini_file in if_node_list:
                    if_setting = IniFileSetting(source=self.file_path)
                    if_attributes = _attributes(ini_file)
                    if_properties = ini_file.find("Properties")
                    if_prop_atts = _attributes(if_properties)
                    if_setting.path = _attr(if_prop_atts, "path")
                    if_setting.section = _attr(if_prop_atts, "section")
                    if_setting.value = _attr(if_prop_atts, "value")
                    if_setting.property = _attr(if_prop_atts, "property")
                    # As in the original, the result is thrown away, so
                    # IniFileSetting.Action keeps its default.
                    if_setting.parse_setting_action(_attr(if_prop_atts, "action"))

                    self.settings.append(if_setting)
            elif name == "NetworkOptions":
                no_node_list = root.findall("NetworkOption")
                for no in no_node_list:
                    netoption_setting = NetOptionSetting(source=self.file_path)
                    no_attributes = _attributes(no)
                    no_properties = no.find("Properties")
                    no_prop_atts = _attributes(no_properties)

                    self.settings.append(netoption_setting)
                if self.logger is not None:
                    self.logger.degub(
                        "LibSnaffle doesn't properly parse NetworkOptions.xml files. "
                    )
            elif name == "NetworkShareSettings":
                ns_node_list = root.findall("NetworkShare")
                for ns in ns_node_list:
                    ns_setting = NetworkShareSetting(source=self.file_path)
                    ns_attributes = _attributes(ns)
                    ns_properties = ns.find("Properties")
                    ns_prop_atts = _attributes(ns_properties)

                    ns_setting.name = _attr(ns_attributes, "name")
                    ns_setting.action = ns_setting.parse_setting_action(
                        _attr(ns_prop_atts, "action")
                    )
                    ns_setting.comment = _attr(ns_prop_atts, "comment")
                    ns_setting.path = _attr(ns_prop_atts, "path")
                    ns_setting.all_regular = _attr(ns_prop_atts, "allRegular")
                    ns_setting.all_hidden = _attr(ns_prop_atts, "allHidden")
                    ns_setting.all_admin_drive = _attr(ns_prop_atts, "allAdminDrive")
                    ns_setting.limit_users = _attr(ns_prop_atts, "limitUsers")
                    ns_setting.abe = _attr(ns_prop_atts, "abe")
                    self.settings.append(ns_setting)
            elif name == "NTServices":
                service_node_list = root.findall("NTService")
                for service in service_node_list:
                    service_setting = NtServiceSetting(source=self.file_path)
                    service_attributes = _attributes(service)
                    service_properties = service.find("Properties")
                    service_prop_atts = _attributes(service_properties)

                    service_setting.name = _attr(service_attributes, "name")
                    service_setting.service_name = _attr(service_prop_atts, "serviceName")
                    service_setting.service_action = _attr(
                        service_prop_atts, "serviceAction"
                    )
                    service_setting.timeout = _attr(service_prop_atts, "timeout")
                    service_setting.program = _attr(service_prop_atts, "program")
                    service_setting.args = _attr(service_prop_atts, "arguments")
                    service_setting.startup_type = _attr(service_prop_atts, "startupType")
                    service_setting.account_name = _attr(service_prop_atts, "accountName")
                    service_setting.user_name = _attr(service_prop_atts, "userName")
                    service_setting.cpassword = _attr(service_prop_atts, "cpassword")
                    service_setting.password = service_setting.decrypt_cpassword(
                        service_setting.cpassword
                    )
                    service_setting.action_on_first_failure = _attr(
                        service_prop_atts, "firstFailure"
                    )
                    service_setting.reset_fail_count_delay = _attr(
                        service_prop_atts, "resetFailCountDelay"
                    )
                    service_setting.append = _attr(service_prop_atts, "append")
                    service_setting.interact = _attr(service_prop_atts, "interact")
                    self.settings.append(service_setting)
            elif name == "Printers":
                printer_node_list = root.findall("SharedPrinter")
                for printer in printer_node_list:
                    printer_setting = PrinterSetting(source=self.file_path)
                    printer_attributes = _attributes(printer)
                    printer_properties = printer.find("Properties")
                    printer_prop_atts = _attributes(printer_properties)
                    printer_setting.name = _attr(printer_attributes, "name")
                    printer_setting.user_name = _attr(printer_prop_atts, "userName")
                    printer_setting.cpassword = _attr(printer_prop_atts, "cpassword")
                    printer_setting.password = printer_setting.decrypt_cpassword(
                        printer_setting.cpassword
                    )
                    printer_setting.action = printer_setting.parse_setting_action(
                        _attr(printer_prop_atts, "action")
                    )
                    printer_setting.path = _attr(printer_prop_atts, "path")
                    printer_setting.port = _attr(printer_prop_atts, "port")
                    printer_setting.comment = _attr(printer_prop_atts, "comment")
                    self.settings.append(printer_setting)
            elif name == "ScheduledTasks":
                sched_task_node_list = root.findall("Task")
                sched_task_v2_node_list = root.findall("TaskV2")
                immediate_task_node_list = root.findall("ImmediateTask")
                immediate_task_v2_node_list = root.findall("ImmediateTaskV2")
                st_parser = SchedTaskParser()
                stv2_parser = SchedTaskV2Parser()
                for sched_task in sched_task_node_list:
                    sts = st_parser.parse_sched_task(SchedTaskType.Task, sched_task)
                    sts.source = self.file_path
                    self.settings.append(sts)
                for sched_task in sched_task_v2_node_list:
                    sts = stv2_parser.parse_sched_task(SchedTaskType.TaskV2, sched_task)
                    sts.source = self.file_path
                    self.settings.append(sts)
                for sched_task in immediate_task_node_list:
                    sts = st_parser.parse_sched_task(
                        SchedTaskType.ImmediateTask, sched_task
                    )
                    sts.source = self.file_path
                    self.settings.append(sts)
                for sched_task in immediate_task_v2_node_list:
                    sts = stv2_parser.parse_sched_task(
                        SchedTaskType.ImmediateTaskV2, sched_task
                    )
                    sts.source = self.file_path
                    self.settings.append(sts)
            elif name == "Shortcuts":
                shortcut_node_list = root.findall("Shortcut")
                for shortcut in shortcut_node_list:
                    shortcut_setting = ShortcutSetting(source=self.file_path)
                    shortcut_attributes = _attributes(shortcut)
                    shortcut_properties = shortcut.find("Properties")
                    shortcut_prop_atts = _attributes(shortcut_properties)

                    shortcut_setting.name = _attr(shortcut_attributes, "name")
                    shortcut_setting.status = _attr(shortcut_attributes, "status")
                    shortcut_setting.target_type = _attr(shortcut_prop_atts, "targetType")
                    shortcut_setting.target_path = _attr(shortcut_prop_atts, "targetPath")
                    shortcut_setting.arguments = _attr(shortcut_attributes, "arguments")
                    shortcut_setting.comment = _attr(shortcut_prop_atts, "comment")
                    shortcut_setting.shortcut_path = _attr(
                        shortcut_prop_atts, "shortcutPath"
                    )
                    shortcut_setting.icon_path = _attr(shortcut_prop_atts, "iconPath")
                    shortcut_setting.icon_index = _attr(shortcut_prop_atts, "iconIndex")
                    shortcut_setting.start_in = _attr(shortcut_prop_atts, "startIn")
                    shortcut_setting.action = shortcut_setting.parse_setting_action(
                        _attr(shortcut_prop_atts, "action")
                    )
                    self.settings.append(shortcut_setting)
            elif name == "RegistrySettings":

                rs_node_list = list(root.iter("Registry"))

                for rs_node in rs_node_list:
                    rs = RegistrySetting(source=self.file_path)
                    rs_attributes = _attributes(rs_node)
                    rs_properties = rs_node.find("Properties")
                    rs_prop_atts = _attributes(rs_properties)

                    # stuff about the setting
                    rs.name = _attr(rs_attributes, "name")
                    rs.status = _attr(rs_attributes, "status")
                    parsed, changed = try_parse_datetime(_attr(rs_attributes, "changed"))
                    if parsed:
                        rs.changed = changed
                    # stuff about the key
                    rs.action = rs.parse_setting_action(_attr(rs_prop_atts, "action"))
                    rs.display_decimal = _attr(rs_attributes, "displayDecimal")
                    rs.default = _attr(rs_prop_atts, "default")
                    # default to hklm and then try to parse the real value
                    hive_string = _attr(rs_prop_atts, "hive")
                    reg_hive = RegHive.HKEY_LOCAL_MACHINE
                    reg_hive = enum_try_parse(RegHive, hive_string)
                    rs.hive = reg_hive
                    rs.key = _attr(rs_prop_atts, "key")

                    # stuff about the value. make a value and put stuff in it.
                    reg_val = RegistryValue(value_name=_attr(rs_prop_atts, "name"))
                    # make a val type to parse into
                    val_type = RegKeyValType.REG_NONE
                    # try to parse it
                    val_type = enum_try_parse(RegKeyValType, _attr(rs_prop_atts, "type"))
                    reg_val.reg_key_val_type = val_type
                    # get the actual value
                    reg_val.value_bytes = _attr(rs_prop_atts, "value").encode("utf-16-le")
                    reg_val.value_string = _attr(rs_prop_atts, "value")
                    rs.values.append(reg_val)
                    self.settings.append(rs)
            elif name == "Devices":
                devices_node_list = root.findall("Device")
                for device in devices_node_list:
                    device_setting = DeviceSetting(source=self.file_path)
                    device_attributes = _attributes(device)
                    device_properties = device.find("Properties")
                    device_prop_atts = _attributes(device_properties)
                    device_setting.name = _attr(device_attributes, "name")
                    device_setting.device_class = _attr(device_prop_atts, "deviceClass")
                    device_setting.device_action = _attr(device_prop_atts, "deviceAction")
                    device_setting.device_class_guid = _attr(
                        device_prop_atts, "deviceClassGUID"
                    )
                    device_setting.device_type = _attr(device_prop_atts, "deviceType")
                    device_setting.device_type_id = _attr(device_prop_atts, "deviceTypeID")
                    self.settings.append(device_setting)
            elif name == "Folders":
                folder_node_list = root.findall("Folder")
                for folder in folder_node_list:
                    folder_setting = FolderSetting(source=self.file_path)
                    folder_attributes = _attributes(folder)
                    folder_properties = folder.find("Properties")
                    folder_prop_atts = _attributes(folder_properties)
                    folder_setting.name = _attr(folder_attributes, "name")
                    folder_setting.status = _attr(folder_attributes, "status")
                    folder_setting.action = folder_setting.parse_setting_action(
                        _attr(folder_prop_atts, "action")
                    )
                    folder_setting.path = _attr(folder_prop_atts, "path")
                    self.settings.append(folder_setting)
            elif name == "InternetSettings":
                # As in the original, this looks for InternetSettings elements
                # *below* the InternetSettings root, so the loop body never runs.
                inet_node_list = root.findall("InternetSettings")
                for inet in inet_node_list:
                    self.logger.degub(
                        "LibSnaffle still doesn't parse InternetSettings xml."
                    )
            else:
                if self.logger is not None:
                    self.logger.degub(
                        root.tag
                        + " didn't seem to have a handler in the XmlParser switch case thing."
                    )
                return
        except Exception as e:
            if self.logger is not None:
                self.logger.error(str(e))
