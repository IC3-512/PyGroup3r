"""Port of LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/InfGpoFile.cs

Represents an .inf file found within a GPO directory (GptTmpl.inf).

PORT NOTE: the C# catches `UserException` around SID resolution, but the throw in
`Trustee`'s constructor is commented out upstream, so those handlers are dead
code in the original too. `UserException` (LibSnaffle/Errors/UserException.cs)
has no Python home yet, so it is declared here to keep the branch intact.

PORT NOTE: `new Trustee(sid, isSid)` calls LookupAccountSid on the local Windows
host. The Python `Trustee.from_input` takes an optional resolver for that; the
GPO file parsers have no handle on an LDAP/LSAT connection, so they call it
without one, which falls through to the well-known-SID table exactly as the
original does on a non-domain-joined host.
"""

import re
from typing import Dict, List

from ..ad.trustee import Trustee
from ..settings import (
    EventAuditSetting,
    FileSecuritySetting,
    GroupSetting,
    GroupSettingMember,
    KerbPolicySetting,
    NtServiceSetting,
    PrivRightSetting,
    RegistrySetting,
    RegistryValue,
    RegKeyValType,
    SettingAction,
    SystemAccessSetting,
)
from .dotnet_compat import enum_cast, try_parse_int
from .gpo_file import GpoFile


class UserException(Exception):
    """Port of LibSnaffle.Errors.UserException."""


def _sddl_parser():
    """Returns (Sddl, SecurableObjectType).

    PORT NOTE: imported on use rather than at module scope, so this module loads
    cleanly regardless of the Sddl parser's own import graph, and so a failure to
    load it lands inside the same try/except that a `new Sddl.Parser.Sddl(...)`
    throw would land in.
    """
    from ..sddl.securable_object_type import SecurableObjectType
    from ..sddl.sddl import Sddl

    return Sddl, SecurableObjectType


class InfGpoFile(GpoFile):
    """Port of LibSnaffle.ActiveDirectory.InfGpoFile."""

    def parse(self) -> None:
        self.get_settings()

    def get_settings(self) -> None:
        # define what a heading looks like
        heading_regex = re.compile(r"^\[(\w+\s?)+\]$")

        inf_content_array = self.get_content_lines()

        inf_content_string = self.get_content_string(inf_content_array)

        if not inf_content_string.strip():
            return

        heading_lines: List[int] = []

        # find all the lines that look like a heading and put the line numbers in an array.
        i = 0
        for inf_line in inf_content_array:
            heading_match = heading_regex.match(inf_line)
            if heading_match:
                heading_lines.append(i)
            i += 1
        # make a dictionary with K/V = start/end of each section
        # this is extraordinarily janky but it works mostly.
        section_slices: Dict[int, int] = {}
        idx = 0
        while True:
            try:
                section_heading_line = heading_lines[idx]
                section_final_line = heading_lines[idx + 1] - 1
                section_slices[section_heading_line] = section_final_line
                idx += 1
            except IndexError:
                # Reproduces catch (ArgumentOutOfRangeException); with no headings
                # at all this indexer throws again and escapes GetSettings.
                section_heading_line = heading_lines[idx]
                section_final_line = len(inf_content_array) - 1
                section_slices[section_heading_line] = section_final_line
                break

        # iterate over the identified sections and get the heading and contents of each.
        for slice_key, slice_value in section_slices.items():
            try:
                # get the section heading
                square_brackets = "[]"
                section_slice_key = inf_content_array[slice_key]
                section_heading = section_slice_key.strip(square_brackets)
                # get the line where the section content starts by adding one to the heading's line
                first_line_of_section = slice_key + 1
                # get the first line of the next section
                last_line_of_section = slice_value
                # subtract one from the other to get the section length, without the heading.
                section_length = last_line_of_section - first_line_of_section + 1
                # get an array segment with the lines
                section_offset = first_line_of_section
                section_count = section_length

                # iterate over the lines in the section
                for b in range(section_offset, section_offset + section_count):
                    line = inf_content_array[b]
                    if line.strip() == "":
                        break
                    # split the line into the key (before the =) and the values (after it)
                    line_key = ""
                    split_line = None
                    split_values = None
                    line_values = None

                    if "=" in line:
                        split_line = line.split("=")
                        line_key = split_line[0].strip()
                        line_key = line_key.strip("\\\"")
                        # then get the values
                        line_values = split_line[1].strip()
                        # and split them into an array on ","
                        split_values = line_values.split(",")
                    else:
                        split_line = line.split(",")
                        line_key = split_line[0].strip()

                    if section_heading == "Privilege Rights":
                        priv_right_setting = PrivRightSetting(
                            source=self.file_path,
                            privilege=line_key,
                        )
                        for trustee_sid in split_values:
                            if not trustee_sid.strip():
                                continue
                            sid_string = trustee_sid.strip("*")
                            if sid_string.startswith("S-"):
                                priv_right_setting.trustees.append(
                                    Trustee.from_input(sid_string, True)
                                )
                            else:
                                priv_right_setting.trustees.append(
                                    Trustee.from_input(sid_string, False)
                                )

                        if len(priv_right_setting.trustees) >= 1:
                            self.settings.append(priv_right_setting)
                    elif section_heading == "Registry Values":
                        reg_val_setting = RegistrySetting(source=self.file_path)
                        # turn the key into properties on the setting obj
                        reg_path_array = line_key.split("\\")
                        # get the hive
                        reg_val_setting.reg_hive_from_string(reg_path_array[0])
                        # get the key
                        key_array = reg_path_array[1 : len(reg_path_array) - 1]
                        reg_val_setting.key = "\\".join(key_array)

                        # figure out the value type
                        parsed, val_type = try_parse_int(split_values[0])
                        if parsed:
                            # create value objects for each of them
                            for value in split_values[1:]:
                                reg_val = RegistryValue(
                                    value_name=reg_path_array[len(reg_path_array) - 1]
                                )
                                reg_val.reg_key_val_type = enum_cast(
                                    RegKeyValType, val_type
                                )
                                reg_val.value_bytes = value.encode("utf-16-le")
                                reg_val.value_string = value
                                # add them to the setting
                                reg_val_setting.values.append(reg_val)

                        # add the setting into settings
                        self.settings.append(reg_val_setting)
                    elif section_heading == "Registry Keys":
                        reg_key_setting = RegistrySetting(source=self.file_path)
                        reg_key_array = line_key.split("\\")
                        # get the hive
                        reg_key_setting.reg_hive_from_string(reg_key_array[0].strip("\""))
                        # get the key
                        reg_key_setting.key = "\\".join(reg_key_array[1:]).strip("\"")
                        reg_key_setting.inheritance = split_line[1]
                        if split_line[2].strip("\"").strip():
                            reg_key_setting.key_sddl_string = split_line[2].strip("\"")
                            # these don't have values, they're just changing acls on keys.
                            Sddl, SecurableObjectType = _sddl_parser()
                            reg_key_setting.parsed_key_sddl = Sddl(
                                reg_key_setting.key_sddl_string,
                                SecurableObjectType.RegistryKey,
                            )

                        self.settings.append(reg_key_setting)
                    elif section_heading == "Kerberos Policy":
                        kerbpol_setting = KerbPolicySetting(
                            source=self.file_path,
                            key=split_line[0].strip(),
                            value=split_line[1].strip(),
                        )
                        self.settings.append(kerbpol_setting)
                    elif section_heading == "Event Audit":
                        event_audit_setting = EventAuditSetting(
                            source=self.file_path,
                            audit_type=line_key,
                        )
                        parsed, audit_level = try_parse_int(line_values[0])
                        if parsed:
                            event_audit_setting.audit_level = audit_level
                        # NB: as in the original, the setting is never added to
                        # Settings, so Event Audit entries are silently dropped.
                    elif section_heading == "File Security ":
                        file_sec_setting = FileSecuritySetting(
                            source=self.file_path,
                            file_sec_path=split_line[0].strip(),
                            sddl=split_line[1].strip(),
                        )
                        Sddl, SecurableObjectType = _sddl_parser()
                        file_sec_setting.parsed_sddl = Sddl(
                            file_sec_setting.sddl, SecurableObjectType.File
                        )
                        self.settings.append(file_sec_setting)
                    elif section_heading == "Group Membership":
                        if line_key.endswith("Memberof"):
                            member = line_key.split("_")[0].strip("*")
                            groups = split_values

                            # set up the sole member that is gonna go in all of the groupsettings
                            group_setting_member = GroupSettingMember()
                            if member.startswith("S-"):
                                group_setting_member.sid = member
                                try:
                                    trustee = Trustee.from_input(member)
                                    group_setting_member.name = trustee.display_name
                                except UserException as e:
                                    group_setting_member.name = "SID Resolution Failed"
                            else:
                                group_setting_member.name = member

                            for group in groups:
                                if group == "":
                                    continue
                                else:
                                    try:
                                        if group.startswith("S-"):
                                            trustee = Trustee.from_input(
                                                group.strip("*"), True
                                            )
                                            group_display_name = trustee.display_name
                                        else:
                                            trustee = Trustee.from_input(
                                                group.strip("*"), False
                                            )
                                            group_display_name = trustee.display_name
                                    except UserException as e:
                                        trustee = Trustee.from_input(
                                            group.strip("*"), False
                                        )
                                        group_display_name = group.strip("*")

                                    group_setting = GroupSetting(
                                        action=SettingAction.Update
                                    )
                                    group_setting.name = group_display_name
                                    group_setting.source = self.file_path
                                    group_setting.members.append(group_setting_member)
                                    self.settings.append(group_setting)
                        elif line_key.endswith("Members"):
                            group = line_key.split("_")[0].strip("*")
                            members = split_values

                            group_setting = GroupSetting(action=SettingAction.Update)

                            if group.startswith("S-"):
                                try:
                                    trustee = Trustee.from_input(group)
                                    group_setting.name = trustee.display_name
                                except UserException as e:
                                    group_setting.name = group
                            else:
                                group_setting.name = group

                            for member in members:
                                if member == "":
                                    continue

                                group_setting_member = GroupSettingMember()
                                trimmed_member = member.strip("*")
                                if trimmed_member.startswith("S-"):
                                    group_setting_member.sid = trimmed_member
                                    try:
                                        trustee = Trustee.from_input(trimmed_member)
                                        group_setting_member.name = trustee.display_name
                                    except UserException as e:
                                        group_setting_member.name = "SID Resolution Failed"
                                else:
                                    group_setting_member.name = trimmed_member

                                group_setting.members.append(group_setting_member)

                            if len(group_setting.members) >= 1:
                                group_setting.source = self.file_path
                                self.settings.append(group_setting)
                        else:
                            self._error(
                                "Unexpected result in Group Membership in inf file "
                                + self.file_path
                            )
                    elif section_heading == "Service General Setting":
                        service_setting = NtServiceSetting(
                            source=self.file_path,
                            service_name=line_key,
                            startup_type=split_line[1],
                        )
                        if split_line[2].strip("\"").strip():
                            service_setting.sddl = split_line[2].strip("\"")
                            # these don't have values, they're just changing acls on keys.
                            Sddl, SecurableObjectType = _sddl_parser()
                            service_setting.parsed_sddl = Sddl(
                                service_setting.sddl, SecurableObjectType.WindowsService
                            )

                        self.settings.append(service_setting)
                    elif section_heading == "System Access":
                        sys_acc_setting = SystemAccessSetting(
                            source=self.file_path,
                            setting_name=line_key,
                            value_string=split_line[1].strip(),
                        )
                        self.settings.append(sys_acc_setting)
                    elif section_heading == "Unicode":
                        # don't care about this but it's expected
                        pass
                    elif section_heading == "Version":
                        # don't care about this but it's expected
                        pass
                    # elif section_heading == "System Log":
                    #     # don't care about this but it's expected
                    #     pass
                    # elif section_heading == "Application Log":
                    #     # don't care about this but it's expected
                    #     pass
                    # elif section_heading == "Security Log":
                    #     # don't care about this but it's expected
                    #     pass
                    # elif section_heading == "Profile Description":
                    #     # don't care about this but it's expected
                    #     pass
                    else:
                        self._degub(
                            "Something unexpected or unhandled in an Inf file: "
                            + section_heading
                        )

                    if line_key == "":
                        self._error(
                            "Something has gone wrong parsing .inf file " + self.file_path
                        )
            except Exception:
                self._error("Something has gone wrong parsing " + self.file_path)
