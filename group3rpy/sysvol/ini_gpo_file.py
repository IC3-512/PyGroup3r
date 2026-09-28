"""Port of LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/IniGpoFile.cs

Parses scripts.ini / psscripts.ini into ScriptSettings.

PORT NOTE: the original reads the file with `File.ReadAllLines(FilePath)`
directly rather than through `GetContentLines()`, so -- unlike the .inf parser --
it does *not* skip `;` comment lines. That difference is preserved.
"""

import os
import re
from typing import Dict, List

from ..ad.gpo import ScriptType
from ..settings import ScriptSetting
from .dotnet_compat import read_all_lines, try_parse_int
from .gpo_file import GpoFile


class IniGpoFile(GpoFile):
    """Port of LibSnaffle.ActiveDirectory.IniGpoFile."""

    def parse(self) -> None:
        self.get_settings()

    def get_settings(self) -> None:
        # define what a heading looks like
        heading_regex = re.compile(r"^\[(\w+\s?)+\]$")

        inf_content_array = read_all_lines(self.fs, self.file_path)

        inf_content_string = os.linesep.join(inf_content_array)

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
        fuck = 0
        while True:
            try:
                section_heading_line = heading_lines[fuck]
                section_final_line = heading_lines[fuck + 1] - 1
                section_slices[section_heading_line] = section_final_line
                fuck += 1
            except IndexError:
                # Reproduces catch (ArgumentOutOfRangeException); if there were no
                # headings at all this indexer throws again and the exception
                # escapes GetSettings, exactly as in the original.
                section_heading_line = heading_lines[fuck]
                section_final_line = len(inf_content_array) - 1
                section_slices[section_heading_line] = section_final_line
                break

        # iterate over the identified sections and get the heading and contents of each.
        for slice_key, slice_value in section_slices.items():
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

            # BE DEV DO CRIMES
            lines_dict: Dict[int, List[str]] = {}

            # iterate over the lines in the section;
            for b in range(section_offset, section_offset + section_count):
                # get the actual fucking line
                line = inf_content_array[b]
                # get the subsection index number off the front of the line
                # (indexing rather than slicing, so an empty line raises the way
                # String.Substring(0, 1) does)
                line_index_string = line[0]

                parsed, line_index = try_parse_int(line_index_string)
                if parsed:
                    if line_index in lines_dict.keys():
                        lines_dict[line_index].append(line[1:])
                    else:
                        lines_dict[line_index] = [line[1:]]
                elif line_index_string == "E" or line_index_string == "S":
                    self._trace(
                        "Ignore StartExecutePSFirst or EndExecutePSFirst configuration"
                    )
                else:
                    if self.logger is not None:
                        self.logger.error(
                            "Something went wrong with the scripts.ini parsing and the int casting and the GLAYVIN!"
                        )

            for subsection_key, subsection_value in lines_dict.items():
                script_setting = ScriptSetting()

                if section_heading == "Startup":
                    script_setting.script_type = ScriptType.Startup
                elif section_heading == "Shutdown":
                    script_setting.script_type = ScriptType.Shutdown
                elif section_heading == "Logon":
                    script_setting.script_type = ScriptType.Logon
                elif section_heading == "Logoff":
                    script_setting.script_type = ScriptType.Logoff
                else:
                    if self.logger is not None:
                        self.logger.error(
                            "There is a type of Scripts.Ini entry that I'm not handling properly. Fuck. "
                            + section_heading
                        )

                for line in subsection_value:
                    split_line = line.split("=")
                    if split_line[0] == "CmdLine":
                        script_setting.cmd_line = split_line[1]
                    elif split_line[0] == "Parameters":
                        script_setting.parameters = split_line[1]
                    else:
                        if self.logger is not None:
                            self.logger.error(
                                "I dunno what the hell a " + split_line[0] + " is but it scares me."
                            )
                script_setting.source = self.file_path
                self.settings.append(script_setting)
