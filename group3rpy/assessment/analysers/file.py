"""Port of Group3r/Assessment/Analysers/File.cs

PORT NOTE: `System.IO.Path` is Windows-flavoured in the original, so `ntpath` is
used instead of `os.path`, which would apply POSIX rules on a Linux host.

PORT NOTE: `(int)MinTriage < 4` is ported as `self.min_triage < 4` -- there is no
Triage member with ordinal 4, so the guard is always true in the original.
"""

import ntpath
from typing import List

from ...classifiers.constants import Triage
from ..finding import GpoFinding, SettingResult
from ..path_analyser import PathAnalyser
from .analyser import Analyser


class FileAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.FileAnalyser."""

    def __init__(self, setting=None):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of FileAnalyser.Analyse."""
        setting = self.setting
        findings: List[GpoFinding] = []

        path_analyser = PathAnalyser(assessment_options)

        # check if there's abusable file copy operations happening
        if setting.from_path and setting.target_path:
            from_path = setting.from_path

            # PORT NOTE: C# `fromPath.FirstOrDefault()` yields '\0' for an empty
            # string, and Char.IsLetter('\0') is false; `from_path[:1].isalpha()`
            # behaves the same way without indexing past the end.
            if from_path[:1].isalpha():
                # Mq.Trace("No point analysing a driveletter cos it's meaningless.");
                pass
            elif ntpath.isabs(from_path):
                path_result = path_analyser.analyse_path(from_path)

                if path_result is not None:
                    # if the path points to a file and we can write to it, that's a finding
                    if path_result.file_exists and path_result.file_writable:
                        if self.min_triage < 4:
                            findings.append(
                                GpoFinding(
                                    path_findings=[path_result],
                                    finding_reason="Writable file identified at "
                                    + path_result.assessed_path
                                    + " to be copied to "
                                    + setting.target_path,
                                    finding_detail="This GPO setting will copy a file from point A to point B. If it's a config file you might be able to modify how an app executes. If it's a script you might be able to modify it before it runs as someone else, if it's an Office doc that supports macros... you get the idea.",
                                    triage=Triage.Red,
                                )
                            )
                    # if the path points to a dir and we can write to it, that's a lesser finding
                    if path_result.directory_exists and path_result.directory_writable:
                        if self.min_triage < Triage.Red:
                            findings.append(
                                GpoFinding(
                                    path_findings=[path_result],
                                    finding_reason="Honestly this looks like a misconfigured GPP File GPO setting, or a bug in Group3r.",
                                    finding_detail="This setting type should be for moving a file, it should never point at a dir.",
                                    triage=Triage.Green,
                                )
                            )
                    # if the path points to a dir or a file that doesn't exist, but a parent directory does, and we can write to that, that's a finding
                    if (
                        path_result.parent_directory_exists
                        and path_result.parent_directory_writable
                    ):
                        if self.min_triage < Triage.Black:
                            findings.append(
                                GpoFinding(
                                    path_findings=[path_result],
                                    finding_reason="A GPP File GPO setting is missing its source file, and it has a writable parent dir identified at "
                                    + path_result.parent_directory_exists
                                    + ". The original target path was "
                                    + path_result.assessed_path
                                    + ". Depending on the file type you might be able to do something fun?",
                                    finding_detail="Recreate the missing parts of the path in the parent dir, put bad guy stuff in the file, cross your fingers.",
                                    triage=Triage.Yellow,
                                )
                            )
                    # if the path points to a dir or a file that exist and snaffler deems them interesting, that's a finding on its own, regardless of whether they're modifiable
                    if len(path_result.snaff_dir_results) > 0:
                        for dr in path_result.snaff_dir_results:
                            if dr.matched_rule is not None:
                                if self.min_triage <= dr.triage:
                                    findings.append(
                                        GpoFinding(
                                            path_findings=[path_result],
                                            finding_reason="The Snaffler engine deemed this directory path interesting on its own.",
                                            finding_detail="Matched Path: "
                                            + dr.dir_path
                                            + " Matched Rule: "
                                            + dr.matched_rule.rule_name,
                                            triage=dr.triage,
                                        )
                                    )
                    if len(path_result.snaff_file_results) > 0:
                        for fr in path_result.snaff_file_results:
                            if fr.matched_rule is not None:
                                if self.min_triage <= fr.triage:
                                    findings.append(
                                        GpoFinding(
                                            path_findings=[path_result],
                                            finding_reason="The Snaffler engine deemed this file path interesting on its own.",
                                            finding_detail="Matched Path: "
                                            + fr.file_path
                                            + " Matched Rule: "
                                            + fr.matched_rule.rule_name
                                            + " Match Context: "
                                            + fr.text_result.match_context,
                                            triage=fr.triage,
                                        )
                                    )

        if "NTFRS" in setting.source:
            setting.is_morphed = True

        # put findings in settingResult
        self.setting_result.findings = findings
        self.setting_result.setting = setting

        return self.setting_result
