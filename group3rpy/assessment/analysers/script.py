"""Port of Group3r/Assessment/Analysers/Script.cs

PORT NOTE: `System.IO.Path` is Windows-flavoured in the original (backslash
separators, UNC awareness), so `ntpath` is used here rather than `os.path`, which
would apply POSIX rules on a Linux host. `ntpath.isabs` differs from
`Path.IsPathRooted` only for drive-relative paths like "C:script.bat", which do
not occur in GPO script settings.

PORT NOTE: `(int)MinTriage < 4` is ported as `self.min_triage < 4` -- there is no
Triage member with ordinal 4, so that guard is always true in the original.
"""

import ntpath
from typing import List

from ...classifiers.constants import Triage
from ..finding import GpoFinding, SettingResult
from ..path_analyser import PathAnalyser
from .analyser import Analyser


class ScriptAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.ScriptAnalyser."""

    def __init__(self, setting=None):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of ScriptAnalyser.Analyse."""
        setting = self.setting
        findings: List[GpoFinding] = []

        # if the script is being run with args that look like creds, that's a finding.
        if setting.parameters is not None and setting.parameters.strip():
            if (
                "pass" in setting.parameters.lower()
                or "pw" in setting.parameters.lower()
                or "cred" in setting.parameters.lower()
                or "-p" in setting.parameters.lower()
                or "/p" in setting.parameters.lower()
            ):
                if self.min_triage < Triage.Black:
                    findings.append(
                        GpoFinding(
                            finding_reason=setting.script_type.name
                            + " script has an arguments setting that looks like it might have a password in it?",
                            finding_detail="Arguments were: " + setting.parameters,
                            triage=Triage.Yellow,
                        )
                    )

        path_analyser = PathAnalyser(assessment_options)

        path = setting.cmd_line

        if not ntpath.isabs(path):
            # if it's not, we need to construct the full path from the GPO path etc.

            base_gpo_path = ntpath.dirname(setting.source)
            adjusted_path = ntpath.join(base_gpo_path, setting.script_type.name)
            path = ntpath.join(adjusted_path, setting.cmd_line)

        path_result = path_analyser.analyse_path(path)

        if path_result is not None and path_result.assessed_path.startswith("\\\\"):
            # if the path points to a file and we can write to it, that's a finding
            if path_result.file_exists and path_result.file_writable:
                findings.append(
                    GpoFinding(
                        path_findings=[path_result],
                        finding_reason="Writable "
                        + setting.script_type.name
                        + " script file identified at "
                        + path_result.assessed_path,
                        finding_detail="This script will run in the context of the users/computers to which this GPO is applied. Change the script, get command exec as those users/computers.",
                        triage=Triage.Black,
                    )
                )
            # if the path points to a dir and we can write to it, that's a lesser finding
            if path_result.directory_exists and path_result.directory_writable:
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            path_findings=[path_result],
                            finding_reason="Honestly this looks like a misconfigured "
                            + setting.script_type.name
                            + " script setting in a GPO or a bug in Group3r.",
                            finding_detail="Script settings should basically never point directly at a dir.",
                            triage=Triage.Green,
                        )
                    )
            # if the path points to a dir or a file that doesn't exist, but a parent directory does, and we can write to that, that's a finding
            if (
                path_result.parent_directory_exists
                and path_result.parent_directory_writable
            ):
                if self.min_triage < 4:
                    findings.append(
                        GpoFinding(
                            path_findings=[path_result],
                            finding_reason="Missing "
                            + setting.script_type.name
                            + " script with a writable parent dir identified at "
                            + path_result.parent_directory_exists
                            + ". The original target path was "
                            + path_result.assessed_path,
                            finding_detail="Recreate the missing parts of the path in the parent dir, put your code in the script. It will then run in the context of the users/computers to which this GPO is applied.",
                            triage=Triage.Red,
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

        # put findings in settingResult
        self.setting_result.findings = findings

        if "NTFRS" in setting.source:
            setting.is_morphed = True

        self.setting_result.setting = setting

        return self.setting_result
