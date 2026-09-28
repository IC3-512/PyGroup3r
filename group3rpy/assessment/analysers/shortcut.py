"""Port of Group3r/Assessment/Analysers/Shortcut.cs

PORT NOTE: `(int)MinTriage < 4` is ported as `self.min_triage < 4` -- there is no
Triage member with ordinal 4, so the guard is always true in the original.
Note also that the Arguments check here is case *sensitive*, unlike the otherwise
identical check in SchedTask/Script. That is how the original does it.
"""

from typing import List

from ...classifiers.constants import Triage
from ..finding import GpoFinding, SettingResult
from ..path_analyser import PathAnalyser
from .analyser import Analyser


class ShortcutAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.ShortcutAnalyser."""

    def __init__(self, setting=None):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of ShortcutAnalyser.Analyse."""
        setting = self.setting
        findings: List[GpoFinding] = []

        path_analyser = PathAnalyser(assessment_options)

        if setting.target_path.startswith("\\\\"):
            # shortcut targets a network share, we need to look at that
            path_result = path_analyser.analyse_path(setting.target_path)

            if path_result is not None:

                if path_result.file_exists and path_result.file_writable:
                    if self.min_triage < 4:
                        findings.append(
                            GpoFinding(
                                finding_reason="Shortcut points at a file that you can modify.",
                                finding_detail="It points to "
                                + setting.target_path
                                + " so maybe see what happens if you modify that file.",
                                triage=Triage.Red,
                            )
                        )
                elif (
                    not path_result.file_exists
                    and path_result.directory_exists
                    and path_result.directory_writable
                ):
                    if self.min_triage < 4:
                        findings.append(
                            GpoFinding(
                                finding_reason="Shortcut points to a file that doesn't exist, in a directory that you can write to.",
                                finding_detail="It points to "
                                + setting.target_path
                                + " so maybe see what happens if you create that file.",
                                triage=Triage.Red,
                            )
                        )
                elif (
                    not path_result.file_exists
                    and not path_result.directory_exists
                    and (
                        path_result.parent_directory_exists is not None
                        and path_result.parent_directory_exists.strip()
                    )
                    and path_result.parent_directory_writable
                ):
                    if self.min_triage < 4:
                        findings.append(
                            GpoFinding(
                                finding_reason="Shortcut points to a file that doesn't exist, in a directory that ALSO doesn't exist, but there's a parent directory that DOES exist that you can write to.",
                                finding_detail="It points to "
                                + setting.target_path
                                + " so maybe see what happens if you create that file.",
                                triage=Triage.Red,
                            )
                        )

        if setting.start_in.startswith("\\\\"):
            path_result = path_analyser.analyse_path(setting.start_in)

            # shortcut uses a startin directory on a network share, we need to look at that.

            if path_result.directory_exists and path_result.directory_writable:
                if self.min_triage < Triage.Black:
                    findings.append(
                        GpoFinding(
                            finding_reason="Shortcut is configured to use a working directory that you can write to.",
                            finding_detail="You might be able to pull some DLL sideloading shenanigans in "
                            + setting.start_in,
                            triage=Triage.Yellow,
                        )
                    )
            elif (
                not path_result.file_exists
                and not path_result.directory_exists
                and (
                    path_result.parent_directory_exists is not None
                    and path_result.parent_directory_exists.strip()
                )
                and path_result.parent_directory_writable
            ):
                if self.min_triage < Triage.Black:
                    findings.append(
                        GpoFinding(
                            finding_reason="Shortcut is configured to use a working directory that doesn't exist, but one of its parent directories DOES, and you can write to it.",
                            finding_detail="You might be able to pull some DLL sideloading shenanigans in "
                            + setting.start_in
                            + " if you create it.",
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

        if setting.arguments is not None and setting.arguments.strip():
            if (
                "pass" in setting.arguments
                or "-p" in setting.arguments
                or "/p" in setting.arguments
            ):
                if self.min_triage < Triage.Black:
                    findings.append(
                        GpoFinding(
                            finding_reason="Shortcut has an arguments setting that looks like it might have a password in it?",
                            finding_detail="Arguments were: " + setting.arguments,
                            triage=Triage.Yellow,
                        )
                    )

        # put findings in settingResult
        self.setting_result.findings = findings

        if "NTFRS" in setting.source:
            setting.is_morphed = True

        self.setting_result.setting = setting

        return self.setting_result
