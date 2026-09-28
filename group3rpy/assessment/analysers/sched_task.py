"""Port of Group3r/Assessment/Analysers/SchedTask.cs

PORT NOTE: `(int)MinTriage < 4` guards are ported as `self.min_triage < 4`. There
is no Triage member with ordinal 4 (Black is 3), so the condition is always true
in the original; writing the literal 4 keeps that visible rather than silently
"fixing" it into an unconditional block.
"""

from typing import List

from ...classifiers.constants import Triage
from ...settings.sched_task_setting import (
    SchedTaskEmailAction,
    SchedTaskExecAction,
    SchedTaskShowMessageAction,
)
from ..finding import GpoFinding, SettingResult
from ..path_analyser import PathAnalyser
from .analyser import Analyser


class SchedTaskAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.SchedTaskAnalyser."""

    def __init__(self, setting=None):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of SchedTaskAnalyser.Analyse."""
        setting = self.setting
        findings: List[GpoFinding] = []

        # if they're specifying who to run the task as
        if setting.principals is not None:
            if len(setting.principals) >= 1:
                for principal in setting.principals:
                    if principal.cpassword is not None and principal.cpassword.strip():
                        password = setting.decrypt_cpassword(principal.cpassword)
                        principal.password = password
                        findings.append(
                            GpoFinding(
                                finding_reason="Group Policy Preferences password found:"
                                + password,
                                finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                                triage=Triage.Black,
                            )
                        )

        if setting.actions is not None:
            for action in setting.actions:
                if type(action) is SchedTaskExecAction:
                    path_analyser = PathAnalyser(assessment_options)

                    sched_task_exec_action = action

                    if sched_task_exec_action.working_dir is not None:
                        if sched_task_exec_action.working_dir.startswith("\\\\"):
                            path_result = path_analyser.analyse_path(
                                sched_task_exec_action.working_dir
                            )

                            # schedtask uses a startin directory on a network share, we need to look at that.
                            if path_result is not None:
                                if (
                                    path_result.directory_exists
                                    and path_result.directory_writable
                                ):
                                    if self.min_triage < Triage.Black:
                                        findings.append(
                                            GpoFinding(
                                                finding_reason="Scheduled task exec action is configured to use a working directory that you can write to.",
                                                finding_detail="You might be able to pull some DLL sideloading shenanigans in "
                                                + sched_task_exec_action.working_dir,
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
                                                finding_reason="Scheduled task exec action is configured to use a working directory that doesn't exist, but one of its parent directories DOES, and you can write to it.",
                                                finding_detail="You might be able to pull some DLL sideloading shenanigans in "
                                                + sched_task_exec_action.working_dir
                                                + " if you create it.",
                                                triage=Triage.Yellow,
                                            )
                                        )

                    if (
                        sched_task_exec_action.args is not None
                        and sched_task_exec_action.args.strip()
                    ):
                        if (
                            "pass" in sched_task_exec_action.args.lower()
                            or "pw" in sched_task_exec_action.args.lower()
                            or "cred" in sched_task_exec_action.args.lower()
                            or "-p" in sched_task_exec_action.args.lower()
                            or "/p" in sched_task_exec_action.args.lower()
                        ):

                            if self.min_triage < Triage.Black:
                                findings.append(
                                    GpoFinding(
                                        finding_reason="Scheduled Task exec action has an arguments setting that looks like it might have a password in it?",
                                        finding_detail="Arguments were: "
                                        + sched_task_exec_action.args,
                                        triage=Triage.Yellow,
                                    )
                                )

                    if sched_task_exec_action.command is not None:
                        if sched_task_exec_action.command.startswith("\\\\"):
                            path_result = path_analyser.analyse_path(
                                sched_task_exec_action.command
                            )

                            if path_result.file_exists and path_result.file_writable:
                                if self.min_triage < 4:
                                    findings.append(
                                        GpoFinding(
                                            finding_reason="Scheduled Task execute action points at a file that you can modify.",
                                            finding_detail="It points to "
                                            + sched_task_exec_action.command
                                            + ", so maybe see what happens if you modify that file.",
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
                                            finding_reason="Scheduled Task execute action points to a file that doesn't exist, in a directory that you can write to.",
                                            finding_detail="It points to "
                                            + sched_task_exec_action.command
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
                                            finding_reason="Scheduled Task execute action points to a file that doesn't exist, in a directory that ALSO doesn't exist, but there's a parent directory that DOES exist that you can write to.",
                                            finding_detail="It points to "
                                            + sched_task_exec_action.command
                                            + " so maybe see what happens if you create that file.",
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
                elif type(action) is SchedTaskEmailAction:
                    sched_task_email_action = action

                    if sched_task_email_action.attachments is not None:
                        if len(sched_task_email_action.attachments) >= 1:
                            attachments = ""
                            if len(sched_task_email_action.attachments) == 1:
                                attachments = sched_task_email_action.attachments[0]
                            else:
                                for attachment in sched_task_email_action.attachments:
                                    # NOTE: yes, this leaves a leading ", " on the
                                    # multi-attachment case. So does the original.
                                    attachments = attachments + ", " + attachment

                            findings.append(
                                GpoFinding(
                                    finding_reason="Scheduled Task is emailing attachments. Could be interesting.",
                                    finding_detail="Check out " + attachments,
                                    triage=Triage.Green,
                                )
                            )
                elif type(action) is SchedTaskShowMessageAction:
                    self.mq.trace(
                        "Scheduled tasks that just show messages probably aren't worth a finding. Also I've never seen this used IRL."
                    )
                else:
                    self.mq.error("Unknown Scheduled Task action type.")

        self.setting_result.findings = findings

        if "NTFRS" in setting.source:
            setting.is_morphed = True

        self.setting_result.setting = setting

        return self.setting_result
