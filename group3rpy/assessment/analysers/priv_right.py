"""Port of Group3r/Assessment/Analysers/PrivRight.cs

The nested loops here are first-match-wins: the inner `foreach` over
TrusteeOptions `break`s as soon as a trustee matches on SID or display name, so
the *first* matching TrusteeOption decides which finding (if any) is produced for
that trustee. That ordering is load bearing and is preserved exactly.
"""

from typing import List

from ...classifiers.constants import Triage
from ..finding import GpoFinding, SettingResult
from .analyser import Analyser


class PrivRightAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.PrivRightAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of PrivRightAnalyser.Analyse."""
        findings: List[GpoFinding] = []

        # iterate over the known-interesting privrights.
        for priv_right in assessment_options.priv_rights:
            if self.setting.privilege == priv_right.priv_right_name and (
                priv_right.grants_remote_access or priv_right.local_privesc
            ):
                for trustee in self.setting.trustees:
                    trustee_sid_for_match = trustee.sid
                    split_trustee = trustee.sid.split("-") if trustee.sid is not None else []
                    if len(split_trustee) == 8:
                        trustee_sid_for_match = (
                            split_trustee[0]
                            + "-"
                            + split_trustee[1]
                            + "-"
                            + split_trustee[2]
                            + "-"
                            + split_trustee[3]
                            + "-"
                            + "<DOMAIN>"
                            + "-"
                            + split_trustee[7]
                        )
                    matched = False
                    for trustee_option in assessment_options.trustee_options:
                        # if we have a match on either SID or display name
                        if (trustee_sid_for_match == trustee_option.sid) or (
                            trustee.display_name.lower() == trustee_option.display_name.lower()
                        ):
                            matched = True
                            if trustee_option.high_priv:
                                # boring
                                break
                            elif trustee_option.low_priv:
                                if (
                                    "network service" in trustee_option.display_name.lower()
                                    or "local service" in trustee_option.display_name.lower()
                                    or trustee_option.display_name.lower() == "service"
                                    or trustee_option.display_name.lower()
                                    == "nt authority\\service"
                                ):
                                    if self.setting.privilege == "SeAssignPrimaryTokenPrivilege":
                                        break
                                    if self.setting.privilege == "SeImpersonatePrivilege":
                                        break

                                # finding
                                gpo_finding = GpoFinding(
                                    finding_reason=(
                                        "Well-known low-priv user/group assigned an "
                                        "interesting OS privilege."
                                    ),
                                    finding_detail=self.setting.privilege
                                    + " was assigned to "
                                    + trustee.display_name
                                    + " - "
                                    + trustee.sid,
                                    triage=Triage.Black,
                                )
                                # add details
                                findings.append(gpo_finding)
                            elif trustee_option.target:
                                matched = True
                                # PORT NOTE: the original compares against the
                                # literal 4, which is one past Triage.Black (3),
                                # so this guard is always true. Kept verbatim.
                                if self.min_triage < 4:
                                    # finding
                                    gpo_finding = GpoFinding(
                                        finding_reason=(
                                            "Targeted user/group assigned an interesting "
                                            "OS privilege."
                                        ),
                                        finding_detail=self.setting.privilege
                                        + " was assigned to "
                                        + trustee.display_name
                                        + " - "
                                        + trustee.sid,
                                        triage=Triage.Red,
                                    )
                                    findings.append(gpo_finding)
                            else:
                                if self.min_triage < Triage.Red:
                                    # finding
                                    gpo_finding = GpoFinding(
                                        finding_reason=(
                                            "User/group assigned an interesting OS privilege. "
                                        ),
                                        finding_detail=self.setting.privilege
                                        + " was assigned to "
                                        + trustee.display_name
                                        + " - "
                                        + trustee.sid,
                                        triage=Triage.Green,
                                    )
                                    # add details
                                    findings.append(gpo_finding)
                            break

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        # put findings in settingResult
        self.setting_result.findings = findings

        self.setting_result.setting = self.setting

        return self.setting_result
