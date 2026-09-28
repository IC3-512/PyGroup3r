"""Port of Group3r/Assessment/Analysers/SystemAccess.cs

DISABLED UPSTREAM: SystemAccessAnalyser is commented out in AnalyserFactory, so
this class is never reached in a normal run. It is ported for completeness only
and must stay unregistered -- note the final `else` throws
NotImplementedException for any setting name it doesn't recognise, which is
presumably why it was disabled.

The if/else-if chain is first-match-wins on `setting.SettingName`, and each arm
carries its own MinTriage guard with the original's numeric threshold.
"""

from typing import List

from ...classifiers.constants import Triage
from ..finding import GpoFinding, SettingResult
from .analyser import Analyser


class SystemAccessAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.SystemAccessAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of SystemAccessAnalyser.Analyse."""
        findings: List[GpoFinding] = []

        if self.setting.setting_name == "MinimumPasswordAge":
            if self.setting.value_string != "1":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Non-default minimum password age.",
                            finding_detail="Minimum password age is "
                            + self.setting.value_string
                            + " days.",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "MaximumPasswordAge":
            if self.setting.value_string != "42":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Non-default maximum password age.",
                            finding_detail="Maximum password age is "
                            + self.setting.value_string
                            + " days.",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "MinimumPasswordLength":
            if self.setting.value_string != "7":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Non-default minimum password length.",
                            finding_detail="Minimum password length is "
                            + self.setting.value_string
                            + " days.",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "PasswordComplexity":
            if self.setting.value_string != "1":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Password complexity disabled.",
                            finding_detail="",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "PasswordHistorySize":
            if self.setting.value_string != "24":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Non-default password history size.",
                            finding_detail="Password history value is "
                            + self.setting.value_string,
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "LockoutBadCount":
            if self.setting.value_string != "5":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Non-default lockout count value.",
                            finding_detail="Accounts lock out after "
                            + self.setting.value_string
                            + " bad passwords",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "ResetLockoutCount":
            if self.setting.value_string != "30":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Non-default lockout reset time value.",
                            finding_detail="Invalid attempt counter resets after"
                            + self.setting.value_string
                            + " minutes.",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "LockoutDuration":
            if self.setting.value_string != "30":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Non-default lockout duration value.",
                            finding_detail="Account unlocks after"
                            + self.setting.value_string
                            + " minutes.",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "ForceLogoffWhenHourExpire":
            if self.setting.value_string != "0":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Force logoff outside hours is enforced.",
                            finding_detail="",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "NewAdministratorName":
            if not (self.setting.value_string is None or self.setting.value_string == ""):
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Local Administrator account name changed.",
                            finding_detail="New local Administrator account name is "
                            + self.setting.value_string,
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "NewGuestName":
            if not (self.setting.value_string is None or self.setting.value_string == ""):
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Local Guest account name changed.",
                            finding_detail="New local Guest account name is "
                            + self.setting.value_string,
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "ClearTextPassword":
            if self.setting.value_string != "0":
                if self.min_triage < Triage.Black:
                    findings.append(
                        GpoFinding(
                            finding_reason=(
                                "SAM (or domain if this GPO applies to DCs) passwords "
                                "stored with reversible encryption."
                            ),
                            finding_detail="",
                            triage=Triage.Yellow,
                        )
                    )

        elif self.setting.setting_name == "EnableGuestAccount":
            if self.setting.value_string != "0":
                if self.min_triage < Triage.Black:
                    findings.append(
                        GpoFinding(
                            finding_reason="Local Guest account enabled.",
                            finding_detail="",
                            triage=Triage.Yellow,
                        )
                    )

        elif self.setting.setting_name == "EnableAdminAccount":
            if self.setting.value_string != "1":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Local Administrator account disabled.",
                            finding_detail="",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "RequireLogonToChangePassword":
            if self.setting.value_string != "1":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason=(
                                "Expired passwords require admin intervention to reset."
                            ),
                            finding_detail="",
                            triage=Triage.Green,
                        )
                    )

        elif self.setting.setting_name == "LSAAnonymousNameLookup":
            if self.setting.value_string != "1":
                if self.min_triage < Triage.Red:
                    findings.append(
                        GpoFinding(
                            finding_reason="Anonymous users can query the local LSA policy.",
                            finding_detail="",
                            triage=Triage.Green,
                        )
                    )

        else:
            raise NotImplementedError(
                "SystemAccess analyser doesn't know what a "
                + self.setting.setting_name
                + " is."
            )

        # put findings in settingResult
        self.setting_result.findings = findings

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
