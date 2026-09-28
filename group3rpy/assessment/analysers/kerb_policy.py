"""Port of Group3r/Assessment/Analysers/KerbPolicy.cs

A flat if/else-if chain over the Kerberos policy key names, each one firing a
Green finding when the value differs from the Windows default. Note the original
has no MinTriage guards at all in this analyser.
"""

from typing import List

from ...classifiers.constants import Triage
from ..finding import GpoFinding, SettingResult
from .analyser import Analyser


class KerbPolicyAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.KerbPolicyAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of KerbPolicyAnalyser.Analyse."""

        findings: List[GpoFinding] = []

        if self.setting.key == "MaxTicketAge":
            if self.setting.value != "10":
                findings.append(
                    GpoFinding(
                        # GpoSetting = setting,
                        finding_reason="Non-default maximum Kerberos ticket age configured. "
                        + self.setting.value,
                        finding_detail="Dunno, bit interesting.",
                        triage=Triage.Green,
                    )
                )

        elif self.setting.key == "MaxRenewAge":
            if self.setting.value != "7":
                findings.append(
                    GpoFinding(
                        # GpoSetting = setting,
                        finding_reason=(
                            "Non-default maximum Kerberos renewal period configured. "
                        )
                        + self.setting.value,
                        finding_detail="Dunno, bit interesting.",
                        triage=Triage.Green,
                    )
                )

        elif self.setting.key == "MaxServiceAge":
            if self.setting.value != "600":
                findings.append(
                    GpoFinding(
                        # GpoSetting = setting,
                        finding_reason=(
                            "Non-default maximum Kerberos service ticket age configured. "
                        )
                        + self.setting.value,
                        finding_detail="Dunno, bit interesting.",
                        triage=Triage.Green,
                    )
                )

        elif self.setting.key == "MaxClockSkew":
            if self.setting.value != "5":
                findings.append(
                    GpoFinding(
                        # GpoSetting = setting,
                        finding_reason="Non-default maximum Kerberos clock skew setting. "
                        + self.setting.value,
                        finding_detail="Dunno, bit interesting.",
                        triage=Triage.Green,
                    )
                )

        elif self.setting.key == "TicketValidateClient":
            if self.setting.value != "1":
                findings.append(
                    GpoFinding(
                        # GpoSetting = setting,
                        finding_reason=(
                            "Kerberos 'Enforce user logon restrictions' setting is disabled."
                        ),
                        finding_detail=(
                            "Probably no significant impact, read here for more details: "
                            "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-user-logon-restrictions"
                        ),
                        triage=Triage.Green,
                    )
                )

        # put findings in settingResult
        self.setting_result.findings = findings

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
