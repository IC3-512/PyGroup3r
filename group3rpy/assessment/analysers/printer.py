"""Port of Group3r/Assessment/Analysers/Printer.cs

Only checks for a GPP cpassword on the printer connection.
"""

from typing import List

from ...classifiers.constants import Triage
from ..finding import GpoFinding, SettingResult
from .analyser import Analyser


class PrinterAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.PrinterAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of PrinterAnalyser.Analyse."""
        findings: List[GpoFinding] = []

        if not (self.setting.cpassword is None or not self.setting.cpassword.strip()):
            password = self.setting.decrypt_cpassword(self.setting.cpassword)
            self.setting.password = password
            findings.append(
                GpoFinding(
                    finding_reason="Group Policy Preferences password found:" + password,
                    finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                    triage=Triage.Black,
                )
            )
        # put findings in settingResult
        self.setting_result.findings = findings

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
