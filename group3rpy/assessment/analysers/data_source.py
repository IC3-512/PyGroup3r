"""Port of Group3r/Assessment/Analysers/DataSource.cs

Two findings: the GPP cpassword (Black) and a blanket informational finding for
the connection details themselves (Green, suppressed at MinTriage >= Red).
"""

from typing import List

from ...classifiers.constants import Triage
from ..finding import GpoFinding, SettingResult
from .analyser import Analyser


class DataSourceAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.DataSourceAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of DataSourceAnalyser.Analyse."""
        # get any findings
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

        if self.min_triage < Triage.Red:
            findings.append(
                GpoFinding(
                    finding_reason="Potentially useful database connection info identified.",
                    finding_detail="Could be helpful for targeting other attacks.",
                    triage=Triage.Green,
                )
            )

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        # put findings in settingResult
        self.setting_result.findings = findings

        self.setting_result.setting = self.setting

        return self.setting_result
