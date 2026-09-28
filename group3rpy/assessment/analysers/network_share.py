"""Port of Group3r/Assessment/Analysers/NetworkShare.cs

As with NetOption, the whole finding block is commented out upstream, so this
analyser only ever sets IsMorphed and hands the setting straight back.
"""

from typing import List

from ..finding import GpoFinding, SettingResult
from .analyser import Analyser


class NetworkShareAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.NetworkShareAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of NetworkShareAnalyser.Analyse."""
        findings: List[GpoFinding] = []
        #
        # findings.Add(new GpoFinding()
        # {
        #     //GpoSetting = setting,
        #     FindingReason = "NetworkShare analyser not implemented.",
        #     FindingDetail = "NetworkShare analyser not implemented.",
        #     Triage = Constants.Triage.Green
        # });
        #
        # // put findings in settingResult
        # SettingResult.Findings = findings;
        #
        # // make a new setting object minus the ugly bits we don't care about.
        # SettingResult.Setting = new NetworkShareSetting();
        #
        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
