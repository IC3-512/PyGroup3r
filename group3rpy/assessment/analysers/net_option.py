"""Port of Group3r/Assessment/Analysers/NetOption.cs

The entire finding block is commented out upstream, so this analyser never
produces a finding and never even assigns SettingResult.Findings -- it just marks
the setting as morphed if it came from an NTFRS path. The dead block is kept as a
comment so the two files stay line-for-line comparable.
"""

from typing import List

from ..finding import GpoFinding, SettingResult
from .analyser import Analyser


class NetOptionAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.NetOptionAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of NetOptionAnalyser.Analyse."""
        findings: List[GpoFinding] = []
        #
        # findings.Add(new GpoFinding()
        # {
        #     //GpoSetting = setting,
        #     FindingReason = "NetOption analyser not implemented.",
        #     FindingDetail = "NetOption analyser not implemented.",
        #     Triage = Constants.Triage.Green
        # });
        #
        # // put findings in settingResult
        # SettingResult.Findings = findings;
        #
        # // make a new setting object minus the ugly bits we don't care about.
        # SettingResult.Setting = new NetOptionSetting();
        #

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
