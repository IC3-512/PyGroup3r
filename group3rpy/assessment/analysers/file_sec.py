"""Port of Group3r/Assessment/Analysers/FileSec.cs

Registered but inert: the original never adds a finding for a FileSecuritySetting,
it just assigns the (always empty) findings list and marks morphed settings. Note
that unlike NetOption/NetworkShare it *does* assign SettingResult.Findings.
"""

from typing import List

from ..finding import GpoFinding, SettingResult
from .analyser import Analyser


class FileSecAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.FileSecAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of FileSecAnalyser.Analyse."""
        findings: List[GpoFinding] = []

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        # put findings in settingResult
        self.setting_result.findings = findings
        self.setting_result.setting = self.setting

        return self.setting_result
