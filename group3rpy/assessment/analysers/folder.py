"""Port of Group3r/Assessment/Analysers/Folder.cs

DISABLED UPSTREAM: FolderAnalyser is commented out in AnalyserFactory and must
stay unregistered.
"""

from ..finding import SettingResult
from .analyser import Analyser


class FolderAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.FolderAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of FolderAnalyser.Analyse."""
        # Nothing particularly sexy or exciting in here.

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
