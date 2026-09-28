"""Port of Group3r/Assessment/Analysers/Device.cs

DISABLED UPSTREAM: DeviceAnalyser is commented out in AnalyserFactory and must
stay unregistered.
"""

from ..finding import SettingResult
from .analyser import Analyser


class DeviceAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.DeviceAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of DeviceAnalyser.Analyse."""
        # No 'finding' level issues in this area.

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
