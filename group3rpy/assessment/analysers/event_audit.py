"""Port of Group3r/Assessment/Analysers/EventAudit.cs

DISABLED UPSTREAM: EventAuditAnalyser is commented out in AnalyserFactory and must
stay unregistered.
"""

from ..finding import SettingResult
from .analyser import Analyser


class EventAuditAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.EventAuditAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of EventAuditAnalyser.Analyse."""
        # Nothing interesting enough in here to merit a 'finding'.

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
