"""Port of Group3r/Assessment/Analysers/EnvVar.cs

DISABLED UPSTREAM: EnvVarAnalyser is commented out in AnalyserFactory and must
stay unregistered. Everything but the IsMorphed check is commented out in the
original and stays commented out here.
"""

from ..finding import SettingResult
from .analyser import Analyser


class EnvVarAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.EnvVarAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of EnvVarAnalyser.Analyse."""
        # TODO - write analysis via textclassifier to look for creds etc

        #
        # List<GpoFinding> findings = new List<GpoFinding>();
        #
        # findings.Add(new GpoFinding()
        # {
        #     //GpoSetting = setting,
        #     FindingReason = "EnvVar analyser not implemented.",
        #     FindingDetail = "EnvVar analyser not implemented.",
        #     Triage = Constants.Triage.Green
        # });
        #             if (findings.Count > 0)
        # {
        #     this.setting.Findings = findings;
        #     return true;
        # }
        #             // put findings in settingResult
        # SettingResult.Findings = findings;
        #
        # // make a new setting object minus the ugly bits we don't care about.
        # SettingResult.Setting = new EnvVarSetting();
        #

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
