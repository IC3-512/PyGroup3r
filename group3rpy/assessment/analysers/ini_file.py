"""Port of Group3r/Assessment/Analysers/IniFile.cs

DISABLED UPSTREAM: IniFileAnalyser is commented out in AnalyserFactory and must
stay unregistered. The body is one big commented-out block in the original (an
unfinished attempt at running the Snaffler engine over the ini file's path), which
is reproduced below as comments -- enabling it would add findings the original
does not produce.
"""

from ..finding import SettingResult
from .analyser import Analyser


class IniFileAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.IniFileAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of IniFileAnalyser.Analyse."""
        #
        # List<GpoFinding> findings = new List<GpoFinding>();
        #
        # findings.Add(new GpoFinding()
        # {
        #     //GpoSetting = setting,
        #     FindingReason = "IniFile analyser not implemented.",
        #     FindingDetail = "IniFile analyser not implemented.",
        #     Triage = Constants.Triage.Green
        # });
        # // put findings in settingResult
        # SettingResult.Findings = findings;
        #
        # // make a new setting object minus the ugly bits we don't care about.
        # SettingResult.Setting = new IniFileSetting();
        #
        #
        #
        #                 // if the path points to a dir or a file that exist and snaffler deems them interesting, that's a finding on its own, regardless of whether they're modifiable
        #     if (pathResult.SnaffDirResults.Count > 0)
        #     {
        #         foreach (DirResult dr in pathResult.SnaffDirResults)
        #         {
        #             if (dr.MatchedRule != null)
        #             {
        #                 if ((int)MinTriage <= (int)dr.Triage)
        #                 {
        #                     findings.Add(new GpoFinding()
        #                     {
        #                         PathFindings = new List<PathResult>() { pathResult },
        #                         FindingReason =
        #                             "The Snaffler engine deemed this directory path interesting on its own.",
        #                         FindingDetail = "Matched Path: " + dr.ResultDirInfo.FullName + " Matched Rule: " + dr.MatchedRule.RuleName,
        #                         Triage = dr.Triage
        #                     });
        #                 }
        #             }
        #         }
        #     }
        #     if (pathResult.SnaffFileResults.Count > 0)
        #     {
        #         foreach (FileResult fr in pathResult.SnaffFileResults)
        #         {
        #             if (fr.MatchedRule != null)
        #             {
        #                 if ((int)MinTriage <= (int)fr.Triage)
        #                 {
        #                     findings.Add(new GpoFinding()
        #                     {
        #                         PathFindings = new List<PathResult>() { pathResult },
        #                         FindingReason =
        #                             "The Snaffler engine deemed this file path interesting on its own.",
        #                         FindingDetail = "Matched Path: " + fr.ResultFileInfo.FullName + " Matched Rule: " + fr.MatchedRule.RuleName + " Match Context: " + fr.TextResult.MatchContext,
        #                         Triage = fr.Triage
        #                     });
        #                 }
        #             }
        #         }
        #     }
        #
        #

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
