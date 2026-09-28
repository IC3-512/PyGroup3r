"""Port of LibSnaffle/Classifiers/ShareClassifier.cs"""

from dataclasses import dataclass
from typing import Any, Optional

from group3rpy.assessment.finding import ClassifierResult, TextResult
from group3rpy.classifiers.classifier_base import ClassifierBase
from group3rpy.classifiers.classifier_options import ClassifierOptions
from group3rpy.classifiers.constants import MatchAction, Triage
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule
from group3rpy.classifiers.text_classifier import TextClassifier


@dataclass
class ShareResult(ClassifierResult):
    """Port of LibSnaffle/Classifiers/Results/ShareResult.cs.

    PORT NOTE: group3rpy/assessment/finding.py carries the file/dir/text result
    types but not this one (Group3r itself never runs share enumeration), so it
    is defined here alongside its only consumer.
    """

    snaffle: bool = False
    scan_share: bool = False
    share_path: Optional[str] = None
    listable: bool = False
    triage: Triage = Triage.Green


class SysvolSwitch:
    """Port of LibSnaffle.Classifiers.SysvolSwitch (a C# static class)."""

    scan_sysvol: bool = True
    scan_netlogon: bool = True


class ShareClassifier(ClassifierBase):
    """Port of LibSnaffle.Classifiers.ShareClassifier."""

    def __init__(
        self, mq: Any, options: ClassifierOptions, fs: Optional[Any] = None
    ) -> None:
        super().__init__(mq, options, fs)

    def classify(
        self, classifier_rule: ClassifierRule, share: str
    ) -> Optional[ClassifierResult]:
        # first time we hit sysvol, toggle the flag and keep going. every other time, bail out.
        if share.lower().endswith("sysvol"):
            if SysvolSwitch.scan_sysvol is False:
                return None
            SysvolSwitch.scan_sysvol = False
        # same for netlogon
        if share.lower().endswith("netlogon"):
            if SysvolSwitch.scan_netlogon is False:
                return None
            SysvolSwitch.scan_netlogon = False
        # check if it matches
        text_classifier = TextClassifier(self.mq, self.options, self.fs)
        text_result: Optional[TextResult] = text_classifier.classify(
            classifier_rule, share
        )
        if text_result is not None:
            # if it does, see what we're gonna do with it
            if classifier_rule.match_action == MatchAction.Discard:
                return None
            elif classifier_rule.match_action == MatchAction.Snaffle:
                # in this context snaffle means 'send a report up the queue but don't scan the share'
                if self.is_share_readable(share):
                    share_result = ShareResult(
                        triage=classifier_rule.triage,
                        listable=True,
                        share_path=share,
                        matched_rule=classifier_rule,
                    )
                    return share_result
                else:
                    return None
            else:
                self._mq_error(
                    "You've got a misconfigured share ClassifierRule named "
                    + classifier_rule.rule_name
                    + "."
                )
                return None
        return None

    def is_share_readable(self, share: str) -> bool:
        """PORT NOTE: `Directory.GetFiles(share)` becomes FsProvider.list_dir."""
        try:
            if self.fs is None:
                return False
            self.fs.list_dir(share)
            return True
        except PermissionError:
            # catch (UnauthorizedAccessException)
            return False
        except Exception as e:  # noqa: BLE001 - mirrors catch (Exception e)
            self._mq_trace(str(e))
        return False
