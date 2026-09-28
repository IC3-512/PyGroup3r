"""Port of LibSnaffle/Classifiers/DirClassifier.cs"""

from typing import Any, Optional

from group3rpy.assessment.finding import DirResult, TextResult
from group3rpy.classifiers.classifier_base import ClassifierBase
from group3rpy.classifiers.classifier_options import ClassifierOptions
from group3rpy.classifiers.constants import MatchAction
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule
from group3rpy.classifiers.text_classifier import TextClassifier


class DirClassifier(ClassifierBase):
    """Port of LibSnaffle.Classifiers.DirClassifier."""

    def __init__(
        self, mq: Any, options: ClassifierOptions, fs: Optional[Any] = None
    ) -> None:
        super().__init__(mq, options, fs)

    def classify(
        self, classifier_rule: ClassifierRule, dir: str
    ) -> Optional[DirResult]:
        # PORT NOTE: `new DirectoryInfo(dir)` becomes the path string itself, and
        # the C# `DirResult(dirInfo)` constructor's ResultDirInfo assignment maps
        # onto DirResult.dir_path.
        dir_result = DirResult(dir_path=dir)

        # check if it matches
        text_classifier = TextClassifier(self.mq, self.options, self.fs)
        text_result: Optional[TextResult] = text_classifier.classify(
            classifier_rule, dir
        )
        if text_result is not None:
            # if it does, see what we're gonna do with it
            if classifier_rule.match_action == MatchAction.Discard:
                dir_result.scan_dir = False
                return dir_result
            elif classifier_rule.match_action == MatchAction.Snaffle:
                dir_result.scan_dir = False
                dir_result.triage = classifier_rule.triage
                return dir_result
            else:
                self._mq_error(
                    "You've got a misconfigured file ClassifierRule named "
                    + classifier_rule.rule_name
                    + "."
                )
                return None
        return dir_result

    # PORT NOTE (upstream bug, deliberately preserved): the C# DirClassifier
    # never assigns DirResult.MatchedRule, so PathAnalyser's
    # `snaffResult.MatchedRule != null` test is always false and no dir result is
    # ever recorded. Setting matched_rule here would emit findings the C# does
    # not, so it is left unset.
