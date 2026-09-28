"""Port of LibSnaffle/Classifiers/ClassifierBase.cs

Class to provide the mechanism to run rules against artefacts.
"""

from abc import ABC, abstractmethod
from typing import Any, Optional

from group3rpy.assessment.finding import ClassifierResult
from group3rpy.classifiers.classifier_options import ClassifierOptions
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule


class ClassifierBase(ABC):
    """Port of LibSnaffle.Classifiers.ClassifierBase.

    PORT NOTE: the C# constructor signature is `(ClassifierOptions, BlockingMq)`
    but every concrete subclass exposes `(BlockingMq, ClassifierOptions)` and
    that is what callers such as PathAnalyser use, so the Python base takes the
    subclass order to keep one signature for the whole hierarchy.

    PORT NOTE: `fs` is an addition. The C# reaches the local/UNC filesystem
    directly through FileInfo/File; on Linux that IO goes through the injected
    FsProvider (`assessment_options.fs`). It is optional because the rules that
    Group3r actually exercises (file-name / dir-name matching via PathAnalyser)
    never touch file content.
    """

    def __init__(
        self,
        mq: Any,
        options: ClassifierOptions,
        fs: Optional[Any] = None,
    ) -> None:
        self.mq = mq
        self.all_rules = options.all_rules
        self.options = options
        self.fs = fs

    @abstractmethod
    def classify(
        self, classifier_rule: ClassifierRule, artefact: str
    ) -> Optional[ClassifierResult]:
        """Provides the logic to apply a rule to the artefact.

        :param classifier_rule: The rule to run
        :param artefact: The string representing the artefact. E.g path to a file.
        """
        raise NotImplementedError

    # --- mq helpers -------------------------------------------------------
    # The C# BlockingMq is always non-null; here mq may be None when a
    # classifier is used standalone (e.g. in tests), so guard the calls.

    def _mq_error(self, message: str) -> None:
        if self.mq is not None:
            self.mq.error(message)

    def _mq_trace(self, message: str) -> None:
        if self.mq is not None:
            self.mq.trace(message)
