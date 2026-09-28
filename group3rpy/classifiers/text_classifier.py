"""Port of LibSnaffle/Classifiers/TextClassifier.cs"""

import re
from typing import Any, Optional

from group3rpy.assessment.finding import TextResult
from group3rpy.classifiers.classifier_base import ClassifierBase
from group3rpy.classifiers.classifier_options import ClassifierOptions
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule


class TextClassifier(ClassifierBase):
    """Port of LibSnaffle.Classifiers.TextClassifier."""

    def __init__(
        self, mq: Any, options: ClassifierOptions, fs: Optional[Any] = None
    ) -> None:
        super().__init__(mq, options, fs)

    def classify(
        self, classifier_rule: ClassifierRule, input: str
    ) -> Optional[TextResult]:
        for regex in classifier_rule.regexes or []:
            try:
                if regex.search(input):
                    result = TextResult(
                        matched_strings=[regex.pattern],
                        matched_rule=classifier_rule,
                    )
                    # PORT NOTE: the already-written group3rpy TextResult has no
                    # match_context field, so the C# `MatchContext` property is
                    # attached dynamically rather than redefining the result type.
                    result.match_context = self.get_context(input, regex)
                    return result
            except Exception as e:  # noqa: BLE001 - mirrors catch (Exception e)
                self._mq_error(str(e))

        return None

    def get_context(self, original: str, match_regex: "re.Pattern[str]") -> str:
        try:
            if self.options.match_context_bytes == 0:
                return ""

            if (len(original) < 6) or (
                len(original) < self.options.match_context_bytes * 2
            ):
                return original

            found_index = match_regex.search(original).start()

            context_start = self.subtract_with_floor(
                found_index, self.options.match_context_bytes, 0
            )
            match_context = ""

            if len(original) <= (
                context_start + (self.options.match_context_bytes * 2)
            ):
                return re.escape(original[context_start:])

            if self.options.match_context_bytes > 0:
                match_context = original[
                    context_start : context_start
                    + self.options.match_context_bytes * 2
                ]

            return re.escape(match_context)
        except Exception as e:  # noqa: BLE001 - mirrors catch (Exception e)
            self._mq_error(str(e))

        return ""

    def subtract_with_floor(self, num1: int, num2: int, floor: int) -> int:
        result = num1 - num2
        if result <= floor:
            return floor
        return result
