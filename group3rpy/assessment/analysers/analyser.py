"""Port of Group3r/Assessment/Analysers/Analyser.cs

Base class for all 25 setting analysers.

Each concrete analyser is constructed with its setting, then `analyse()` is called
with the AssessmentOptions. `min_triage` is set by the controller before the call
and is compared numerically inside the analysers (`if ((int)MinTriage < 2)` becomes
`if self.min_triage < Triage.Red`), so it must stay a Triage IntEnum.
"""

from abc import ABC, abstractmethod
from typing import Optional

from ...classifiers.constants import Triage
from ..finding import SettingResult


class Analyser(ABC):
    """Port of Group3r.Assessment.Analysers.Analyser."""

    def __init__(self, setting=None):
        self.setting = setting
        self.setting_result: SettingResult = SettingResult()
        self.mq = None
        self.min_triage: Triage = Triage.Green

    @abstractmethod
    def analyse(self, assessment_options) -> SettingResult:
        """Produce the SettingResult for this analyser's setting."""
        raise NotImplementedError
