"""Port of Group3r/View/IGpoPrinter.cs."""

from abc import ABC, abstractmethod

from ..ad.gpo import GPO
from ..assessment.finding import GpoResult


class IGpoPrinter(ABC):
    """Defines interface for GPO output behaviour."""

    @abstractmethod
    def output_gpo(self, gpo: GPO) -> str:
        ...

    @abstractmethod
    def output_gpo_result(self, gpo_result: GpoResult) -> str:
        ...
