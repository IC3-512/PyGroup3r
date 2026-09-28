"""Port of Group3r/Assessment/Analysers/Package.cs

Only MSI paths on a UNC share are assessed -- the original explicitly tests
`msiPath.StartsWith("\\\\")` (i.e. a literal double backslash) and silently skips
anything else.
"""

from typing import List

from ...classifiers.constants import Triage
from ..finding import GpoFinding, SettingResult
from ..path_analyser import PathAnalyser
from .analyser import Analyser


class PackageAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.PackageAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of PackageAnalyser.Analyse."""
        findings: List[GpoFinding] = []

        path_analyser = PathAnalyser(assessment_options)

        for msi_path in self.setting.msi_file_list:
            if not (msi_path is None or not msi_path.strip()):
                if msi_path.startswith("\\\\"):
                    # shortcut targets a network share, we need to look at that
                    path_result = path_analyser.analyse_path(msi_path)

                    if path_result is not None:
                        if path_result.file_exists and path_result.file_writable:
                            # PORT NOTE: the original compares against the literal
                            # 4, one past Triage.Black (3), so this guard is always
                            # true. Kept verbatim.
                            if self.min_triage < 4:
                                findings.append(
                                    GpoFinding(
                                        finding_reason=(
                                            "MSI package installer setting points at a "
                                            "file that you can modify."
                                        ),
                                        finding_detail="It points to "
                                        + msi_path
                                        + " so maybe see what happens if you replace that file with something fun.",
                                        triage=Triage.Red,
                                    )
                                )
                        elif (
                            not path_result.file_exists
                            and path_result.directory_exists
                            and path_result.directory_writable
                        ):
                            if self.min_triage < 4:
                                findings.append(
                                    GpoFinding(
                                        finding_reason=(
                                            "MSI package installer points to a file that "
                                            "doesn't exist, in a directory that you can "
                                            "write to."
                                        ),
                                        finding_detail="It points to "
                                        + msi_path
                                        + " so maybe see what happens if you put something fun in there.",
                                        triage=Triage.Red,
                                    )
                                )
                        elif (
                            not path_result.file_exists
                            and not path_result.directory_exists
                            and not (
                                path_result.parent_directory_exists is None
                                or not path_result.parent_directory_exists.strip()
                            )
                            and path_result.parent_directory_writable
                        ):
                            if self.min_triage < 4:
                                findings.append(
                                    GpoFinding(
                                        finding_reason=(
                                            "MSI package installer points to a file that "
                                            "doesn't exist, in a directory that ALSO "
                                            "doesn't exist, but there's a parent directory "
                                            "that DOES exist that you can write to."
                                        ),
                                        finding_detail="It points to "
                                        + msi_path
                                        + " so maybe see what happens if you create that file.",
                                        triage=Triage.Red,
                                    )
                                )

        self.setting_result.findings = findings
        self.setting_result.setting = self.setting

        return self.setting_result
