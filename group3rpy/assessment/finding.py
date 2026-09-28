"""Port of Group3r/Assessment/GpoFinding.cs, GpoResult.cs and the Result types
from LibSnaffle/Classifiers/Results/Result.cs.

These are the shared contracts every analyser produces, and what both the
default printers and the new HTML report consume.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, List, Optional

from ..ad.trustee import Trustee
from ..classifiers.constants import Triage

if TYPE_CHECKING:  # pragma: no cover
    from ..ad.gpo import GPOAttributes


class ACEType(Enum):
    """Port of Group3r.Assessment.ACEType."""

    Allow = "Allow"
    Deny = "Deny"


class AccessType(Enum):
    """Port of Group3r.Assessment.AccessType."""

    READ = "READ"
    WRITE = "WRITE"
    MODIFY = "MODIFY"
    FULL = "FULL"


@dataclass
class RwStatus:
    """Port of LibSnaffle.Classifiers.Results.RwStatus."""

    exists: bool = False
    can_read: bool = False
    can_write: bool = False
    can_modify: bool = False


@dataclass
class AceFinding:
    """Port of Group3r.Assessment.AceFinding."""

    finding_reason: Optional[str] = None
    finding_detail: Optional[str] = None
    triage: Triage = Triage.Green


@dataclass
class SimpleAce:
    """Port of Group3r.Assessment.SimpleAce.

    `rights` is a list of right-name strings exactly as the SDDL parser emits
    them, because analysers and FsAclAnalyser test membership against those
    literal names.
    """

    trustee: Optional[Trustee] = None
    ace_type: ACEType = ACEType.Allow
    rights: List[str] = field(default_factory=list)
    ace_finding: Optional[AceFinding] = None


@dataclass
class ClassifierResult:
    """Port of LibSnaffle.Classifiers.Results.Result."""

    matched_rule: Any = None
    matched_string: Optional[str] = None
    rw_status: Optional[RwStatus] = None


@dataclass
class TextResult(ClassifierResult):
    """Port of LibSnaffle.Classifiers.Results.TextResult.

    `match_context` is a real property upstream (TextResult.cs) and is read by
    ScriptAnalyser, SchedTaskAnalyser, ShortcutAnalyser, FileAnalyser and
    FileResultMessage, so it must exist on the dataclass rather than being
    attached dynamically by the classifier.
    """

    matched_strings: List[str] = field(default_factory=list)
    matched_rule: Any = None
    match_context: Optional[str] = None


@dataclass
class FileResult(ClassifierResult):
    """Port of LibSnaffle.Classifiers.Results.FileResult.

    `ResultFileInfo` becomes a plain path plus the metadata we can read over SMB,
    since there is no local FileInfo in this port.
    """

    file_path: Optional[str] = None
    file_length: int = 0
    text_result: Optional[TextResult] = None
    triage: Triage = Triage.Green


@dataclass
class DirResult(ClassifierResult):
    """Port of LibSnaffle.Classifiers.Results.DirResult."""

    scan_dir: bool = False
    dir_path: Optional[str] = None
    triage: Triage = Triage.Green


@dataclass
class PathResult:
    """Port of the abstract Group3r.Assessment.PathResult."""

    assessed_path: Optional[str] = None
    file_exists: bool = False
    file_writable: bool = False
    directory_exists: bool = False
    directory_writable: bool = False
    # Note: string in the original, holding the path of the parent that exists.
    parent_directory_exists: Optional[str] = None
    parent_directory_writable: bool = False
    snaff_dir_results: List[DirResult] = field(default_factory=list)
    snaff_file_results: List[FileResult] = field(default_factory=list)
    rw_status: RwStatus = field(default_factory=RwStatus)

    def set_properties(self, original_path: str, exists: bool) -> None:
        raise NotImplementedError


@dataclass
class FilePathResult(PathResult):
    """Port of Group3r.Assessment.FilePathResult."""

    def set_properties(self, original_path: str, exists: bool) -> None:
        if exists:
            self.file_exists = True
        self.assessed_path = original_path


@dataclass
class DirPathResult(PathResult):
    """Port of Group3r.Assessment.DirPathResult."""

    def set_properties(self, original_path: str, exists: bool) -> None:
        if exists:
            self.directory_exists = True
        self.assessed_path = original_path


@dataclass
class GpoFinding:
    """Port of Group3r.Assessment.GpoFinding."""

    finding_reason: Optional[str] = None
    finding_detail: Optional[str] = None
    triage: Triage = Triage.Green
    path_findings: List[PathResult] = field(default_factory=list)
    acl_result: List[SimpleAce] = field(default_factory=list)


@dataclass
class SddlFinding:
    """Port of Group3r.Assessment.SddlFinding."""

    finding_reason: Optional[str] = None
    finding_detail: Optional[str] = None
    access_type: Optional[AccessType] = None


@dataclass
class SettingResult:
    """Port of Group3r.Assessment.SettingResult."""

    setting: Any = None
    findings: List[GpoFinding] = field(default_factory=list)


@dataclass
class FsAclResult:
    """Port of Group3r.Assessment.FsAclResult."""

    rw_status: RwStatus = field(default_factory=RwStatus)
    interesting_aces: List[SimpleAce] = field(default_factory=list)
    findings: List[GpoFinding] = field(default_factory=list)


class GpoResult:
    """Port of Group3r.Assessment.GpoResult.

    The constructor reproduces the original's behaviour of nulling out the raw
    security descriptor after parsing it, and of adding the blanket
    "Found some interesting ACLs on this GPO" finding whenever the GPO's own
    nTSecurityDescriptor yields any simplified ACEs.
    """

    def __init__(self, assessment_options, attributes: "GPOAttributes"):
        from .sddl_analyser import SddlAnalyser  # local import: avoids a cycle

        self.attributes = attributes
        self.gpo_acl_result: List[SimpleAce] = []
        self.gpo_attribute_findings: List[GpoFinding] = []
        self.setting_results: List[SettingResult] = []

        # null this out for display because we've already parsed it into a
        # semi-readable format
        self.attributes.nt_security_descriptor = None
        self._get_gpo_acl_result(assessment_options, SddlAnalyser)

    def _get_gpo_acl_result(self, assessment_options, sddl_analyser_cls) -> None:
        """Port of GpoResult.GetGpoAclResult."""
        sddl_analyser = sddl_analyser_cls(assessment_options)

        if self.attributes.nt_security_descriptor_sddl is None:
            return

        acl_result = sddl_analyser.analyse_sddl(
            self.attributes.nt_security_descriptor_sddl
        )
        if len(acl_result) > 0:
            self.gpo_attribute_findings.append(
                GpoFinding(
                    acl_result=acl_result,
                    finding_reason=(
                        "Found some interesting ACLs on this GPO. "
                        "Might wanna check 'em out."
                    ),
                    finding_detail="IDK just look at it jeez.",
                    triage=Triage.Black,
                )
            )
