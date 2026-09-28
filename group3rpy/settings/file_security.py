"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/FileSecurity.cs

Note the filename/classname mismatch in the original: FileSecurity.cs declares
`FileSecuritySetting`. The class name is kept as-is because AnalyserFactory
dispatches on the type name.
"""

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from ..ad.gpo import GpoSetting

if TYPE_CHECKING:  # pragma: no cover
    from ..sddl.sddl import Sddl


class SecurityInheritanceType(Enum):
    NO_REPLACE = "NO_REPLACE"
    CONFIGURE_THEN_INHERIT = "CONFIGURE_THEN_INHERIT"
    CONFIGURE_THEN_PROPAGATE = "CONFIGURE_THEN_PROPAGATE"


@dataclass
class FileSecuritySetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.FileSecuritySetting."""

    sddl: str | None = None
    parsed_sddl: "Sddl | None" = None
    file_sec_path: str | None = None
    # C# enum fields default to the member with value 0.
    security_inheritance_type: SecurityInheritanceType = SecurityInheritanceType.NO_REPLACE
