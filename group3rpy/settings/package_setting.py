"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/PackageSetting.cs"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from ..ad.gpo import GpoSetting


@dataclass
class PackageSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.PackageSetting."""

    display_name: str | None = None
    distinguished_name: str | None = None
    msi_file_list: list[str] = field(default_factory=list)
    # PORT NOTE: C# `DateTime` is a value type defaulting to DateTime.MinValue;
    # Python has no equivalent sentinel, so unset dates are None. The parsers
    # always assign these before use.
    created_date: datetime | None = None
    modified_date: datetime | None = None
    ads_path: str | None = None
    # PORT NOTE: C# `Guid` defaults to Guid.Empty; represented as uuid.UUID here,
    # unset being None.
    product_code: uuid.UUID | None = None
    cn: str | None = None
    upgrade_product_code: uuid.UUID | None = None
    msi_script_name: str | None = None
    package_action: str | None = None
    parent_gpo: str | None = None
