"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/NtServiceSetting.cs"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..ad.gpo import GpoSetting

if TYPE_CHECKING:  # pragma: no cover
    from ..sddl.sddl import Sddl


@dataclass
class NtServiceSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.NtServiceSetting."""

    name: str | None = None
    sddl: str | None = None
    parsed_sddl: "Sddl | None" = None
    service_name: str | None = None
    timeout: str | None = None
    startup_type: str | None = None
    user_name: str | None = None
    cpassword: str | None = None
    password: str | None = None
    service_action: str | None = None
    program: str | None = None
    args: str | None = None
    action_on_first_failure: str | None = None
    # TODO possible there are second and third failures, check.
    append: str | None = None
    account_name: str | None = None
    reset_fail_count_delay: str | None = None
    interact: str | None = None
