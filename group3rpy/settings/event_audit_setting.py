"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/EventAuditSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting


@dataclass
class EventAuditSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.EventAuditSetting."""

    audit_type: str | None = None
    audit_level: int = 0
