"""Port of LibSnaffle/ActiveDirectory/GPO/GpoSettings/ScriptSetting.cs"""

from dataclasses import dataclass

from ..ad.gpo import GpoSetting, ScriptType


@dataclass
class ScriptSetting(GpoSetting):
    """Port of LibSnaffle.ActiveDirectory.ScriptSetting."""

    # C# enum fields default to the member with value 0, i.e. ScriptType.Logon.
    script_type: ScriptType = ScriptType.Logon
    cmd_line: str = ""
    parameters: str = ""
