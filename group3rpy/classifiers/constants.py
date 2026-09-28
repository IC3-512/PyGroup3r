"""Port of LibSnaffle/Classifiers/Rules/Constants.cs

Enum member *names* and ordinal values match the C# original exactly, because
Group3r compares triage levels numerically (e.g. `if ((int)MinTriage < 2)`).
"""

from enum import Enum, IntEnum


class MatchLoc(Enum):
    ShareName = "ShareName"
    FilePath = "FilePath"
    FileName = "FileName"
    FileExtension = "FileExtension"
    FileContentAsString = "FileContentAsString"
    FileContentAsBytes = "FileContentAsBytes"
    FileLength = "FileLength"
    FileMD5 = "FileMD5"


class MatchListType(Enum):
    Exact = "Exact"
    Contains = "Contains"
    Regex = "Regex"
    EndsWith = "EndsWith"
    StartsWith = "StartsWith"


class MatchAction(Enum):
    Discard = "Discard"
    SendToNextScope = "SendToNextScope"
    Snaffle = "Snaffle"
    Relay = "Relay"
    CheckForKeys = "CheckForKeys"
    EnterArchive = "EnterArchive"


class Triage(IntEnum):
    """Ordinals matter: Green=0, Yellow=1, Red=2, Black=3."""

    Green = 0
    Yellow = 1
    Red = 2
    Black = 3

    @classmethod
    def parse(cls, value):
        """Parse a triage name case-insensitively, as OptionsParser does."""
        if isinstance(value, cls):
            return value
        if value is None:
            return cls.Green
        for member in cls:
            if member.name.lower() == str(value).strip().lower():
                return member
        raise ValueError(f"Unknown triage level: {value!r}")


class EnumerationScope(Enum):
    ShareEnumeration = "ShareEnumeration"
    DirectoryEnumeration = "DirectoryEnumeration"
    FileEnumeration = "FileEnumeration"
    ContentsEnumeration = "ContentsEnumeration"
