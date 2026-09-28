"""Port of LibSnaffle/Sddl.Parser/StringLengthComparer.cs."""

from typing import Mapping, TypeVar

_V = TypeVar("_V")


class StringLengthComparer:
    """Port of the internal Sddl.Parser.StringLengthComparer class.

    Orders longest-first, and alphabetically for equal lengths. Used by the
    SortedDictionary backing Ace.AceTypesDict so that two character tokens
    ("AU") are prefix-matched before one character tokens ("A").
    """

    @staticmethod
    def compare(x: str, y: str) -> int:
        result = (len(x) > len(y)) - (len(x) < len(y))

        if result == 0:
            return (x > y) - (x < y)
        else:
            return -result

    @staticmethod
    def key(x: str) -> tuple[int, str]:
        return (-len(x), x)


def sorted_by_string_length(source: Mapping[str, _V]) -> dict[str, _V]:
    """Reproduce SortedDictionary<string, T>(new StringLengthComparer()) order."""
    return {k: source[k] for k in sorted(source, key=StringLengthComparer.key)}
