"""Port of LibSnaffle/Sddl.Parser/Acm.cs."""

from .errors import Error


class Acm:
    """Port of the abstract Sddl.Parser.Acm class."""

    def __init__(self):
        self._errors: list[Error] = []

    @property
    def is_valid(self) -> bool:
        return len(self._errors) == 0

    @property
    def errors(self) -> list[Error]:
        return self._errors

    def report(self, error: Error) -> None:
        self._errors.append(error)


def cs_substring(value: str, start_index: int, length: int) -> str:
    """PORT NOTE: emulates C# String.Substring(int, int).

    Python slicing silently clamps out-of-range indices while C# raises
    ArgumentOutOfRangeException. Acl/Sddl both compute substring offsets
    arithmetically and rely on the CLR throwing for malformed input, so the
    port reproduces that instead of quietly returning a shorter string.
    """
    if start_index < 0 or length < 0 or start_index + length > len(value):
        raise ValueError(
            "Index and length must refer to a location within the string."
        )
    return value[start_index:start_index + length]


def cs_index_of(value: str, ch: str, start_index: int) -> int:
    """PORT NOTE: emulates C# String.IndexOf(char, int startIndex).

    The CLR throws ArgumentOutOfRangeException when startIndex is greater than
    the string length, which is how `new Sddl("")` fails in the original;
    str.find() would quietly return -1 and parse the empty string as a valid
    (empty) descriptor instead.
    """
    if start_index < 0 or start_index > len(value):
        raise ValueError("Index was out of range. Must be non-negative and less than the size of the collection.")
    return value.find(ch, start_index)
