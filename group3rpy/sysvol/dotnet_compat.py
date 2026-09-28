"""Small .NET behavioural shims used by the SYSVOL file parsers.

This module has no C# counterpart; it exists so the ported parsers can reproduce
BCL semantics that Python does not share. Everything here is deliberately
"bug-compatible" with .NET rather than idiomatic.

PORT NOTE (encoding): the C# parsers read GPO files through
`File.ReadAllLines` / `StreamReader`, which auto-detect a byte order mark and
otherwise decode as UTF-8. GPO files in the wild are variously UTF-16LE with a
BOM (GptTmpl.inf, registry.pol payload strings), UTF-8 with a BOM, or ANSI.
`decode_bytes` reproduces that: BOM sniff for UTF-16LE / UTF-16BE / UTF-8, then
UTF-8, then Latin-1 as a last resort. The Latin-1 fallback is the one divergence
from .NET, which would emit U+FFFD replacement characters for undecodable bytes;
Latin-1 keeps the original bytes visible in findings instead of destroying them.

PORT NOTE (TryParse): `Boolean.TryParse`, `int.TryParse`, `DateTime.TryParse` and
`Enum.TryParse` all write a value to their `out` parameter even when they fail --
`default(T)`. The callers in the parsers rely on the *failure* path leaving the
setting field alone, except for `Enum.TryParse`, where the failure path silently
overwrites a pre-seeded value with the zero-valued enum member. `enum_try_parse`
therefore always returns a value, exactly as the original does.
"""

import re
from datetime import datetime
from enum import Enum
from typing import Any, List, Optional, Tuple, Type

_LINE_SPLIT = re.compile("\r\n|\r|\n")

_INT_PATTERN = re.compile(r"[+-]?[0-9]+")

# Formats tried by try_parse_datetime, in order, before ISO parsing.
_DATETIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y",
    "%Y-%m-%d",
)


def decode_bytes(data: bytes) -> str:
    """Equivalent of .NET's BOM-sniffing StreamReader default. See module docs."""
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def read_all_lines(fs, path: str) -> List[str]:
    """Equivalent of `File.ReadAllLines(path)`.

    Splits on CRLF, CR or LF only (Python's str.splitlines() also breaks on
    vertical tab, form feed and the Unicode separators, which .NET does not), and
    drops the empty trailing element a final newline would otherwise produce,
    because .NET's line reader stops at end of stream.
    """
    lines = _LINE_SPLIT.split(decode_bytes(fs.read_file(path)))
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def try_parse_bool(value: Optional[str]) -> Tuple[bool, bool]:
    """Equivalent of `Boolean.TryParse(value, out result)`.

    Only "true"/"false" parse (case-insensitively, surrounding whitespace
    trimmed); "1" and "0" do *not*, which is why several GPP boolean attributes
    stay at their default in the original too.
    """
    if value is None:
        return (False, False)
    trimmed = value.strip().lower()
    if trimmed == "true":
        return (True, True)
    if trimmed == "false":
        return (True, False)
    return (False, False)


def try_parse_int(value: Optional[str]) -> Tuple[bool, int]:
    """Equivalent of `int.TryParse(value, out result)` (NumberStyles.Integer).

    PORT NOTE: .NET Framework ignores an embedded NUL and everything after it, so
    `int.TryParse("1\\0")` succeeds with 1. Reproduced here because UTF-16-derived
    values routinely carry a trailing NUL once decoded as UTF-8.
    """
    if value is None:
        return (False, 0)
    trimmed = value.split("\x00", 1)[0].strip()
    if _INT_PATTERN.fullmatch(trimmed):
        try:
            return (True, int(trimmed))
        except ValueError:
            return (False, 0)
    return (False, 0)


def try_parse_datetime(value: Optional[str]) -> Tuple[bool, Optional[datetime]]:
    """Equivalent of `DateTime.TryParse(value, out result)`.

    PORT NOTE: .NET's parser is culture-driven and accepts a much wider range of
    formats than anything in the standard library. The formats tried here cover
    the GPP `changed` attribute ("2015-08-25 12:01:20") plus the common US and
    ISO spellings; anything else reports failure, which leaves the setting's
    date field untouched exactly as a failed TryParse does.
    """
    if value is None:
        return (False, None)
    trimmed = value.strip()
    if trimmed == "":
        return (False, None)
    for fmt in _DATETIME_FORMATS:
        try:
            return (True, datetime.strptime(trimmed, fmt))
        except ValueError:
            continue
    try:
        return (True, datetime.fromisoformat(trimmed))
    except ValueError:
        return (False, None)


def enum_cast(enum_cls: Type[Enum], value: int) -> Any:
    """Equivalent of C#'s unchecked `(SomeEnum)someInt` cast.

    PORT NOTE: casting an int to an enum in C# never throws, even when no member
    has that value; `enum_cls(value)` in Python raises ValueError. Undefined
    values are therefore handed back as the plain int, which still compares and
    formats sensibly against the IntEnum members downstream, instead of aborting
    the parse of a whole file.
    """
    try:
        return enum_cls(value)
    except ValueError:
        return value


def enum_try_parse(enum_cls: Type[Enum], value: Optional[str]) -> Any:
    """Equivalent of `Enum.TryParse<T>(value, out result)`.

    Case-sensitive member-name match, then a numeric-value match, and on failure
    `default(T)` -- the member whose value is 0. The callers seed their variable
    with a different member before calling TryParse, but C# overwrites it via the
    `out` parameter regardless of success, so the seed is dead. That quirk is
    preserved by always returning from here.
    """
    zero = enum_cls(0)
    if value is None:
        return zero
    trimmed = value.strip()
    if trimmed == "":
        return zero
    try:
        return enum_cls[trimmed]
    except KeyError:
        pass
    parsed, number = try_parse_int(trimmed)
    if parsed:
        try:
            return enum_cls(number)
        except ValueError:
            return zero
    return zero
