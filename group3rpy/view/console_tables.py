"""Port of Group3r/View/ConsoleTables.cs (the vendored ConsoleTables library).

Every row of Group3r's default report goes through `to_mark_down_string()`, so
the padding, the ` | ` separators and the `-` divider produced here are part of
the product. Two .NET behaviours are reproduced by hand:

* `StringBuilder.AppendLine()` appends `Environment.NewLine`, which is CRLF on
  the Windows box Group3r runs on. NiceGpoPrinter.IndentPara then rewrites those
  CRLFs, so the whole report is CRLF-terminated.
* `string.Format("{0,-12}", value)` composite formatting, including the
  `value.ToString()` call it makes on each argument.
"""

import datetime as _datetime
import re
import sys
from enum import Enum
from typing import Any, Iterable, List, Optional, TextIO

# PORT NOTE: Environment.NewLine / StringBuilder.AppendLine on Windows.
NEWLINE = "\r\n"

# PORT NOTE: stands in for `char.MinValue`, the delimiter ToMinimalString uses.
CHAR_MIN_VALUE = "\0"

# PORT NOTE: sentinel so that an explicitly-passed null `options` still raises,
# as the C# `options ?? throw new ArgumentNullException("options")` does.
_MISSING: Any = object()

_FORMAT_HOLE = re.compile(r"\{(\d+)(?:,(-?\d+))?\}")


def dotnet_str(value: Any) -> str:
    """PORT NOTE: stand-in for `object.ToString()` as .NET would render it.

    Needed because the table measures and pads `value.ToString()`, and because
    NiceGpoPrinter calls `.ToString()` on enums, bools, Guids and DateTimes.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, _datetime.datetime):
        # PORT NOTE: .NET's default DateTime.ToString() is the culture's general
        # date/time pattern; Group3r runs on an en-US console, i.e.
        # "M/d/yyyy h:mm:ss tt".
        hour = value.hour % 12
        if hour == 0:
            hour = 12
        return "%d/%d/%d %d:%02d:%02d %s" % (
            value.month,
            value.day,
            value.year,
            hour,
            value.minute,
            value.second,
            "AM" if value.hour < 12 else "PM",
        )
    return str(value)


def net_format(format_string: str, *values: Any) -> str:
    """PORT NOTE: stand-in for `string.Format`, supporting the `{index,width}`
    alignment syntax the table builds. Substitution is one pass over the format
    string, so braces inside the *values* are never reinterpreted."""

    def sub(match: re.Match) -> str:
        index = int(match.group(1))
        text = dotnet_str(values[index]) if index < len(values) else ""
        if match.group(2) is None:
            return text
        width = int(match.group(2))
        if width < 0:
            return text.ljust(-width)
        return text.rjust(width)

    return _FORMAT_HOLE.sub(sub, format_string)


class Format(Enum):
    """Port of ConsoleTables.Format."""

    Default = 0
    MarkDown = 1
    Alternative = 2
    Minimal = 3


class Alignment(Enum):
    """Port of ConsoleTables.Alignment."""

    Left = 0
    Right = 1


class ConsoleTableOptions:
    """Port of ConsoleTables.ConsoleTableOptions."""

    def __init__(
        self,
        columns: Optional[Iterable[str]] = None,
        enable_count: bool = True,
        number_alignment: Alignment = Alignment.Left,
        output_to: Optional[TextIO] = None,
    ):
        self.columns: List[str] = list(columns) if columns is not None else []
        self.enable_count = enable_count
        # Enable only from a list of objects
        self.number_alignment = number_alignment
        # The TextWriter to write to. Defaults to Console.Out.
        self.output_to = output_to if output_to is not None else sys.stdout


class ConsoleTable:
    """Port of ConsoleTables.ConsoleTable."""

    # PORT NOTE: `NumericTypes` exists in the C# only so that GetNumberAlignment
    # can right-align numeric columns of a table built by `From<T>()`.
    NumericTypes = (int, float)

    def __init__(self, *columns: str, options: Optional[ConsoleTableOptions] = _MISSING):
        if options is _MISSING:
            options = ConsoleTableOptions(columns=list(columns))
        if options is None:
            raise ValueError("options")
        self.options = options
        self.rows: List[List[Any]] = []
        self.columns: List[Any] = list(options.columns)
        self.column_types: Optional[List[type]] = None

    def add_column(self, names: Iterable[str]) -> "ConsoleTable":
        for name in names:
            self.columns.append(name)
        return self

    def add_row(self, *values: Any) -> "ConsoleTable":
        if not self.columns:
            raise Exception("Please set the columns first")

        if len(self.columns) != len(values):
            raise Exception(
                "The number columns in the row ({Columns.Count}) does not match the values ({values.Length})"
                .replace("{Columns.Count}", str(len(self.columns)))
                .replace("{values.Length}", str(len(values)))
            )

        self.rows.append(list(values))
        return self

    def configure(self, action) -> "ConsoleTable":
        action(self.options)
        return self

    def to_string(self) -> str:
        builder: List[str] = []

        # find the longest column by searching each row
        column_lengths = self.column_lengths()

        # set right alinment if is a number
        column_alignment = [self.get_number_alignment(i) for i in range(len(self.columns))]

        # create the string format with padding
        format_string = "".join(
            " | {" + str(i) + "," + column_alignment[i] + str(column_lengths[i]) + "}"
            for i in range(len(self.columns))
        ) + " |"

        # find the longest formatted line
        max_row_length = max(
            0,
            max(len(net_format(format_string, *row)) for row in self.rows) if self.rows else 0,
        )
        column_headers = net_format(format_string, *self.columns)

        # longest line is greater of formatted columnHeader and longest row
        longest_line = max(max_row_length, len(column_headers))

        # add each row
        results = [net_format(format_string, *row) for row in self.rows]

        # create the divider
        divider = " " + "".join("-" for _ in range(longest_line - 1)) + " "

        builder.append(divider + NEWLINE)
        builder.append(column_headers + NEWLINE)

        for row in results:
            builder.append(divider + NEWLINE)
            builder.append(row + NEWLINE)

        builder.append(divider + NEWLINE)

        if self.options.enable_count:
            builder.append("" + NEWLINE)
            builder.append(net_format(" Count: {0}", len(self.rows)))

        return "".join(builder)

    def to_mark_down_string(self, delimiter: str = "|") -> str:
        builder: List[str] = []

        # find the longest column by searching each row
        column_lengths = self.column_lengths()

        # create the string format with padding
        format_string = self._format(column_lengths, delimiter)

        # find the longest formatted line
        column_headers = net_format(format_string, *self.columns)

        # add each row
        results = [net_format(format_string, *row) for row in self.rows]

        # create the divider
        divider = re.sub(r"[^|]", "-", column_headers)

        builder.append(column_headers + NEWLINE)
        builder.append(divider + NEWLINE)
        for row in results:
            builder.append(row + NEWLINE)

        return "".join(builder)

    def to_minimal_string(self) -> str:
        return self.to_mark_down_string(CHAR_MIN_VALUE)

    def to_string_alternative(self) -> str:
        builder: List[str] = []

        # find the longest column by searching each row
        column_lengths = self.column_lengths()

        # create the string format with padding
        format_string = self._format(column_lengths)

        # find the longest formatted line
        column_headers = net_format(format_string, *self.columns)

        # add each row
        results = [net_format(format_string, *row) for row in self.rows]

        # create the divider
        divider = re.sub(r"[^|]", "-", column_headers)
        divider_plus = divider.replace("|", "+")

        builder.append(divider_plus + NEWLINE)
        builder.append(column_headers + NEWLINE)

        for row in results:
            builder.append(divider_plus + NEWLINE)
            builder.append(row + NEWLINE)
        builder.append(divider_plus + NEWLINE)

        return "".join(builder)

    def _format(self, column_lengths: List[int], delimiter: str = "|") -> str:
        """Port of the private `Format` method (renamed to avoid colliding with
        the `Format` enum)."""
        # set right alinment if is a number
        column_alignment = [self.get_number_alignment(i) for i in range(len(self.columns))]

        delimiter_str = "" if delimiter == CHAR_MIN_VALUE else delimiter
        format_string = (
            "".join(
                " " + delimiter_str + " {" + str(i) + "," + column_alignment[i] + str(column_lengths[i]) + "}"
                for i in range(len(self.columns))
            )
            + " "
            + delimiter_str
        ).strip()
        return format_string

    def get_number_alignment(self, i: int) -> str:
        return (
            ""
            if (
                self.options.number_alignment == Alignment.Right
                and self.column_types is not None
                and self.column_types[i] in self.NumericTypes
            )
            else "-"
        )

    def column_lengths(self) -> List[int]:
        column_lengths = [
            max(
                len(dotnet_str(x))
                for x in ([row[i] for row in self.rows] + [self.columns[i]])
                if x is not None
            )
            for i in range(len(self.columns))
        ]
        return column_lengths

    def write(self, format: Format = Format.Default) -> None:
        if format == Format.Default:
            self.options.output_to.write(self.to_string() + NEWLINE)
        elif format == Format.MarkDown:
            self.options.output_to.write(self.to_mark_down_string() + NEWLINE)
        elif format == Format.Alternative:
            self.options.output_to.write(self.to_string_alternative() + NEWLINE)
        elif format == Format.Minimal:
            self.options.output_to.write(self.to_minimal_string() + NEWLINE)
        else:
            raise ValueError("format")
