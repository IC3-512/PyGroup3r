"""Port of LibSnaffle/Concurrency/MessageTypes/*.cs and of
Group3r/Concurrency/GpoResultMessage.cs + FileResultMessage.cs.

The message classes carry a `get_message()` method exactly as the C#
`QueueMessage.GetMessage()` override does, and the format templates are kept as
the original literal strings (placeholders included) so that nothing about the
rendered line can drift.
"""

import datetime as _datetime
import re
from typing import Any, Optional

# PORT NOTE: .NET custom date/time format specifiers used by the message types.
# The templates below are copied verbatim from the C# interpolated strings, so
# the substitution is done by hand rather than by an f-string.
_NET_DATE_TOKENS = re.compile(r"yyyy|MM|dd|HH|mm|ss|zzz")


def net_date_string(value: Optional[_datetime.datetime], fmt: str) -> str:
    """PORT NOTE: stand-in for .NET `DateTime.ToString(string format)`.

    Only the specifiers Group3r actually uses are supported (yyyy, MM, dd, HH,
    mm, ss, zzz); anything else in the format string is passed through.
    """
    if value is None:
        return ""

    def offset(dt: _datetime.datetime) -> str:
        aware = dt if dt.tzinfo is not None else dt.astimezone()
        delta = aware.utcoffset() or _datetime.timedelta(0)
        total = int(delta.total_seconds())
        sign = "-" if total < 0 else "+"
        total = abs(total)
        return "%s%02d:%02d" % (sign, total // 3600, (total % 3600) // 60)

    def sub(match: re.Match) -> str:
        token = match.group(0)
        if token == "yyyy":
            return "%04d" % value.year
        if token == "MM":
            return "%02d" % value.month
        if token == "dd":
            return "%02d" % value.day
        if token == "HH":
            return "%02d" % value.hour
        if token == "mm":
            return "%02d" % value.minute
        if token == "ss":
            return "%02d" % value.second
        return offset(value)

    return _NET_DATE_TOKENS.sub(sub, fmt)


def _fill(
    template: str,
    datetime_string: str,
    delimeter: str,
    message_string: Optional[str],
    hole: str = "{MessageString}",
) -> str:
    """Substitute the C# interpolation holes in one of the message templates.

    The message string is substituted last, and only ever by `str.replace`, so a
    GPO report containing curly braces (registry GUIDs, the `{Red}` colour tags
    the NLog highlighting rules look for, ...) cannot be mangled.
    """
    out = template.replace("{datetime}", datetime_string)
    out = out.replace("{Delimeter}", delimeter)
    return out.replace(hole, "" if message_string is None else message_string)


class QueueMessage:
    """Port of LibSnaffle.Concurrency.QueueMessage (abstract)."""

    def __init__(
        self,
        msg_date_time: Optional[_datetime.datetime] = None,
        message_string: Optional[str] = None,
    ):
        #: DateTime representing the time that the message was created.
        self.msg_date_time = msg_date_time
        #: The content of the message.
        self.message_string = message_string
        # Represents the delimiter used to seperate message components when the
        # output is constructed. Defaults to a single space.
        self.delimeter = " "

    def get_message(self) -> str:
        """Method to construct the messgage to be outputted."""
        raise NotImplementedError


class TraceMessage(QueueMessage):
    """Port of LibSnaffle.Concurrency.TraceMessage."""

    def get_message(self) -> str:
        datetime = net_date_string(
            self.msg_date_time,
            "yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}".replace(
                "{Delimeter}", self.delimeter
            ),
        )
        return _fill("{datetime}[Trace]{Delimeter}{MessageString}", datetime, self.delimeter, self.message_string)


class DebugMessage(QueueMessage):
    """Port of LibSnaffle.Concurrency.DebugMessage."""

    def get_message(self) -> str:
        datetime = net_date_string(
            self.msg_date_time,
            "yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}".replace(
                "{Delimeter}", self.delimeter
            ),
        )
        return _fill("{datetime}[Degub]{Delimeter}{MessageString}", datetime, self.delimeter, self.message_string)


class InfoMessage(QueueMessage):
    """Port of LibSnaffle.Concurrency.InfoMessage."""

    def get_message(self) -> str:
        datetime = net_date_string(
            self.msg_date_time,
            "yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}".replace(
                "{Delimeter}", self.delimeter
            ),
        )
        return _fill("{datetime}[Info]{Delimeter}{MessageString}", datetime, self.delimeter, self.message_string)


class ErrorMessage(QueueMessage):
    """Port of LibSnaffle.Concurrency.ErrorMessage."""

    def get_message(self) -> str:
        datetime = net_date_string(
            self.msg_date_time,
            "yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz".replace("{Delimeter}", self.delimeter),
        )
        return _fill(
            "{datetime}{Delimeter}[Error]{Delimeter}{MessageString}",
            datetime,
            self.delimeter,
            self.message_string,
        )


class FatalMessage(QueueMessage):
    """Port of LibSnaffle.Concurrency.FatalMessage."""

    def get_message(self) -> str:
        datetime = net_date_string(
            self.msg_date_time,
            "yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}".replace(
                "{Delimeter}", self.delimeter
            ),
        )
        return _fill("{datetime}[Fatal]{Delimeter}{MessageString}", datetime, self.delimeter, self.message_string)


class FinishMessage(QueueMessage):
    """Port of LibSnaffle.Concurrency.FinishMessage."""

    def get_message(self) -> str:
        datetime = net_date_string(
            self.msg_date_time,
            "yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}".replace(
                "{Delimeter}", self.delimeter
            ),
        )
        return _fill("{datetime}[Finish]{Delimeter}{MessageString}", datetime, self.delimeter, self.message_string)


class GpoResultMessage(QueueMessage):
    """Port of Group3r.GpoResultMessage."""

    def __init__(
        self,
        msg_date_time: Optional[_datetime.datetime] = None,
        message_string: Optional[str] = None,
        gpo_result: Any = None,
    ):
        super().__init__(msg_date_time, message_string)
        self.gpo_result = gpo_result

    def get_message(self) -> str:
        datetime = net_date_string(
            self.msg_date_time,
            "yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}".replace(
                "{Delimeter}", self.delimeter
            ),
        )
        return _fill("{datetime}[GPO]{Delimeter}{MessageString}", datetime, self.delimeter, self.message_string)


class FileResultMessage(QueueMessage):
    """Port of Group3r.FileResultMessage."""

    def __init__(
        self,
        msg_date_time: Optional[_datetime.datetime] = None,
        message_string: Optional[str] = None,
        result: Any = None,
    ):
        super().__init__(msg_date_time, message_string)
        self.result = result

    def get_message(self) -> str:
        datetime = net_date_string(
            self.msg_date_time,
            "yyyy-MM-dd{Delimeter}HH:mm:ss{Delimeter}zzz{Delimeter}".replace(
                "{Delimeter}", self.delimeter
            ),
        )

        context = self.result.text_result.match_context if self.result.text_result is not None else ""
        matched_string = (
            self.result.text_result.matched_strings[0] if self.result.text_result is not None else ""
        )
        # PORT NOTE: the C# builds this with string interpolation (the `{{`/`}}`
        # in the original are escapes for single braces); the holes are filled by
        # concatenation here so no caller-supplied brace can be reinterpreted.
        msg = (
            "{"
            + self.result.matched_rule.triage.name
            + "}<"
            + self.result.matched_rule.rule_name
            + "|"
            + ("R" if self.result.rw_status.can_read else "")
            + ("W" if self.result.rw_status.can_write else "")
            + ("M" if self.result.rw_status.can_modify else "")
            + "|"
            + matched_string
            + "|Lengthoffile>("
            + self.result.file_path
            + ")"
            + context
        )
        return _fill(
            "{datetime}[HOSTSTRING] [File]{Delimeter}{msg}", datetime, self.delimeter, msg, hole="{msg}"
        )
