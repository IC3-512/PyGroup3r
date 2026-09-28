"""Port of LibSnaffle/Logging/Logging.cs

PORT NOTE: NLog becomes the standard library's `logging`. The layout is
`${message}` in the original, so a log line is exactly the message text with no
added timestamp or level prefix -- the `[Trace]`/`[Degub]`/`[Info]`/`[Error]`/
`[Fatal]` prefixes come from the message classes themselves. That is reproduced
here so console and file output match the original byte for byte.

NLog's ColoredConsoleTarget word-highlighting rules become ANSI colouring. The
original sets `DetectOutputRedirected = true`, which suppresses colour when stdout
is not a console, so colouring here is likewise applied only to a TTY -- meaning
redirected output is plain text, exactly as upstream.
"""

import logging
import re
import sys
from typing import Optional

TRACE = 5
logging.addLevelName(TRACE, "Trace")

# NLog level -> logging level, as ParseLogLevelString maps them.
_LEVELS = {
    "debug": logging.DEBUG,
    "degub": logging.DEBUG,
    "trace": TRACE,
    "data": logging.WARNING,
    "info": logging.INFO,
}

# ANSI equivalents of the ConsoleWordHighlightingRule set in Logging.cs and in
# Group3rRunner.SetupLogger (which adds [File], [GPO], {Yellow} and {Green}).
_RESET = "\x1b[0m"
_COLOURS = {
    "[Trace]": "\x1b[90m",   # DarkGray
    "[Degub]": "\x1b[37m",   # Gray
    "[Info]": "\x1b[97m",    # White
    "[Error]": "\x1b[95m",   # Magenta
    "[Fatal]": "\x1b[91m",   # Red
    "[File]": "\x1b[92m",    # Green
    "[GPO]": "\x1b[96m",     # Cyan
    "{Red}": "\x1b[91m",
    "{Black}": "\x1b[90m",
    "{Yellow}": "\x1b[93m",
    # Group3rRunner really does colour {Green} as Yellow. Preserved.
    "{Green}": "\x1b[93m",
}
_TOKENS = re.compile("|".join(re.escape(token) for token in _COLOURS))


class _ColourFormatter(logging.Formatter):
    """Applies the word-highlighting rules to whole lines containing a token."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        match = _TOKENS.search(message)
        if match is None:
            return message
        return _COLOURS[match.group(0)] + message + _RESET


class _PlainFormatter(logging.Formatter):
    """The `${message}` layout: message text and nothing else."""

    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


def parse_log_level_string(log_level_string: Optional[str], mq) -> int:
    """Port of Logging.ParseLogLevelString, including its Degub/Error messages."""
    key = (log_level_string or "").lower()
    if key in _LEVELS:
        level = _LEVELS[key]
        if key in ("debug", "degub"):
            mq.degub("Set verbosity level to degub.")
        elif key == "trace":
            mq.degub("Set verbosity level to trace.")
        elif key == "data":
            mq.degub("Set verbosity level to data.")
        else:
            mq.degub("Set verbosity level to info.")
        return level

    mq.error(
        "Invalid verbosity level "
        + str(log_level_string)
        + " falling back to default level (info)."
    )
    return logging.INFO


def setup_logger(
    log_to_file: bool,
    log_to_console: bool,
    mq,
    log_level_string: Optional[str],
    log_file_path: Optional[str],
) -> None:
    """Port of Logging.SetupLogger."""
    level = parse_log_level_string(log_level_string, mq)

    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    if log_to_console:
        console = logging.StreamHandler(stream=sys.stdout)
        console.setLevel(level)
        # DetectOutputRedirected: no colour unless we are on a real console.
        console.setFormatter(
            _ColourFormatter() if sys.stdout.isatty() else _PlainFormatter()
        )
        root.addHandler(console)

    if log_to_file and log_file_path:
        logfile = logging.FileHandler(log_file_path, encoding="utf-8")
        logfile.setLevel(level)
        logfile.setFormatter(_PlainFormatter())
        root.addHandler(logfile)
