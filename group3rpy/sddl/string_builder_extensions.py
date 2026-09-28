"""Port of LibSnaffle/Sddl.Parser/StringBuilderExtensions.cs.

PORT NOTE: C# uses Environment.NewLine, which is "\\r\\n" on the Windows hosts
Group3r normally runs on. This port runs on Linux, so NEW_LINE is "\\n" -- the
same platform-dependent value the original asks for. Only the ToString()
pretty-printers below are affected; no parsed right name depends on it.
"""

NEW_LINE = "\n"

INDENT_STRING = "  "
INDENT_NEW_LINE = f"{NEW_LINE}{INDENT_STRING}"


def append_indent_env(sb: list[str], value: str) -> list[str]:
    indented_value = f"{INDENT_STRING}{value.replace(NEW_LINE, INDENT_NEW_LINE)}"
    return append_line_env(sb, indented_value.rstrip())


def append_line_env(sb: list[str], value: str) -> list[str]:
    sb.append(f"{value}{NEW_LINE}")
    return sb
