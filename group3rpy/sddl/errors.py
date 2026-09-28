"""Port of LibSnaffle/Sddl.Parser/Errors.cs."""


class Template:
    """Port of the nested Sddl.Parser.Error.Template class."""

    def __init__(self, code: str, formattable: str):
        self._code = code
        self._formattable = formattable

    @property
    def code(self) -> str:
        return self._code

    @property
    def formattable(self) -> str:
        return self._formattable

    def format(self, *args: str) -> "Error":
        return Error(self, *args)


class Error:
    """Port of the Sddl.Parser.Error class."""

    # C# declares the constructor private; construct via Template.format().
    def __init__(self, t: Template, *args: str):
        self._code = t.code
        # PORT NOTE: C# string.Format(T.Formattable, args) silently ignores
        # surplus arguments (e.g. SDP001 is formatted with the offending SID
        # even though its text has no placeholder); str.format does the same.
        self._description = t.formattable.format(*args)

    @property
    def code(self) -> str:
        return self._code

    @property
    def description(self) -> str:
        return self._description

    def __repr__(self) -> str:
        return f"{self._code}: {self._description}"

    SDP001: Template
    SDP002: Template
    SDP003: Template
    SDP004: Template
    SDP005: Template
    SDP006: Template
    SDP007: Template

    Template = Template


Error.SDP001 = Template("SDP001", "One or many access control model (ACM) components are invalid.")
Error.SDP002 = Template("SDP002", "Unknown SID `{0}` encountered.")
Error.SDP003 = Template("SDP003", "ACE have incorrect format. {0} parts, but at least 6 are required.")
Error.SDP004 = Template("SDP004", "ACL flags part can not be fully parsed (reminder: `{0}`).")
Error.SDP005 = Template("SDP005", "ACE at positional number {0} is empty.")
Error.SDP006 = Template("SDP006", "ACL contains unexpected `{0}` characters.")
Error.SDP007 = Template("SDP007", "Unknown SDDL components encountered.")
