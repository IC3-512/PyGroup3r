"""Port of LibSnaffle/Sddl.Parser/Format.cs."""

UNKNOWN_STRING = "Unknown({0})"


class Format:
    """Port of the internal static Sddl.Parser.Format class."""

    @staticmethod
    def unknown(input: str) -> str:
        return UNKNOWN_STRING.format(input)


def unknown(input: str) -> str:
    """Module level convenience alias for Format.unknown."""
    return Format.unknown(input)
