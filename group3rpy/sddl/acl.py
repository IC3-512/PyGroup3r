"""Port of LibSnaffle/Sddl.Parser/Acl.cs."""

from .ace import Ace, BEGIN_TOKEN, END_TOKEN
from .acm import Acm, cs_substring
from .errors import Error
from .match import Match
from .securable_object_type import SecurableObjectType
from .string_builder_extensions import append_indent_env, append_line_env


class Acl(Acm):
    """Port of the Sddl.Parser.Acl class."""

    def __init__(self, acl: str, type: SecurableObjectType = SecurableObjectType.Unknown):
        super().__init__()

        self._raw = acl
        self._flags: list[str] | None = None
        self._aces: list[Ace] | None = None

        begin = acl.find(BEGIN_TOKEN)

        # Flags
        flags = acl if begin == -1 else cs_substring(acl, 0, begin)
        flags_labels, reminder = Match.many_by_prefix(flags, SdControlsDict)

        if reminder is not None:
            self.report(Error.SDP004.format(reminder))

        self._flags = list(flags_labels)

        # Aces
        if begin != -1:
            aces: list[Ace] = []

            # brackets balance: '(' = +1, ')' = -1
            balance = 0
            for end in range(begin, len(acl)):
                length = end - begin - 1

                if acl[end] == BEGIN_TOKEN:
                    if balance == 0:
                        begin = end

                    balance += 1
                elif acl[end] == END_TOKEN:
                    balance -= 1

                    if length < 0:
                        self.report(Error.SDP005.format(str(begin)))
                        continue

                    if balance == 0:
                        aces.append(Ace(cs_substring(acl, begin + 1, length), type))
                elif balance <= 0:
                    self.report(Error.SDP006.format(cs_substring(acl, begin + 1, length)))

                    balance = 0

            self._aces = list(aces)

    @property
    def raw(self) -> str:
        return self._raw

    @property
    def flags(self) -> list[str] | None:
        return self._flags

    @property
    def aces(self) -> list[Ace] | None:
        return self._aces

    def __str__(self) -> str:
        any_flags = self._flags is not None and len(self._flags) > 0
        any_aces = self._aces is not None and len(self._aces) > 0

        sb: list[str] = []

        if any_flags:
            append_line_env(sb, f"Flags: {', '.join(self._flags)}")

        if any_aces:
            for i in range(len(self._aces)):
                append_line_env(sb, f"Ace[{i:02d}]")
                append_indent_env(sb, str(self._aces[i]))

        return "".join(sb)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Acl):
            return False
        return (
            (
                (self._flags is None and other._flags is None)
                or (
                    self._flags is not None
                    and other._flags is not None
                    and len(set(self._flags) - set(other._flags)) == 0
                )
            )
            and (
                (self._aces is None and other._aces is None)
                or (
                    self._aces is not None
                    and other._aces is not None
                    and len(self._aces) == len(other._aces)
                    and all(a == b for a, b in zip(self._aces, other._aces))
                )
            )
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(self._raw)


SdControlsDict: dict[str, str] = {
    "P": "PROTECTED",
    "AR": "AUTO_INHERIT_REQ",
    "AI": "AUTO_INHERITED",
    "NO_ACCESS_CONTROL": "NULL_ACL",
}
