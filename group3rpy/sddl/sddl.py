"""Port of LibSnaffle/Sddl.Parser/Sddl.cs.

Public entry point of the SDDL parser package.
"""

from .ace import Ace
from .acl import Acl
from .acm import Acm, cs_index_of, cs_substring
from .errors import Error
from .securable_object_type import SecurableObjectType
from .sid import Sid
from .string_builder_extensions import append_indent_env, append_line_env

DELIMINATOR_TOKEN = ":"
OWNER_TOKEN = "O"
GROUP_TOKEN = "G"
DACL_TOKEN = "D"
SACL_TOKEN = "S"


class Sddl(Acm):
    """Port of the Sddl.Parser.Sddl class."""

    def __init__(self, sddl: str, type: SecurableObjectType = SecurableObjectType.Unknown):
        super().__init__()

        self._raw = sddl
        self._owner: Sid | None = None
        self._group: Sid | None = None
        self._dacl: Acl | None = None
        self._sacl: Acl | None = None

        components: dict[str, str] = {}

        i = 0
        idx = 0
        len_ = 0

        while i != -1:
            i = cs_index_of(sddl, DELIMINATOR_TOKEN, idx + 1)

            if idx > 0:
                len_ = (i - idx - 2) if i > 0 else len(sddl) - (idx + 1)
                key = sddl[idx - 1]
                # C# evaluates the Add() arguments left to right, so the
                # substring is taken (and may throw) before the duplicate key
                # check happens.
                value = cs_substring(sddl, idx + 1, len_)
                # PORT NOTE: C# Dictionary<,>.Add throws on a duplicate key; the
                # original does not guard against it, so neither does the port.
                if key in components:
                    raise ValueError("An item with the same key has already been added.")
                components[key] = value

            idx = i

        owner = components.get(OWNER_TOKEN)
        if owner is not None:
            self._owner = Sid(owner)
            del components[OWNER_TOKEN]

        group = components.get(GROUP_TOKEN)
        if group is not None:
            self._group = Sid(group)
            del components[GROUP_TOKEN]

        dacl = components.get(DACL_TOKEN)
        if dacl is not None:
            self._dacl = Acl(dacl, type)
            del components[DACL_TOKEN]

        sacl = components.get(SACL_TOKEN)
        if sacl is not None:
            self._sacl = Acl(sacl, type)
            del components[SACL_TOKEN]

        if len(components) > 0:
            self.report(Error.SDP007.format())

    @property
    def raw(self) -> str:
        return self._raw

    @property
    def owner(self) -> Sid | None:
        return self._owner

    @property
    def group(self) -> Sid | None:
        return self._group

    @property
    def dacl(self) -> Acl | None:
        return self._dacl

    @property
    def sacl(self) -> Acl | None:
        return self._sacl

    def __str__(self) -> str:
        sb: list[str] = []

        if self._owner is not None:
            append_line_env(sb, f"Owner: {str(self._owner)}")

        if self._group is not None:
            append_line_env(sb, f"Group: {str(self._group)}")

        if self._dacl is not None:
            append_line_env(sb, "Dacl:")
            append_indent_env(sb, str(self._dacl))

        if self._sacl is not None:
            append_line_env(sb, "Sacl:")
            append_indent_env(sb, str(self._sacl))

        return "".join(sb)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Sddl):
            return False
        return (
            self._owner == other._owner
            and self._group == other._group
            and self._dacl == other._dacl
            and self._sacl == other._sacl
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(self._raw)


# PORT NOTE: re-exported here so that callers can do
# `from group3rpy.sddl.sddl import Sddl, SecurableObjectType` exactly as the C#
# code does `new Sddl.Parser.Sddl(s, Sddl.Parser.SecurableObjectType.File)`.
from .binary import sddl_from_binary, sddl_string_from_binary  # noqa: E402

__all__ = [
    "Sddl",
    "SecurableObjectType",
    "Ace",
    "Acl",
    "Sid",
    "sddl_from_binary",
    "sddl_string_from_binary",
]
