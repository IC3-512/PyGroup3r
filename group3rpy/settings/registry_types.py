"""Registry enums from LibSnaffle/ActiveDirectory/GPO/GpoSettings/RegistrySetting.cs

`RegHive` and `RegKeyValType` live in their own module (rather than in
`registry_setting.py`) so that `group3rpy.options.reg_keys` can import them
without pulling in the setting classes. `registry_setting` re-exports both for
convenience.
"""

from enum import Enum, IntEnum


class RegKeyValType(IntEnum):
    """Port of LibSnaffle.ActiveDirectory.RegKeyValType (C# `enum : uint`)."""

    REG_NONE = 0
    REG_SZ = 1       # string type (ASCII)
    REG_EXPAND_SZ = 2       # string, includes %ENVVAR% (expanded by caller) (ASCII)
    REG_BINARY = 3      # binary format, callerspecific
    REG_DWORD = 4       # DWORD in little endian format
    REG_DWORD_BIG_ENDIAN = 5       # DWORD in big endian format
    REG_LINK = 6       # symbolic link (UNICODE)
    REG_MULTI_SZ = 7       # multiple strings, delimited by \0, terminated by \0\0 (ASCII)
    REG_RESOURCE_LIST = 8
    REG_FULL_RESOURCE_DESCRIPTOR = 9
    REG_RESOURCE_REQUIREMENTS_LIST = 10
    REG_QWORD = 11


class RegHive(Enum):
    """Port of LibSnaffle.ActiveDirectory.RegHive.

    Values are the C# ordinals, so that the default value (0) is
    HKEY_CLASSES_ROOT exactly as in the original.
    """

    HKEY_CLASSES_ROOT = 0
    HKEY_CURRENT_USER = 1
    HKEY_LOCAL_MACHINE = 2
    HKEY_USERS = 3
    HKEY_CURRENT_CONFIG = 4
