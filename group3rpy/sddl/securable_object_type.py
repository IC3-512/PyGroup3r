"""Port of LibSnaffle/Sddl.Parser/SecurableObjectType.cs."""

from enum import Enum


class SecurableObjectType(Enum):
    """A list of securable object types in Windows is defined here https://msdn.microsoft.com/en-us/library/aa379557(VS.85).aspx.
    The enum partition object types into groups differing in allowed access rights.
    """

    Unknown = 0

    # NTFS file system
    File = 1
    Directory = 2

    Pipe = 3

    Process = 4
    Thread = 5

    FileMappingObject = 6

    AccessToken = 7

    WindowsManagementObject = 8

    RegistryKey = 9

    WindowsService = 10

    LocalOrRemotePrinter = 11

    NetworkShare = 12

    # Interprocess synchronization object
    Event = 13
    Mutex = 14
    Semaphore = 15
    Timer = 16

    JobObject = 17

    DirectoryServiceObject = 18
