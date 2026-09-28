"""Port of LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/GpoFileFactory.cs

PORT NOTE: the C# builds a `FileInfo` and dispatches on `info.Name` and
`info.Extension`. Those become `ntpath`/`posixpath` basename and extension of the
path, and `info.Length` becomes `fs.file_length(path)`, because SYSVOL is reached
over SMB rather than through System.IO.
"""

import ntpath

from ..smb.provider import FsProvider
from .gpo_file import GpoFile
from .inf_gpo_file import InfGpoFile
from .ini_gpo_file import IniGpoFile
from .pol_gpo_file import PolGpoFile
from .xml_gpo_file import XmlGpoFile


def _file_name(file_path: str) -> str:
    """Stands in for `FileInfo.Name`.

    PORT NOTE: `ntpath` is used rather than `os.path` because it treats both "\\"
    and "/" as separators, so it handles the "\\"-joined UNC paths that come back
    from SMB *and* the "/"-joined paths of an offline SYSVOL copy on Linux.
    `os.path.basename` on Linux would return a whole UNC path unchanged.
    """
    return ntpath.basename(file_path)


def _extension(file_path: str) -> str:
    """Stands in for `FileInfo.Extension`, which includes the leading dot."""
    return ntpath.splitext(_file_name(file_path))[1]


class GpoFileFactory:
    """Port of LibSnaffle.ActiveDirectory.GpoFileFactory (a static class)."""

    @staticmethod
    def get_file(file_path: str, fs: FsProvider, logger=None) -> GpoFile:
        """Port of GpoFileFactory.GetFile."""
        info_name = _file_name(file_path)
        info_extension = _extension(file_path)
        new_file = None

        if fs.file_length(file_path) == 0:
            if logger is not None:
                logger.degub("Empty file was unparseable " + file_path)

        if info_name.lower() == "gpttmpl.inf":
            new_file = InfGpoFile(file_path, fs, logger)
        elif info_name.lower() == "scripts.ini":
            new_file = IniGpoFile(file_path, fs, logger)
        elif info_name.lower() == "psscripts.ini":
            new_file = IniGpoFile(file_path, fs, logger)
        elif info_name.lower() == "registry.pol":
            new_file = PolGpoFile(file_path, fs, logger)
        elif info_extension.lower() == ".xml":
            new_file = XmlGpoFile(file_path, fs, logger)
        else:
            raise NotImplementedError("No parser for " + file_path)

        return new_file
