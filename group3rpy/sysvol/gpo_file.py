"""Port of LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/GpoFile.cs

Base class for every SYSVOL settings-file parser.

PORT NOTE: the C# constructor takes a `FileInfo` alongside the path and keeps it
in `Info`, using it for `.Length`, `.Name` and `.Extension`. There is no
`FileInfo` for a UNC path on Linux, so the injected `FsProvider` takes its place
and is stored as `self.fs`; `full_name` stands in for `Info.FullName`, which for
an absolute path is the path itself. All file reads go through the provider.
"""

import os
from typing import List, Optional

from ..ad.gpo import GpoSetting
from ..smb.provider import FsProvider
from .dotnet_compat import read_all_lines


class GpoFile:
    """Port of LibSnaffle.ActiveDirectory.GpoFile (abstract)."""

    def __init__(self, filepath: str, fs: FsProvider, logger=None):
        self.file_path = filepath
        self.fs = fs
        self.logger = logger
        self.settings: List[GpoSetting] = []

    @property
    def full_name(self) -> str:
        """Stands in for `Info.FullName`."""
        return self.file_path

    # -- logging shims --------------------------------------------------------

    def _trace(self, message: str) -> None:
        if self.logger is not None:
            self.logger.trace(message)

    def _degub(self, message: str) -> None:
        if self.logger is not None:
            self.logger.degub(message)

    def _error(self, message: str) -> None:
        if self.logger is not None:
            self.logger.error(message)

    # -- content helpers ------------------------------------------------------

    def get_content_lines(self) -> List[str]:
        """Port of GpoFile.GetContentLines."""
        lines = read_all_lines(self.fs, self.file_path)

        line_list: List[str] = []

        for line in lines:
            if line.startswith(";"):
                continue
            else:
                line_list.append(line)

        return line_list

    def get_content_string(self, lines: Optional[List[str]] = None) -> str:
        """Port of both GpoFile.GetContentString overloads.

        PORT NOTE: `Environment.NewLine` is the host's line separator, so
        `os.linesep` is used. It only ever feeds an IsNullOrWhiteSpace check, so
        the choice of separator is not observable.
        """
        if lines is None:
            lines = self.get_content_lines()
        return os.linesep.join(lines)

    def parse(self) -> None:
        """Port of the abstract GpoFile.Parse."""
        raise NotImplementedError
