"""Port of LibSnaffle/ActiveDirectory/Sysvol/Sysvol.cs and SysvolHelper.cs

Walks SYSVOL, finds GPO directories, parses every settings file it recognises and
sorts the resulting settings into Computer or User policy. The morphed-GPO
(NTFRS) split is preserved exactly.

PORT NOTE: directory and file enumeration go through an injected FsProvider
(impacket SMB, or a local directory in offline mode) instead of System.IO.
"""

import ntpath
import uuid
from typing import List, Optional

from ..ad.gpo import GPO, PolicyType
from ..smb.provider import FsProvider


class SysvolException(Exception):
    """Port of LibSnaffle.Errors.SysvolException."""


class FileFactoryException(Exception):
    """Port of LibSnaffle.Errors.FileFactoryException."""


class Sysvol:
    """Port of LibSnaffle.ActiveDirectory.Sysvol."""

    def __init__(
        self,
        sysvol_path: str,
        fs: FsProvider,
        logger=None,
    ):
        self.logger = logger
        self.fs = fs
        self.sysvol_path = sysvol_path
        self._trace("Enumerating GPO directories.")
        self.gpo_dirs = self.enumerate_gpo_directories(sysvol_path)
        self._trace("Enumerating SYSVOL GPOs.")
        self.gpos = self.enumerate_sysvol_gpos(self.gpo_dirs)

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

    # -- enumeration ----------------------------------------------------------

    def enumerate_gpo_directories(self, sysvol_path: str) -> List[str]:
        """Port of Sysvol.EnumerateGPODirectories.

        Assumes that a directory under ./policies whose name parses as a GUID is
        a GPO directory.
        """
        gpo_dirs: List[str] = []
        try:
            dirs = self.fs.list_dirs(sysvol_path)
        except Exception as exc:
            self._error(str(exc))
            self._error(
                "Failed to list the contents of SYSVOL - make sure you can access "
                "SYSVOL as the current user."
            )
            raise SysvolException(
                "Failed to list the contents of SYSVOL from " + sysvol_path
            ) from exc

        for directory in dirs:
            self._trace("Looking for policies dirs in " + directory)

            if "policies" in directory.lower():
                if "ntfrs" in directory.lower():
                    self._trace("Found a morphed policies directory: " + directory)
                self._trace("Found policies dir in " + directory)
                try:
                    for subdir in self.fs.list_dirs(directory):
                        name = ntpath.basename(subdir.rstrip("\\/"))
                        try:
                            uuid.UUID(name)
                            gpo_dirs.append(subdir)
                            self._trace("Found GPO dir " + subdir)
                        except ValueError:
                            self._trace("Found a dir that isn't a GPO dir " + subdir)
                            # Not a guid, not a GPO.
                except Exception as exc:
                    self._error("Failed to list the contents of " + directory)
                    self._error(str(exc))

        # The original returns whenever count >= 0, i.e. always; the throw below
        # it is unreachable. Preserved for behavioural equivalence.
        return gpo_dirs

    def enumerate_sysvol_gpos(self, gpo_dirs: List[str]) -> List[GPO]:
        """Port of Sysvol.EnumerateSysvolGpos."""
        from .gpo_file_factory import GpoFileFactory

        gpos: List[GPO] = []

        for gpo_dir in gpo_dirs:
            self._trace("Looking for GP Setting files in " + gpo_dir)

            name = ntpath.basename(gpo_dir.rstrip("\\/"))
            morphed_gpo = GPO.create(name, gpo_dir, True)
            gpo = GPO.create(name, gpo_dir, False)

            # For each file in PathInSysvol and all subdirectories.
            try:
                files_in_gpo = list(self.fs.list_all_files(gpo_dir))
            except Exception as exc:
                self._error(str(exc))
                files_in_gpo = []

            for file in files_in_gpo:
                self._trace("Looking inside file " + file + " for settings.")
                try:
                    # Get the file and its settings
                    gpo_file = GpoFileFactory.get_file(file, self.fs, self.logger)
                    gpo_file.parse()
                    # File only gets added if it is successfully parsed.
                    if "ntfrs" in file.lower():
                        morphed_gpo.gpo_files.append(file)
                        self.sort_settings(morphed_gpo, gpo_file)
                    else:
                        gpo.gpo_files.append(file)
                        self.sort_settings(gpo, gpo_file)
                except FileFactoryException as exc:
                    self._degub(f"Issue Parsing '{gpo_dir}': {exc}")
                    # Log this and proceed, it's not a dealbreaker.
                except NotImplementedError as exc:
                    self._degub(str(exc))
                except Exception as exc:
                    self._error(str(exc))

            if len(gpo.settings) >= 1:
                gpos.append(gpo)
            if len(morphed_gpo.settings) >= 1:
                gpos.append(morphed_gpo)

        return gpos

    def sort_settings(self, gpo: GPO, gpo_file) -> None:
        """Port of Sysvol.sortSettings.

        Sorts settings into Computer or User policy based on whether the file's
        path contains a `\\machine\\` or `\\user\\` component.
        """
        if len(gpo_file.settings) > 0:
            full_name = (gpo_file.full_name or "").lower()
            if "\\machine\\" in full_name or "/machine/" in full_name:
                for gpo_setting in gpo_file.settings:
                    gpo_setting.policy_type = PolicyType.Computer
                    gpo.settings.append(gpo_setting)
            elif "\\user\\" in full_name or "/user/" in full_name:
                for gpo_setting in gpo_file.settings:
                    gpo_setting.policy_type = PolicyType.User
                    gpo.settings.append(gpo_setting)
            else:
                self._degub(
                    "Some kind of policy I never done did heard of before? "
                    + (gpo_file.full_name or "")
                )
        else:
            self._trace(
                "File "
                + (gpo_file.full_name or "")
                + " didn't seem to have any interesting settings in it."
            )


class SysvolHelper:
    """Port of LibSnaffle.ActiveDirectory.SysvolHelper."""

    def __init__(self, fs: FsProvider, logger=None):
        self.fs = fs
        self.logger = logger

    def load_sysvol_offline(self, sysvol_path: str) -> Sysvol:
        """Port of SysvolHelper.LoadSysvolOffline."""
        self._validate_sysvol_path(sysvol_path)
        return Sysvol(sysvol_path, self.fs, self.logger)

    def load_sysvol_online_by_domain(self, target_domain: str) -> Sysvol:
        """Port of SysvolHelper.LoadSysvolOnlineByDomain."""
        sysvol_path = "\\\\" + target_domain + "\\sysvol\\" + target_domain + "\\"
        self._validate_sysvol_path(sysvol_path)
        return Sysvol(sysvol_path, self.fs, self.logger)

    def load_sysvol_online_by_dc(self, target_domain: str, target_dc: str) -> Sysvol:
        """Port of SysvolHelper.LoadSysvolOnlineByDc."""
        sysvol_path = "\\\\" + target_dc + "\\sysvol\\" + target_domain + "\\"
        self._validate_sysvol_path(sysvol_path)
        return Sysvol(sysvol_path, self.fs, self.logger)

    def _validate_sysvol_path(self, sysvol_path: Optional[str]) -> bool:
        """Port of SysvolHelper.ValidateSysvolPath."""
        if not sysvol_path:
            raise SysvolException("Failed to load SysVol, empty path.")
        try:
            # As in the original, the result is not checked -- this only exists to
            # surface a hard IO failure early.
            self.fs.dir_exists(sysvol_path)
        except Exception as exc:
            raise SysvolException(
                "Failed to read SYSVOL from " + sysvol_path
            ) from exc
        return True
