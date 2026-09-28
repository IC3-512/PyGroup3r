"""Filesystem providers that stand in for the .NET `System.IO` + Win32 ACL calls
the original Group3r makes against SYSVOL and against UNC paths referenced by
GPO settings.

PORT NOTE: the C# original runs on a domain-joined Windows host, so it can call
`Directory.Exists`, `File.GetAccessControl` etc. directly on `\\\\dc\\sysvol\\...`
and on whatever UNC paths turn up inside GPO settings. On Linux there is no such
redirector, so every one of those calls is routed through an `FsProvider`:

  * `SmbFsProvider`   - impacket SMB, for UNC paths (`\\\\host\\share\\...`)
  * `LocalFsProvider` - a local directory, for `-s/--sysvol` offline mode
  * `CompositeFsProvider` - routes UNC to SMB and everything else to local,
    which is what reproduces the original's behaviour of being able to follow a
    UNC path out of a GPO setting even while reading SYSVOL from a local copy.

Security descriptors are fetched as *binary* via SMB2 QUERY_INFO with
`SMB2_0_INFO_SECURITY` and `OWNER|DACL`, which is the same information
`GetAccessControl(...Owner | Access)` returns in the original. The binary blob is
handed to `group3rpy.sddl` for conversion so that both the SMB path and the
SDDL-string path produce identical right-name strings.
"""

import ntpath
import os

import threading
from abc import ABC, abstractmethod
from typing import Iterator, List, Optional, Tuple

from impacket.smb3structs import (
    DACL_SECURITY_INFORMATION,
    FILE_ATTRIBUTE_NORMAL,
    FILE_DIRECTORY_FILE,
    FILE_NON_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    OWNER_SECURITY_INFORMATION,
    READ_CONTROL,
    SMB2_0_INFO_SECURITY,
    SYNCHRONIZE,
)
from impacket.smbconnection import SessionError, SMBConnection


class FsProvider(ABC):
    """The filesystem surface the ported code is allowed to use."""

    @abstractmethod
    def file_exists(self, path: str) -> bool: ...

    @abstractmethod
    def dir_exists(self, path: str) -> bool: ...

    @abstractmethod
    def read_file(self, path: str) -> bytes: ...

    @abstractmethod
    def list_dir(self, path: str) -> List[str]:
        """Immediate children (files and dirs), as full paths."""

    @abstractmethod
    def list_dirs(self, path: str) -> List[str]:
        """Immediate child directories only, as full paths.

        Equivalent of `Directory.GetDirectories`.
        """

    @abstractmethod
    def list_all_files(self, path: str) -> List[str]:
        """Recursive file listing. Equivalent of FileSystemEnumerator.ListAllFiles."""

    @abstractmethod
    def file_length(self, path: str) -> int: ...

    @abstractmethod
    def get_security_descriptor(self, path: str) -> Optional[bytes]:
        """Binary SD with OWNER + DACL, or None if unavailable/denied."""


def split_unc(path: str) -> Tuple[str, str, str]:
    """Split `\\\\host\\share\\a\\b` into ('host', 'share', 'a\\b')."""
    if not path.startswith("\\\\"):
        raise ValueError(f"Not a UNC path: {path!r}")
    remainder = path[2:]
    parts = remainder.split("\\")
    parts = [p for p in parts]
    if len(parts) < 2:
        raise ValueError(f"UNC path has no share component: {path!r}")
    host = parts[0]
    share = parts[1]
    rest = "\\".join(parts[2:])
    return host, share, rest


def is_unc(path: str) -> bool:
    return bool(path) and path.startswith("\\\\")


class LocalFsProvider(FsProvider):
    """Local-filesystem provider, used for `--sysvol <local path>` offline mode.

    Accepts both Windows-style and POSIX-style separators and normalises to the
    host separator, since offline sysvol copies on Linux use `/` internally while
    the ported code still passes `\\`-joined paths around.
    """

    def __init__(self, root: Optional[str] = None):
        self.root = root

    def _local(self, path: str) -> str:
        return path.replace("\\", os.sep)

    def file_exists(self, path: str) -> bool:
        return os.path.isfile(self._local(path))

    def dir_exists(self, path: str) -> bool:
        return os.path.isdir(self._local(path))

    def read_file(self, path: str) -> bytes:
        with open(self._local(path), "rb") as handle:
            return handle.read()

    def list_dir(self, path: str) -> List[str]:
        # Joins with the host separator and preserves the caller's path form, so
        # list_dir and list_dirs return paths of the same shape.
        local = self._local(path)
        return [os.path.join(path, name) for name in sorted(os.listdir(local))]

    def list_dirs(self, path: str) -> List[str]:
        local = self._local(path)
        out = []
        for name in sorted(os.listdir(local)):
            if os.path.isdir(os.path.join(local, name)):
                out.append(os.path.join(path, name))
        return out

    def list_all_files(self, path: str) -> List[str]:
        out: List[str] = []
        for dirpath, _dirnames, filenames in os.walk(self._local(path)):
            for name in sorted(filenames):
                out.append(os.path.join(dirpath, name))
        return out

    def file_length(self, path: str) -> int:
        try:
            return os.path.getsize(self._local(path))
        except OSError:
            return 0

    def get_security_descriptor(self, path: str) -> Optional[bytes]:
        # PORT NOTE: a local copy of SYSVOL on Linux carries no Windows security
        # descriptors, so ACL-derived findings are unavailable in offline mode.
        # The original has the same blind spot when pointed at a copied sysvol.
        return None


class SmbFsProvider(FsProvider):
    """impacket-backed provider for UNC paths.

    One `SMBConnection` per host, created lazily and reused. Connections and the
    per-host tree cache are guarded by a lock because Group3r fans GPO analysis
    out across threads.
    """

    def __init__(
        self,
        username: str = "",
        password: str = "",
        domain: str = "",
        lmhash: str = "",
        nthash: str = "",
        aes_key: str = "",
        kerberos: bool = False,
        kdc_host: Optional[str] = None,
        host_override: Optional[str] = None,
        timeout: int = 30,
    ):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.aes_key = aes_key
        self.kerberos = kerberos
        self.kdc_host = kdc_host
        # When set, every UNC host is dialled at this address instead. Lets the
        # caller pin traffic to a specific DC (`--domaincontroller`) while the
        # paths still carry the domain name.
        self.host_override = host_override
        self.timeout = timeout

        self._lock = threading.RLock()
        self._connections: dict[str, SMBConnection] = {}
        self._trees: dict[Tuple[str, str], int] = {}
        self._dead_hosts: set[str] = set()

    # -- connection management ------------------------------------------------

    def _connect(self, host: str) -> Optional[SMBConnection]:
        key = host.lower()
        with self._lock:
            if key in self._connections:
                return self._connections[key]
            if key in self._dead_hosts:
                return None
            target = self.host_override or host
            try:
                conn = SMBConnection(host, target, sess_port=445, timeout=self.timeout)
                if self.kerberos:
                    conn.kerberosLogin(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                        self.aes_key,
                        self.kdc_host,
                    )
                else:
                    conn.login(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                    )
                self._connections[key] = conn
                return conn
            except Exception:
                # Unreachable or auth-refused hosts are remembered so a big scan
                # does not stall retrying the same dead referral over and over.
                self._dead_hosts.add(key)
                return None

    def _tree(self, host: str, share: str) -> Optional[int]:
        conn = self._connect(host)
        if conn is None:
            return None
        key = (host.lower(), share.lower())
        with self._lock:
            if key in self._trees:
                return self._trees[key]
            try:
                tree_id = conn.connectTree(share)
                self._trees[key] = tree_id
                return tree_id
            except Exception:
                return None

    def close(self) -> None:
        with self._lock:
            for conn in self._connections.values():
                try:
                    conn.close()
                except Exception:
                    pass
            self._connections.clear()
            self._trees.clear()

    # -- helpers --------------------------------------------------------------

    def _stat(self, path: str):
        """Return the impacket SharedFile for `path`, or None."""
        try:
            host, share, rest = split_unc(path)
        except ValueError:
            return None
        conn = self._connect(host)
        if conn is None:
            return None
        if not rest:
            # The share root itself.
            return "SHARE_ROOT"
        try:
            entries = conn.listPath(share, rest)
        except SessionError:
            return None
        except Exception:
            return None
        base = ntpath.basename(rest)
        for entry in entries:
            if entry.get_longname() == base:
                return entry
        # A pattern-less listPath on an exact name returns the entry itself; if
        # the name came back as '.' treat the first entry as the match.
        if len(entries) == 1 and entries[0].get_longname() in (".", base):
            return entries[0]
        return None

    # -- FsProvider -----------------------------------------------------------

    def file_exists(self, path: str) -> bool:
        entry = self._stat(path)
        if entry is None or entry == "SHARE_ROOT":
            return False
        return not entry.is_directory()

    def dir_exists(self, path: str) -> bool:
        entry = self._stat(path)
        if entry == "SHARE_ROOT":
            return True
        if entry is None:
            return False
        return bool(entry.is_directory())

    def file_length(self, path: str) -> int:
        entry = self._stat(path)
        if entry is None or entry == "SHARE_ROOT":
            return 0
        try:
            return int(entry.get_filesize())
        except Exception:
            return 0

    def read_file(self, path: str) -> bytes:
        host, share, rest = split_unc(path)
        conn = self._connect(host)
        if conn is None:
            raise OSError(f"Could not connect to {host}")
        chunks: List[bytes] = []
        conn.getFile(share, rest, chunks.append)
        return b"".join(chunks)

    def _list(self, path: str, want_dirs: Optional[bool]) -> List[str]:
        try:
            host, share, rest = split_unc(path)
        except ValueError:
            return []
        conn = self._connect(host)
        if conn is None:
            return []
        pattern = ntpath.join(rest, "*") if rest else "*"
        try:
            entries = conn.listPath(share, pattern)
        except Exception:
            return []
        out: List[str] = []
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            if want_dirs is True and not entry.is_directory():
                continue
            if want_dirs is False and entry.is_directory():
                continue
            out.append(path.rstrip("\\") + "\\" + name)
        return out

    def list_dir(self, path: str) -> List[str]:
        return self._list(path, None)

    def list_dirs(self, path: str) -> List[str]:
        return self._list(path, True)

    def list_all_files(self, path: str) -> List[str]:
        out: List[str] = []
        for entry in self._walk(path):
            out.append(entry)
        return out

    def _walk(self, path: str) -> Iterator[str]:
        try:
            host, share, rest = split_unc(path)
        except ValueError:
            return
        conn = self._connect(host)
        if conn is None:
            return
        stack = [path.rstrip("\\")]
        while stack:
            current = stack.pop()
            _h, _s, current_rest = split_unc(current)
            pattern = ntpath.join(current_rest, "*") if current_rest else "*"
            try:
                entries = conn.listPath(share, pattern)
            except Exception:
                continue
            for entry in entries:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue
                child = current + "\\" + name
                if entry.is_directory():
                    stack.append(child)
                else:
                    yield child

    def get_security_descriptor(self, path: str) -> Optional[bytes]:
        """Fetch OWNER+DACL as a binary security descriptor over SMB2."""
        try:
            host, share, rest = split_unc(path)
        except ValueError:
            return None
        conn = self._connect(host)
        if conn is None:
            return None
        tree_id = self._tree(host, share)
        if tree_id is None:
            return None

        entry = self._stat(path)
        if entry is None:
            return None
        is_dir = entry == "SHARE_ROOT" or bool(entry.is_directory())

        smb = conn.getSMBServer()
        if not hasattr(smb, "queryInfo"):
            # PORT NOTE: SMB1 has no QUERY_INFO security class, so ACL-derived
            # findings are skipped against SMB1-only hosts.
            return None

        file_id = None
        try:
            file_id = smb.create(
                tree_id,
                rest or "",
                READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_DIRECTORY_FILE if is_dir else FILE_NON_DIRECTORY_FILE,
                FILE_OPEN,
                FILE_ATTRIBUTE_NORMAL,
            )
            return smb.queryInfo(
                tree_id,
                file_id,
                infoType=SMB2_0_INFO_SECURITY,
                fileInfoClass=0,
                additionalInformation=(
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
                ),
            )
        except Exception:
            # Access denied on READ_CONTROL is routine and not worth surfacing;
            # the original silently degrades the same way via
            # UnauthorizedAccessException in FsAclAnalyser.
            return None
        finally:
            if file_id is not None:
                try:
                    smb.close(tree_id, file_id)
                except Exception:
                    pass


class CompositeFsProvider(FsProvider):
    """Routes UNC paths to SMB and everything else to the local filesystem."""

    def __init__(self, smb: Optional[SmbFsProvider], local: Optional[LocalFsProvider] = None):
        self.smb = smb
        self.local = local or LocalFsProvider()

    def _pick(self, path: str) -> FsProvider:
        if is_unc(path) and self.smb is not None:
            return self.smb
        return self.local

    def file_exists(self, path: str) -> bool:
        return self._pick(path).file_exists(path)

    def dir_exists(self, path: str) -> bool:
        return self._pick(path).dir_exists(path)

    def read_file(self, path: str) -> bytes:
        return self._pick(path).read_file(path)

    def list_dir(self, path: str) -> List[str]:
        return self._pick(path).list_dir(path)

    def list_dirs(self, path: str) -> List[str]:
        return self._pick(path).list_dirs(path)

    def list_all_files(self, path: str) -> List[str]:
        return self._pick(path).list_all_files(path)

    def file_length(self, path: str) -> int:
        return self._pick(path).file_length(path)

    def get_security_descriptor(self, path: str) -> Optional[bytes]:
        return self._pick(path).get_security_descriptor(path)

    def close(self) -> None:
        if self.smb is not None:
            self.smb.close()


class NullFsProvider(FsProvider):
    """Provider that reports nothing, for unit tests and dry runs."""

    def file_exists(self, path: str) -> bool:
        return False

    def dir_exists(self, path: str) -> bool:
        return False

    def read_file(self, path: str) -> bytes:
        raise FileNotFoundError(path)

    def list_dir(self, path: str) -> List[str]:
        return []

    def list_dirs(self, path: str) -> List[str]:
        return []

    def list_all_files(self, path: str) -> List[str]:
        return []

    def file_length(self, path: str) -> int:
        return 0

    def get_security_descriptor(self, path: str) -> Optional[bytes]:
        return None
