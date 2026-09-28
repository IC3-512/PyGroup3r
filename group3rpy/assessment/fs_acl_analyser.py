"""Port of Group3r/Assessment/FsAclAnalyser.cs

Decides whether the target user can write to or modify a path, by parsing the
path's security descriptor and matching each ACE's trustee against the known
TrusteeOption set.

PORT NOTE: the original takes a `FileSystemInfo` and calls
`Directory/File.GetAccessControl(...Owner | Access)` to get an SDDL string. Here
the security descriptor is fetched as binary over SMB via
`assessment_options.fs.get_security_descriptor(path)` and converted through
`group3rpy.sddl`, so the resulting right names are identical. The caller passes
`is_dir` explicitly, replacing the C# runtime type test on FileInfo vs
DirectoryInfo.
"""

from typing import List, Optional

from ..sddl.sddl import SecurableObjectType, sddl_from_binary
from .finding import ACEType, FsAclResult, RwStatus, SimpleAce
from .sddl_analyser import SddlAnalyser


class AllowDeny:
    """Port of Group3r.Assessment.AllowDeny."""

    Unset = "Unset"
    Allow = "Allow"
    Deny = "Deny"


class FsAclAnalyser:
    """Port of Group3r.Assessment.FsAclAnalyser."""

    # Verbatim from the C# field initialisers.
    READ_RIGHTS = ["Read", "ReadAndExecute", "ReadData", "ListDirectory"]
    WRITE_RIGHTS = [
        "CREATE_LINK",
        "WRITE",
        "WRITE_OWNER",
        "WRITE_DAC",
        "APPEND_DATA",
        "WRITE_DATA",
        "CREATE_CHILD",
        "FILE_WRITE",
        "ADD_FILE",
        "ADD_SUBDIRECTORY",
        "Owner",
    ]
    MODIFY_RIGHTS = [
        "STANDARD_RIGHTS_ALL",
        "STANDARD_DELETE",
        "DELETE_TREE",
        "FILE_ALL",
        "GENERIC_ALL",
        "GENERIC_WRITE",
        "WRITE_OWNER",
        "WRITE_DAC",
        "Owner",
        "DELETE_CHILD",
    ]

    def __init__(self, assessment_options):
        self.assessment_options = assessment_options
        self.sddl_analyser = SddlAnalyser(assessment_options)

    def analyse_fs_acl(self, path: str, is_dir: bool) -> FsAclResult:
        """Port of FsAclAnalyser.AnalyseFsAcl."""
        # The original hard-codes this local to false, shadowing
        # AssessmentOptions.SuckItAndSee, so the "suck it and see" branch below is
        # dead code upstream. Preserved, and still unreachable.
        suck_it_and_see = False
        rw_status = RwStatus(exists=False, can_read=False, can_modify=False, can_write=False)

        if suck_it_and_see:  # pragma: no cover - dead in the original too
            return self._suck_it_and_see(path, is_dir, rw_status)

        if self.assessment_options.trustee_options is None:
            raise ValueError(
                "If you aren't running in 'suck it and see' mode, the TargetTrustees "
                "option needs to be populated somehow."
            )

        fs = getattr(self.assessment_options, "fs", None)
        if fs is None:
            return FsAclResult(rw_status=rw_status)

        # first we check if the thing even exists and we can look at it.
        parsed_sddl = None
        if is_dir:
            if fs.dir_exists(path):
                rw_status.exists = True
                raw = fs.get_security_descriptor(path)
                if raw:
                    parsed_sddl = sddl_from_binary(raw, SecurableObjectType.Directory)
        else:
            if fs.file_exists(path):
                rw_status.exists = True
                raw = fs.get_security_descriptor(path)
                if raw:
                    parsed_sddl = sddl_from_binary(raw, SecurableObjectType.File)

        # if it doesn't exist then might as well bail out now.
        if not rw_status.exists:
            return FsAclResult(rw_status=rw_status)

        if parsed_sddl is None:
            # PORT NOTE: the original throws "File/Folder ACL not read/parsed
            # properly." here. Over SMB, a denied READ_CONTROL is routine rather
            # than exceptional -- the original reaches the same outcome through
            # its UnauthorizedAccessException catch, which returns a bare
            # FsAclResult with the existing rwStatus -- so we return that instead
            # of raising, which keeps a single unreadable ACL from aborting the
            # whole GPO.
            return FsAclResult(rw_status=rw_status)

        fs_acl_result = FsAclResult()

        # Parse the SDDL into a workable format
        analysed_sddl = self.sddl_analyser.analyse_sddl(parsed_sddl)

        for simple_ace in analysed_sddl:
            grants_write = False
            grants_modify = False
            deny_right = False

            # see if any of the rights are interesting
            for right in simple_ace.rights:
                if right in self.WRITE_RIGHTS:
                    grants_write = True
                if right in self.MODIFY_RIGHTS:
                    grants_modify = True

            # check if it's allow or deny
            if simple_ace.ace_type == ACEType.Deny:
                deny_right = True

            if deny_right:
                continue  # TODO actually handle deny rights properly

            match = None
            # see if the trustee is a users/group we know about.
            if simple_ace.trustee is not None and simple_ace.trustee.display_name is not None:
                name_matches = [
                    t
                    for t in self.assessment_options.trustee_options
                    if t.display_name == simple_ace.trustee.display_name
                ]
                if name_matches:
                    match = name_matches[0]
            if simple_ace.trustee is not None and simple_ace.trustee.sid is not None:
                sid_matches = [
                    t
                    for t in self.assessment_options.trustee_options
                    if t.sid == simple_ace.trustee.sid
                ]
                if sid_matches:
                    match = sid_matches[0]

            if match is not None and match.display_name is not None:
                # check if it's one of the aggravating principals that are both
                # local and domain and windows struggles to distinguish between:
                if match.display_name in (
                    "Administrators",
                    "Administrator",
                    "SYSTEM",
                    "Local System",
                ):
                    continue
                # so if it's a user/group that we know about...
                if match.target or match.low_priv:
                    # and it's either canonically low-priv or we are a member of it
                    # set rwStatus based on it.
                    if grants_modify:
                        rw_status.can_modify = True
                    if grants_write:
                        rw_status.can_write = True
                    if grants_modify or grants_write:
                        fs_acl_result.interesting_aces.append(simple_ace)
                elif not match.high_priv:
                    fs_acl_result.interesting_aces.append(simple_ace)
                    if grants_modify or grants_write:
                        # NOTE: the original appends the same ACE a second time
                        # here. Preserved -- it is observable in the ACE list.
                        fs_acl_result.interesting_aces.append(simple_ace)
            else:
                # otherwise there's no match.
                if grants_modify or grants_write:
                    fs_acl_result.interesting_aces.append(simple_ace)

        fs_acl_result.rw_status = rw_status
        return fs_acl_result

    def _suck_it_and_see(self, path: str, is_dir: bool, rw_status: RwStatus) -> FsAclResult:
        """Port of the `suckItAndSee` branch.

        Unreachable in the original because the local flag is hard-coded false;
        kept for completeness. It would probe access by attempting writes, which
        this port deliberately does not do over SMB without an explicit opt-in.
        """
        raise NotImplementedError(
            "suckItAndSee is dead code in the original (local flag hard-coded false)"
        )


class FileRight:
    """Port of Group3r.Assessment.FileRight (unused upstream)."""

    def __init__(self):
        self.right_name: Optional[str] = None
        self.read_right = False
        self.write_right = False
        self.modify_right = False
        self.allow_deny = AllowDeny.Unset
