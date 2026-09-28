"""Port of Group3r/Options/AssessmentOptions/AssessmentOptions.cs

The C# original is a `partial class` whose loader methods are spread over
AssessmentOptions.cs, PrivRights.cs, Trustees.cs, RegKeys.cs and
FileExtensions.cs. Python has no partial classes, so each of those files is
ported to its own module exposing a module-level `load_*()` function, and the
methods here delegate to them. The construction order in `__init__` is
identical to the C# constructor.
"""

from dataclasses import dataclass
from enum import Enum

from group3rpy.classifiers.constants import Triage
from group3rpy.settings.registry_types import RegHive, RegKeyValType


@dataclass
class PrivRightOption:
    """Port of C# `PrivRightOption`."""

    priv_right_name: str | None = None
    grants_remote_access: bool = False
    remote_access_desc: str | None = None
    local_privesc: bool = False
    local_privesc_desc: str | None = None
    ms_description: str | None = None


@dataclass
class TrusteeOption:
    """Port of C# `TrusteeOption`."""

    sid: str | None = None
    display_name: str | None = None
    description: str | None = None
    domain_sid: bool = False  # is this the sid of a domain group/account?
    local_sid: bool = False  # is this the sid of a local group/account?
    # is this group/account canonically high-priv, i.e. do they have well-known
    # paths to get local Admin/Domain Admin by default?
    high_priv: bool = False
    # is this group/account canonically low-priv, i.e. are they one of the
    # massive default groups like Domain Users etc.
    low_priv: bool = False
    target: bool = False


class InterestingIf(Enum):
    """Port of C# `enum InterestingIf` - implicit ordinals 0..4."""

    Present = 0
    Bad = 1
    NotGood = 2
    NotDefault = 3
    LessThanGood = 4


@dataclass
class RegKey:
    """Port of C# `RegKey`.

    Defaults mirror C# field defaults: `null` for reference types (str/bytes),
    `0` for `int`, and the zero-valued enum member for enums - which means
    `RegHive.HKEY_CLASSES_ROOT`, `RegKeyValType.REG_NONE`,
    `InterestingIf.Present` and `Triage.Green`.
    """

    ms_desc: str | None = None
    friendly_description: str | None = None
    reg_hive: RegHive = RegHive.HKEY_CLASSES_ROOT
    key: str | None = None
    value_name: str | None = None
    value_type: RegKeyValType = RegKeyValType.REG_NONE
    interesting_if: InterestingIf = InterestingIf.Present
    default_binary: bytes | None = None
    default_dword: int = 0
    default_sz: str | None = None
    good_binary: bytes | None = None
    good_sz: str | None = None
    good_dword: int = 0
    bad_binary: bytes | None = None
    bad_sz: str | None = None
    bad_dword: int = 0
    triage: Triage = Triage.Green


# Verbatim port of the C# `InterestingRights` initialiser. "CREATE_CHILD" and
# "SET_VALUE" genuinely appear twice in the original; the duplicates are kept.
INTERESTING_RIGHTS: list[str] = [
    "Owner",
    "CREATE_CHILD",
    "GENERIC_WRITE",
    "GENERIC_ALL",
    "WRITE_ATTRIBUTES",
    "WRITE_PROPERTIES",
    "WRITE_PROPERTY",
    "APPEND_DATA",
    "WRITE_DATA",
    "ALL_ACCESS",
    "DELETE_CHILD",
    "CREATE_CHILD",
    "WRITE_TREE",
    "FILE_WRITE",
    "FILE_ALL",
    "KEY_WRITE",
    "KEY_ALL",
    "STANDARD_RIGHTS_ALL",
    "STANDARD_DELETE",
    "DELETE_TREE",
    "ADD_FILE",
    "ADD_SUBDIRECTORY",
    "CREATE_PIPE_INSTANCE",
    "WRITE",
    "CREATE_LINK",
    "SET_VALUE",
    "WRITE_DAC",
    "WRITE_OWNER",
    "SET_VALUE",
]


class AssessmentOptions:
    """Port of C# `public partial class AssessmentOptions`."""

    def __init__(self):
        self.priv_rights: list[PrivRightOption] = []
        self.trustee_options: list[TrusteeOption] = []
        self.suck_it_and_see: bool = False
        # C# leaves TargetTrustees null until the options parser fills it in, and
        # GroupCon.cs explicitly tests `TargetTrustees != null`, so the initial
        # value must be None rather than an empty list.
        self.target_trustees: list[TrusteeOption] | None = None
        self.reg_keys: list[RegKey] = []
        # C# spelling: `ExeAndScriptExtentions`. Kept misspelled on purpose.
        self.exe_and_script_extentions: list[str] = []
        self.config_file_extensions: list[str] = []
        self.office_macro_extensions: list[str] = []
        self.classifier_options = None
        self.min_triage: Triage = Triage.Green
        self.interesting_rights: list[str] = list(INTERESTING_RIGHTS)
        # PORT NOTE: the C# original reaches the Windows filesystem directly.
        # The Python port takes its sysvol/UNC filesystem from this injected
        # FsProvider (group3rpy/smb/provider.py). See CONVENTIONS.md.
        self.fs = None

        # create default snaffler rules
        # PORT NOTE: imported defensively so that this module still imports
        # standalone while the classifier rules port lands.
        try:
            from group3rpy.classifiers.classifier_options import ClassifierOptions
            from group3rpy.classifiers.rules.classifier_rules import ClassifierRules

            self.classifier_options = ClassifierOptions(all_rules=ClassifierRules())
            self.classifier_options.all_rules.build_default_classifiers()
            self.classifier_options.all_rules.prepare_classifiers()
        except ImportError:  # PORT NOTE: remove once the classifier port exists.
            self.classifier_options = None

        self.load_priv_rights()
        self.load_trustee_options()
        self.load_reg_keys()
        self.load_exe_and_script_extensions()
        self.load_config_file_extensions()
        self.load_office_macro_extensions()

    # --- PrivRights.cs ---
    def load_priv_rights(self) -> None:
        from group3rpy.options.priv_rights import load_priv_rights

        self.priv_rights = load_priv_rights()

    # --- Trustees.cs ---
    def load_trustee_options(self) -> None:
        from group3rpy.options.trustees import load_trustee_options

        self.trustee_options = load_trustee_options()

    # --- RegKeys.cs ---
    def load_reg_keys(self) -> None:
        from group3rpy.options.reg_keys import load_reg_keys

        self.reg_keys = load_reg_keys()

    # --- FileExtensions.cs ---
    def load_exe_and_script_extensions(self) -> None:
        from group3rpy.options.file_extensions import load_exe_and_script_extensions

        self.exe_and_script_extentions = load_exe_and_script_extensions()

    def load_config_file_extensions(self) -> None:
        from group3rpy.options.file_extensions import load_config_file_extensions

        self.config_file_extensions = load_config_file_extensions()

    def load_office_macro_extensions(self) -> None:
        from group3rpy.options.file_extensions import load_office_macro_extensions

        self.office_macro_extensions = load_office_macro_extensions()


# """
# "interestingWords": [
# "nattend.xml",
# "passw",
# "kdb",
# "putty.config",
# "winscp.ini",
# "id_rsa",
# "id_dsa",
# "web.config",
# "ppk",
# "ssh",
# "rdp",
# "cred",
# "-p ",
# "/u ",
# "psexec",
# "net user",
# "key",
# "vnc",
# "vpn",
# "powershell",
# "cmd",
# "/c ",
# "path",
# "-command"
# ]
# }
# """
