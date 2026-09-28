"""Port of Group3r/Assessment/Analysers/Registry.cs

Two completely separate jobs live in this analyser: assessing the DACL/owner of a
registry key shipped in an .inf ("registry keys" section), and matching the key
and its values against the `RegKey` rules in AssessmentOptions.
"""

from typing import List, Optional

from ...classifiers.constants import Triage
from ...options.assessment_options import InterestingIf
from ...settings.registry_types import RegKeyValType
from ..finding import GpoFinding, SettingResult
from ..sddl_analyser import SddlAnalyser
from .analyser import Analyser


def _contains_ignore_case(haystack: str, needle: str) -> bool:
    """C# `haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0`.

    A null `needle` throws in C# (ArgumentNullException) and raises here
    (AttributeError), and a null `haystack` throws in both, so the failure modes
    line up.
    """
    return needle.lower() in haystack.lower()


def _utf8_string(value_bytes: bytes) -> Optional[str]:
    """C# `Encoding.UTF8.GetString(valueBytes, 0, valueBytes.Length)`.

    PORT NOTE: .NET substitutes U+FFFD for invalid sequences, which then makes
    Int32.TryParse fail and yield 0. Python's strict decoder raises instead, so an
    undecodable blob is reported as None -- which `_try_parse_int32` also turns
    into 0. Same outcome, no error-handler name needed.
    """
    try:
        return value_bytes.decode()
    except UnicodeDecodeError:
        return None


def _try_parse_int32(text: Optional[str]) -> int:
    """C# `Int32.TryParse(text, out dword)`: `dword` is 0 when the parse fails.

    PORT NOTE: .NET Framework's number parser ignores an embedded NUL character
    and everything after it, so `Int32.TryParse("1\\0")` succeeds with 1. (.NET
    Core 3.0+ dropped that tolerance, but Group3r targets .NET Framework 4.5.1
    and the mono reference behaves the same way.) This matters here because
    GptTmpl.inf DWORD values arrive as UTF-16 bytes -- "1" is `31 00` -- which
    `_utf8_string` decodes to "1\\0". Without truncating at the NUL, every
    REG_DWORD rule would compare against 0 and the non-default findings would
    silently disappear.
    """
    if text is None:
        return 0
    text = text.split("\x00", 1)[0]
    try:
        value = int(text.strip())
    except (AttributeError, TypeError, ValueError):
        return 0
    if value < -2147483648 or value > 2147483647:
        return 0
    return value


class RegistryAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.RegistryAnalyser."""

    def __init__(self, setting=None):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of RegistryAnalyser.Analyse."""
        setting = self.setting
        findings: List[GpoFinding] = []

        # sometimes it'll be about the permissions on the reg key
        if setting.parsed_key_sddl is not None:
            sddl_analyser = SddlAnalyser(assessment_options)

            simple_acl = sddl_analyser.analyse_sddl(setting.parsed_key_sddl)
            if len(simple_acl) > 0:
                if self.min_triage < Triage.Red:
                    gpo_finding = GpoFinding(
                        acl_result=simple_acl,
                        finding_reason="Found some interesting ACEs on a registry key, probably because someone was being given control of it.",
                        finding_detail="You'll need to take a closer look at this key to know if this has any value at all. Good luck.",
                        triage=Triage.Green,
                    )
                    findings.append(gpo_finding)
            # ok who's the owner?
            if setting.parsed_key_sddl.owner is not None:
                for trustee in assessment_options.trustee_options:
                    if (setting.parsed_key_sddl.owner.alias == trustee.display_name) and (
                        not trustee.high_priv
                    ):
                        # TODO do proper sid comparisons or something fuck
                        if self.min_triage < Triage.Black:
                            findings.append(
                                GpoFinding(
                                    finding_reason="The "
                                    + trustee.display_name
                                    + " trustee has been made owner of this registry key.",
                                    finding_detail="You'll need to take a closer look at this key to know if this has any value at all. Good luck.",
                                    triage=Triage.Green,
                                )
                            )
                        break
            # ok who got permissions then
            for ace in setting.parsed_key_sddl.dacl.aces:
                # deny settings aren't super interesting
                if ace.ace_type == "ACCESS_ALLOWED":
                    key_writable = False
                    for right in ace.rights:
                        # check if the right being assigned is one that allows interesting access
                        if right == "KEY_ALL" or right == "KEY_WRITE":
                            key_writable = True

                    for trustee in assessment_options.trustee_options:
                        if ace.ace_sid.alias == trustee.display_name:
                            if trustee.high_priv:
                                # we don't care if a high priv user has a privilege, that's boring.
                                break

                            if trustee.low_priv and key_writable:
                                if self.min_triage < Triage.Black:
                                    findings.append(
                                        GpoFinding(
                                            finding_reason="The "
                                            + trustee.display_name
                                            + " trustee has been granted rights to modify this registry key.",
                                            finding_detail="You'll need to take a closer look at this key to know if this has any value at all. Good luck.",
                                            triage=Triage.Yellow,
                                        )
                                    )
                            if trustee.low_priv:
                                if self.min_triage < Triage.Red:
                                    findings.append(
                                        GpoFinding(
                                            finding_reason="The "
                                            + trustee.display_name
                                            + " trustee has been granted additional rights over this registry key.",
                                            finding_detail="You'll need to take a closer look at this key to know if this has any value at all. Good luck.",
                                            triage=Triage.Green,
                                        )
                                    )
                                break

        # other times it'll be about the value(s)
        for rule_key in assessment_options.reg_keys:
            if _contains_ignore_case(setting.key, rule_key.key):
                # this is a potentially interesting key
                for reg_value in setting.values:
                    # figure out the basis on which the ruleKey is considered 'interesting' and act accordingly.
                    if rule_key.interesting_if == InterestingIf.Present:
                        # some of these won't have a value name at all, only the key.
                        # That's fine, sometimes we're just looking for the presence of a key and the subkeys don't even matter.
                        if (rule_key.value_name is None) or _contains_ignore_case(
                            reg_value.value_name, rule_key.value_name
                        ):
                            if self.min_triage < rule_key.triage:
                                findings.append(
                                    GpoFinding(
                                        finding_reason="This registry key being present at all is considered interesting.",
                                        finding_detail=rule_key.friendly_description
                                        + " "
                                        + rule_key.ms_desc,
                                        triage=rule_key.triage,
                                    )
                                )
                    elif rule_key.interesting_if == InterestingIf.Bad:
                        # these will have to be precise matches
                        if _contains_ignore_case(
                            reg_value.value_name, rule_key.value_name
                        ):
                            interesting = False
                            if rule_key.value_type == RegKeyValType.REG_DWORD:
                                dword = _try_parse_int32(
                                    _utf8_string(reg_value.value_bytes)
                                )
                                interesting = self.is_interesting_because_bad_dword(
                                    rule_key.bad_dword, dword
                                )
                            elif rule_key.value_type == RegKeyValType.REG_BINARY:
                                interesting = self.is_interesting_because_bad_binary(
                                    rule_key.bad_binary, reg_value.value_bytes
                                )
                            elif rule_key.value_type == RegKeyValType.REG_SZ:
                                interesting = self.is_interesting_because_bad_sz(
                                    rule_key.bad_sz, reg_value.value_string
                                )
                            else:
                                raise NotImplementedError(
                                    "No code to handle rules around "
                                    + rule_key.value_type.name
                                    + " keys."
                                )

                            if interesting:
                                if self.min_triage < rule_key.triage:
                                    findings.append(
                                        GpoFinding(
                                            finding_reason="This registry key was found to match a known-vulnerable value.",
                                            finding_detail=rule_key.friendly_description
                                            + " "
                                            + rule_key.ms_desc,
                                            triage=rule_key.triage,
                                        )
                                    )
                    elif rule_key.interesting_if == InterestingIf.NotDefault:
                        if _contains_ignore_case(
                            reg_value.value_name, rule_key.value_name
                        ):
                            interesting = False
                            if rule_key.value_type == RegKeyValType.REG_DWORD:
                                dword = _try_parse_int32(
                                    _utf8_string(reg_value.value_bytes)
                                )
                                interesting = (
                                    self.is_interesting_because_not_default_dword(
                                        rule_key.default_dword, dword
                                    )
                                )
                            elif rule_key.value_type == RegKeyValType.REG_BINARY:
                                interesting = (
                                    self.is_interesting_because_not_default_binary(
                                        rule_key.default_binary, reg_value.value_bytes
                                    )
                                )
                            elif rule_key.value_type == RegKeyValType.REG_SZ:
                                interesting = (
                                    self.is_interesting_because_not_default_sz(
                                        rule_key.default_sz, reg_value.value_string
                                    )
                                )
                            else:
                                raise NotImplementedError(
                                    "No code to handle rules around "
                                    + rule_key.value_type.name
                                    + " keys."
                                )
                            if interesting:
                                if self.min_triage < rule_key.triage:
                                    findings.append(
                                        GpoFinding(
                                            finding_reason="This registry key was set to a non-default value, which was interesting enough for me.",
                                            finding_detail=rule_key.friendly_description
                                            + " "
                                            + rule_key.ms_desc,
                                            triage=rule_key.triage,
                                        )
                                    )
                    elif rule_key.interesting_if == InterestingIf.NotGood:
                        if _contains_ignore_case(
                            reg_value.value_name, rule_key.value_name
                        ):
                            interesting = False
                            if rule_key.value_type == RegKeyValType.REG_DWORD:
                                dword = _try_parse_int32(
                                    _utf8_string(reg_value.value_bytes)
                                )
                                # NOTE: the original calls the NotDefault comparison here, not
                                # the NotGood one. Preserved, bug and all.
                                interesting = (
                                    self.is_interesting_because_not_default_dword(
                                        rule_key.good_dword, dword
                                    )
                                )
                            elif rule_key.value_type == RegKeyValType.REG_BINARY:
                                interesting = (
                                    self.is_interesting_because_not_default_binary(
                                        rule_key.good_binary, reg_value.value_bytes
                                    )
                                )
                            elif rule_key.value_type == RegKeyValType.REG_SZ:
                                interesting = (
                                    self.is_interesting_because_not_default_sz(
                                        rule_key.good_sz, reg_value.value_string
                                    )
                                )
                            else:
                                raise NotImplementedError(
                                    "No code to handle rules around "
                                    + rule_key.value_type.name
                                    + " keys."
                                )
                            if interesting:
                                if self.min_triage < rule_key.triage:
                                    findings.append(
                                        GpoFinding(
                                            finding_reason="This registry key was set to a non-default value, which was interesting enough for me.",
                                            finding_detail=rule_key.friendly_description
                                            + " "
                                            + rule_key.ms_desc,
                                            triage=rule_key.triage,
                                        )
                                    )
                    elif rule_key.interesting_if == InterestingIf.LessThanGood:
                        if _contains_ignore_case(
                            reg_value.value_name, rule_key.value_name
                        ):
                            interesting = False
                            if rule_key.value_type == RegKeyValType.REG_DWORD:
                                dword = _try_parse_int32(
                                    _utf8_string(reg_value.value_bytes)
                                )
                                interesting = (
                                    self.is_interesting_because_less_than_good(
                                        rule_key.good_dword, dword
                                    )
                                )
                            else:
                                raise NotImplementedError(
                                    "No code to handle rules around "
                                    + rule_key.value_type.name
                                    + " keys."
                                )
                            if interesting:
                                if self.min_triage < rule_key.triage:
                                    findings.append(
                                        GpoFinding(
                                            finding_reason="This registry key was set to a 'less-than-good' value, which made it interesting.",
                                            finding_detail=rule_key.friendly_description
                                            + " "
                                            + rule_key.ms_desc,
                                            triage=rule_key.triage,
                                        )
                                    )

        # put findings in settingResult
        self.setting_result.findings = findings

        # make a new setting object minus the ugly bits we don't care about.
        self.setting_result.setting = setting

        return self.setting_result

    # The C# has one overload set per value type; Python has no overload
    # resolution, so each overload becomes a distinctly named method and the call
    # sites pick the one the C# compiler would have picked from the declared type
    # of the RegKey field being compared.

    def is_interesting_because_less_than_good(
        self, good_val: int, setting_val: int
    ) -> bool:
        if setting_val < good_val:
            return True
        return False

    def is_interesting_because_not_default_dword(
        self, default_val: int, setting_val: int
    ) -> bool:
        if default_val != setting_val:
            return True
        return False

    def is_interesting_because_not_default_sz(
        self, default_val: str, setting_val: str
    ) -> bool:
        if default_val != setting_val:
            return True
        return False

    def is_interesting_because_not_default_binary(
        self, default_val: bytes, setting_val: bytes
    ) -> bool:
        # PORT NOTE: `byte[] != byte[]` in C# is *reference* inequality, not a
        # content comparison, so this overload is true for any two distinct
        # arrays. `is not` reproduces that exactly; `!=` would not.
        if default_val is not setting_val:
            return True
        return False

    def is_interesting_because_not_good_dword(
        self, good_val: int, setting_val: int
    ) -> bool:
        if good_val != setting_val:
            return True
        return False

    def is_interesting_because_not_good_sz(
        self, good_val: str, setting_val: str
    ) -> bool:
        if good_val != setting_val:
            return True
        return False

    def is_interesting_because_not_good_binary(
        self, good_val: bytes, setting_val: bytes
    ) -> bool:
        # PORT NOTE: reference comparison in the original, see above.
        if good_val is not setting_val:
            return True
        return False

    def is_interesting_because_bad_dword(self, bad_val: int, setting_val: int) -> bool:
        if bad_val == setting_val:
            return True
        return False

    def is_interesting_because_bad_sz(self, bad_val: str, setting_val: str) -> bool:
        if bad_val == setting_val:
            return True
        return False

    def is_interesting_because_bad_binary(
        self, bad_val: bytes, setting_val: bytes
    ) -> bool:
        # PORT NOTE: reference comparison in the original, so this is only ever
        # true when both sides are literally the same object (or both null).
        if bad_val is setting_val:
            return True
        return False
