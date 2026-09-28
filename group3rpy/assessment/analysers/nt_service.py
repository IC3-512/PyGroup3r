"""Port of Group3r/Assessment/Analysers/NtService.cs

Looks for two things: a service DACL that hands abusable rights to a trustee we
care about, and a GPP cpassword on the service's logon account.
"""

from typing import List

from ...classifiers.constants import Triage
from ...options.assessment_options import TrusteeOption
from ...settings import NtServiceSetting
from ..finding import ACEType, GpoFinding, SettingResult
from ..sddl_analyser import SddlAnalyser
from .analyser import Analyser


class NtServiceAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.NtServiceAnalyser."""

    def __init__(self, setting):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of NtServiceAnalyser.Analyse."""
        findings: List[GpoFinding] = []

        mod_rights: List[str] = ["WRITE_DAC", "WRITE_OWNER", "SERVICE_CHANGE_CONFIG"]

        if self.setting.parsed_sddl is not None:
            # Parse the SDDL into a workable format
            analysed_sddl = SddlAnalyser(assessment_options).analyse_sddl(
                self.setting.parsed_sddl
            )

            for simple_ace in analysed_sddl:
                grants_write = False
                deny_right = False

                for right in simple_ace.rights:
                    if right in mod_rights:
                        grants_write = True

                # check if it's allow or deny
                if simple_ace.ace_type == ACEType.Deny:
                    deny_right = True

                if deny_right:
                    continue  # TODO actually handle deny rights properly

                match = TrusteeOption()
                # see if the trustee is a users/group we know about.
                if simple_ace.trustee.display_name is not None:
                    name_matches = [
                        trusteeopt
                        for trusteeopt in assessment_options.trustee_options
                        if trusteeopt.display_name == simple_ace.trustee.display_name
                    ]
                    if len(name_matches) > 0:
                        match = name_matches[0]
                if simple_ace.trustee.sid is not None:
                    sid_matches = [
                        trusteeopt
                        for trusteeopt in assessment_options.trustee_options
                        if trusteeopt.sid == simple_ace.trustee.sid
                    ]
                    if len(sid_matches) > 0:
                        match = sid_matches[0]

                if match.display_name is not None:
                    # check if it's one of the aggravating principals that are both
                    # local and domain and windows struggles to distinguish between:
                    if (
                        match.display_name == "Administrators"
                        or match.display_name == "Administrator"
                        or match.display_name == "SYSTEM"
                        or match.display_name == "Local System"
                    ):
                        continue

                    # so if it's a user/group that we know about...
                    if match.target or match.low_priv:

                        # and it's either canonically low-priv or we are a member of it
                        if grants_write:
                            findings.append(
                                GpoFinding(
                                    finding_reason=(
                                        "A Windows service's ACL is being configured to "
                                        "grant abusable permissions to a target trustee."
                                    ),
                                    finding_detail=(
                                        "This should allow local privilege escalation on "
                                        "affected hosts. Service: "
                                    )
                                    + self.setting.service_name.replace("\\", "").replace(
                                        '"', ""
                                    )
                                    + ", Trustee: "
                                    + match.display_name
                                    + " - "
                                    + match.sid,
                                    triage=Triage.Red,
                                )
                            )

        if not (self.setting.cpassword is None or not self.setting.cpassword.strip()):
            password = self.setting.decrypt_cpassword(self.setting.cpassword)
            self.setting.password = password
            findings.append(
                GpoFinding(
                    finding_reason="Group Policy Preferences password found:" + password,
                    finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                    triage=Triage.Black,
                )
            )

        # put findings in settingResult
        self.setting_result.findings = findings

        # make a new setting object minus the ugly bits we don't care about.
        self.setting_result.setting = NtServiceSetting()

        if "NTFRS" in self.setting.source:
            self.setting.is_morphed = True

        self.setting_result.setting = self.setting

        return self.setting_result
