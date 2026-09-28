"""Port of Group3r/Assessment/Analysers/Group.cs

PORT NOTE: the LINQ `TrusteeOptions.Where(...).First()` calls become `next()` over
a generator; `First()` on an empty sequence throws InvalidOperationException in
C#, and `next()` raises StopIteration here, which is what the `except` clauses
below key off (the inner block swallows exactly that case, as the original does).

PORT NOTE: `(int)MinTriage < 4` is ported as `self.min_triage < 4` -- there is no
Triage member with ordinal 4, so the guard is always true in the original.
"""

from typing import List, Optional

from ...ad.gpo import SettingAction
from ...classifiers.constants import Triage
from ...options.assessment_options import TrusteeOption
from ..finding import GpoFinding, SettingResult
from .analyser import Analyser


def _equals_ignore_case(left: str, right: Optional[str]) -> bool:
    """C# `left.Equals(right, StringComparison.OrdinalIgnoreCase)`.

    A null `right` is simply not equal; a null `left` throws in C# and raises
    AttributeError here, which the callers' `except` clauses handle the same way
    the original's `catch` clauses do.
    """
    if right is None:
        return False
    return left.lower() == right.lower()


class GroupAnalyser(Analyser):
    """Port of Group3r.Assessment.Analysers.GroupAnalyser."""

    def __init__(self, setting=None):
        super().__init__(setting)

    def analyse(self, assessment_options) -> SettingResult:
        """Port of GroupAnalyser.Analyse."""
        setting = self.setting

        findings: List[GpoFinding] = []

        # If we're deleting all users that doesn't give us access
        # If they're deleting all groups that doesn't give us access
        # If 'removeaccounts' - that doesn't give us access.
        # If the group name is a privileged one and they're renaming it - green finding
        # if the group name is a privileged one and they're adding a big group or a group we're in - red finding
        # if the group name is administrators and they're adding a big group or a group we're in, black finding

        group = TrusteeOption()

        try:
            if setting.name.startswith("S-"):
                group = next(
                    trustee_option
                    for trustee_option in assessment_options.trustee_options
                    if _equals_ignore_case(trustee_option.sid, setting.name)
                )
            elif (setting.group_sid is not None) and setting.group_sid.startswith("S-"):
                group = next(
                    trustee_option
                    for trustee_option in assessment_options.trustee_options
                    if _equals_ignore_case(trustee_option.sid, setting.group_sid)
                )
            else:
                group = next(
                    trustee_option
                    for trustee_option in assessment_options.trustee_options
                    if _equals_ignore_case(trustee_option.display_name, setting.name)
                )
        except Exception as e:
            # PORT NOTE: C# logs `e.ToString()`, which includes the exception type
            # and stack trace; `repr(e)` is the closest Python equivalent.
            self.mq.trace(
                "Group "
                + setting.name
                + " threw an error trying to match it to a well known name or well known sid."
                + repr(e)
            )
            group.display_name = setting.name

        # if it's not one of these it's not a finding
        if (
            (setting.action == SettingAction.Add)
            or (setting.action == SettingAction.Update)
            or (setting.action == SettingAction.Create)
        ):
            # if any of these are true, it's not a finding
            if (
                (setting.delete_all_groups is False)
                and (setting.delete_all_users is False)
                and (setting.remove_accounts is False)
            ):
                #
                if setting.new_name and group.high_priv:
                    if self.min_triage < Triage.Red:
                        findings.append(
                            GpoFinding(
                                # GpoSetting = setting,
                                finding_reason="A privileged local group is being renamed.",
                                finding_detail="Group "
                                + group.display_name
                                + " is being renamed to "
                                + setting.new_name,
                                triage=Triage.Green,
                            )
                        )
                # if there's no members, who cares?
                if len(setting.members) > 0:
                    for gs_member in setting.members:
                        to_member = TrusteeOption()
                        try:
                            if gs_member.name.startswith("S-"):
                                to_member = next(
                                    trustee_option
                                    for trustee_option in assessment_options.trustee_options
                                    if _equals_ignore_case(
                                        trustee_option.sid, gs_member.name
                                    )
                                )
                            else:
                                to_member = next(
                                    trustee_option
                                    for trustee_option in assessment_options.trustee_options
                                    if _equals_ignore_case(
                                        trustee_option.display_name, gs_member.name
                                    )
                                )
                        except StopIteration:
                            # Mq.Trace("User didn't parse to a well known name or well known sid")
                            pass
                        except Exception as e:
                            self.mq.trace(
                                "Something else went fucky with parsing "
                                + gs_member.name
                            )
                        # if it's a high priv group and we're adding a low priv trustee, that's a red
                        alreadyred = False
                        if to_member.low_priv and group.high_priv:
                            alreadyred = True
                            if self.min_triage < 4:
                                findings.append(
                                    GpoFinding(
                                        # GpoSetting = setting,
                                        finding_reason="A privileged local group is having a low-priv member added to it.",
                                        finding_detail="Group "
                                        + group.display_name
                                        + " is having "
                                        + to_member.display_name
                                        + " added to it.",
                                        triage=Triage.Red,
                                    )
                                )

                        # if it's a high priv group and we're adding any other trustee, that's a yellow
                        # we do !toMember.HighPriv because we need it to work whether toMember is resolved to a well known sid or not..
                        if group.high_priv and not to_member.high_priv and not alreadyred:
                            if self.min_triage < Triage.Red:
                                findings.append(
                                    GpoFinding(
                                        # GpoSetting = setting,
                                        finding_reason="A privileged local group is having a member added to it. Might be interesting, hard to say.",
                                        finding_detail="Group "
                                        + group.display_name
                                        + " is having "
                                        + gs_member.name
                                        + " added to it.",
                                        triage=Triage.Green,
                                    )
                                )

        # put findings in settingResult
        self.setting_result.findings = findings

        if "NTFRS" in setting.source:
            setting.is_morphed = True

        self.setting_result.setting = setting

        return self.setting_result
