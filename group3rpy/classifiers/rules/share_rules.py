"""Port of LibSnaffle/Classifiers/Rules/ShareRules.cs

The C# file is one half of the `partial class ClassifierRules`; in Python it is
a mixin that `ClassifierRules` inherits, so `_build_share_rules` appends to
`self.all_classifier_rules` exactly like `BuildShareRules()` appends to
`AllClassifierRules`.
"""

from group3rpy.classifiers.constants import (
    EnumerationScope,
    MatchAction,
    MatchListType,
    MatchLoc,
    Triage,
)
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule


class ShareRulesMixin:
    """Port of the BuildShareRules() half of ClassifierRules."""

    def _build_share_rules(self) -> None:
        self.all_classifier_rules.append(
            ClassifierRule(
                rule_name="DiscardShareEndsWith",
                description="Skips scanning inside shares ending with these words.",
                enumeration_scope=EnumerationScope.ShareEnumeration,
                match_location=MatchLoc.ShareName,
                match_action=MatchAction.Discard,
                word_list_type=MatchListType.EndsWith,
                word_list=[
                    "\\print$",
                    "\\ipc$",
                ],
            )
        )
        self.all_classifier_rules.append(
            ClassifierRule(
                rule_name="KeepShareBlack",
                description=(
                    "Notifies the user that they can read C$ or ADMIN$ or something "
                    "fun/noisy, but doesn't actually scan inside it."
                ),
                enumeration_scope=EnumerationScope.ShareEnumeration,
                match_location=MatchLoc.ShareName,
                match_action=MatchAction.Snaffle,
                word_list_type=MatchListType.EndsWith,
                triage=Triage.Black,
                word_list=[
                    "\\C$",
                    "\\ADMIN$",
                ],
            )
        )
        # """
        # this.ClassifierRules.Add(new ClassifierRule()
        # {
        #     RuleName = "KeepShareRed",
        #     Description = "Notifies the user that they can read C$ or ADMIN$ or something fun/noisy, but doesn't actually scan inside it.",
        #     EnumerationScope = EnumerationScope.ShareEnumeration,
        #     MatchLocation = MatchLoc.ShareName,
        #     MatchAction = MatchAction.Snaffle,
        #     WordListType = MatchListType.EndsWith,
        #     Triage = Triage.Black,
        #     WordList = new List<string>()
        #         {
        #             "\\Users",
        #         },
        # });
        # """

    # """
    # [Nett.TomlIgnore]
    # public string[] ShareStringsToPrioritise { get; set; } =
    # {
    #     // these are substrings that make a share or hostname more interesting and make it worth prioritising.
    #     "IT",
    #     "security",
    #     "admin",
    #     "dev",
    #     "sql",
    #     "backup",
    #     "sap",
    #     "erp",
    #     "oracle",
    #     "vmware",
    #     "sccm"
    # };
    # """
