"""Port of LibSnaffle/Classifiers/Rules/PathRules.cs

One half of the C# `partial class ClassifierRules`, expressed as a mixin.
"""

from group3rpy.classifiers.constants import (
    EnumerationScope,
    MatchAction,
    MatchListType,
    MatchLoc,
)
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule


class PathRulesMixin:
    """Port of the BuildPathRules() half of ClassifierRules."""

    def _build_path_rules(self) -> None:
        self.all_classifier_rules.append(
            ClassifierRule(
                description="File paths that will be skipped entirely.",
                rule_name="DiscardFilepathContains",
                enumeration_scope=EnumerationScope.DirectoryEnumeration,
                match_location=MatchLoc.FilePath,
                match_action=MatchAction.Discard,
                word_list_type=MatchListType.Contains,
                word_list=[
                    # these are directory names that make us skip a dir instantly when building a tree.
                    "winsxs",
                    "syswow64",
                    "system32",
                    "systemapps",
                    "servicing\\packages",
                    "Microsoft.NET\\Framework",
                    "windows\\immersivecontrolpanel",
                    "windows\\diagnostics",
                    "windows\\debug",
                    "node_modules",
                    "vendor\\bundle",
                    "vendor\\cache",
                    "locale\\",
                    "chocolatey\\helpers",
                    "sources\\sxs",
                    "localization\\",
                    "\\AppData\\Local\\Microsoft\\",
                    "\\AppData\\Roaming\\Microsoft\\",
                    "\\wsuscontent",
                    "\\Application Data\\Microsoft\\CLR Security Config\\",
                ],
            )
        )
