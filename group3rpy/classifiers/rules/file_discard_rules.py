"""Port of LibSnaffle/Classifiers/Rules/FileDiscardRules.cs

One half of the C# `partial class ClassifierRules`, expressed as a mixin.
"""

from group3rpy.classifiers.constants import (
    EnumerationScope,
    MatchAction,
    MatchListType,
    MatchLoc,
)
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule


class FileDiscardRulesMixin:
    """Port of the BuildFileDiscardRules() half of ClassifierRules."""

    def _build_file_discard_rules(self) -> None:
        self.all_classifier_rules.append(
            ClassifierRule(
                description="Skip any further scanning for files with these extensions.",
                rule_name="DiscardExtExact",
                enumeration_scope=EnumerationScope.FileEnumeration,
                match_location=MatchLoc.FileExtension,
                word_list_type=MatchListType.Exact,
                match_action=MatchAction.Discard,
                word_list=[
                    # always skip these file extensions
                    # image formats
                    ".bmp",  # test file created
                    ".eps",  # test file created
                    ".gif",  # test file created
                    ".ico",  # test file created
                    ".jfi",  # test file created
                    ".jfif",  # test file created
                    ".jif",  # test file created
                    ".jpe",  # test file created
                    ".jpeg",  # test file created
                    ".jpg",  # test file created
                    ".png",  # test file created
                    ".psd",  # test file created
                    ".svg",  # test file created
                    ".tif",  # test file created
                    ".tiff",  # test file created
                    ".webp",  # test file created
                    ".xcf",  # test file created
                    # font
                    ".ttf",  # test file created
                    ".otf",  # test file created
                    # misc
                    ".lock",  # test file created
                    ".css",  # test file created
                    ".less",  # test file created
                ],
            )
        )
