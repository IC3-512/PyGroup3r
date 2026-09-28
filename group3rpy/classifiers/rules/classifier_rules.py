"""Port of LibSnaffle/Classifiers/Rules/ClassifierRules.cs

The C# type is a `partial class` spread over ShareRules.cs, PathRules.cs,
FileDiscardRules.cs, FileNameRules.cs and FileContentRules.cs. Python has no
partial classes, so each of those files becomes a mixin and `ClassifierRules`
inherits all of them; the build order in `build_default_classifiers()` is
identical to the C#, which is what fixes the order of `all_classifier_rules`.
"""

import warnings
import re
from typing import List

from group3rpy.classifiers.constants import EnumerationScope, MatchListType
from group3rpy.classifiers.rules.classifier_rule import ClassifierRule
from group3rpy.classifiers.rules.file_content_rules import FileContentRulesMixin
from group3rpy.classifiers.rules.file_discard_rules import FileDiscardRulesMixin
from group3rpy.classifiers.rules.file_name_rules import FileNameRulesMixin
from group3rpy.classifiers.rules.path_rules import PathRulesMixin
from group3rpy.classifiers.rules.share_rules import ShareRulesMixin

# PORT NOTE: the C# compiles every rule regex with
# `RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant`.
# Python's `re` caches compiled patterns itself so `Compiled` has no analogue,
# and `re` has no culture-sensitive casing to turn off, so `CultureInvariant`
# has none either. Only `IgnoreCase` carries over.
_REGEX_FLAGS = re.IGNORECASE


class ClassifierRules(
    ShareRulesMixin,
    PathRulesMixin,
    FileDiscardRulesMixin,
    FileNameRulesMixin,
    FileContentRulesMixin,
):
    """Port of LibSnaffle.Classifiers.ClassifierRules."""

    def __init__(self) -> None:
        # Classifiers
        self.all_classifier_rules: List[ClassifierRule] = []
        # [Nett.TomlIgnore]
        self.share_classifier_rules: List[ClassifierRule] = []
        # [Nett.TomlIgnore]
        self.dir_classifier_rules: List[ClassifierRule] = []
        # [Nett.TomlIgnore]
        self.file_classifier_rules: List[ClassifierRule] = []
        # [Nett.TomlIgnore]
        self.contents_classifier_rules: List[ClassifierRule] = []

    def prepare_classifiers(self) -> None:
        # Where rules are using regexen, we precompile them here.
        # We're gonna use them a lot so efficiency matters.
        #
        # PORT NOTE: 14 of the upstream patterns contain `[[:space:]]`, which looks
        # like a POSIX class but is not one in .NET *or* Python -- both engines read
        # it as the set {[ : s p a c e} followed by a literal `]`. The patterns are
        # therefore ported verbatim, bug included. Python emits a
        # "Possible nested set" FutureWarning for each, which is suppressed here
        # rather than by rewriting the pattern, because `TextResult.matched_strings`
        # carries `regex.pattern` through into report output.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            self._compile_classifiers()

    def _compile_classifiers(self) -> None:
        for classifier_rule in self.all_classifier_rules:
            classifier_rule.regexes = []
            if classifier_rule.word_list_type == MatchListType.Regex:
                for pattern in classifier_rule.word_list:
                    classifier_rule.regexes.append(re.compile(pattern, _REGEX_FLAGS))
            elif classifier_rule.word_list_type == MatchListType.Contains:
                classifier_rule.regexes = []
                for word in classifier_rule.word_list:
                    pattern = re.escape(word)
                    classifier_rule.regexes.append(re.compile(pattern, _REGEX_FLAGS))
            elif classifier_rule.word_list_type == MatchListType.EndsWith:
                for word in classifier_rule.word_list:
                    pattern = re.escape(word)
                    pattern = pattern + "$"
                    classifier_rule.regexes.append(re.compile(pattern, _REGEX_FLAGS))
            elif classifier_rule.word_list_type == MatchListType.StartsWith:
                for word in classifier_rule.word_list:
                    pattern = re.escape(word)
                    pattern = "^" + pattern
                    classifier_rule.regexes.append(re.compile(pattern, _REGEX_FLAGS))
            elif classifier_rule.word_list_type == MatchListType.Exact:
                for word in classifier_rule.word_list:
                    pattern = re.escape(word)
                    pattern = "^" + pattern + "$"
                    classifier_rule.regexes.append(re.compile(pattern, _REGEX_FLAGS))

        # sort everything into enumeration scopes
        self.share_classifier_rules = [
            classifier
            for classifier in self.all_classifier_rules
            if classifier.enumeration_scope == EnumerationScope.ShareEnumeration
        ]
        self.dir_classifier_rules = [
            classifier
            for classifier in self.all_classifier_rules
            if classifier.enumeration_scope == EnumerationScope.DirectoryEnumeration
        ]
        self.file_classifier_rules = [
            classifier
            for classifier in self.all_classifier_rules
            if classifier.enumeration_scope == EnumerationScope.FileEnumeration
        ]
        self.contents_classifier_rules = [
            classifier
            for classifier in self.all_classifier_rules
            if classifier.enumeration_scope == EnumerationScope.ContentsEnumeration
        ]

    def build_default_classifiers(self) -> None:
        self.all_classifier_rules = []
        self._build_share_rules()
        self._build_path_rules()
        self._build_file_discard_rules()
        self._build_file_name_rules()
        self._build_file_content_rules()
