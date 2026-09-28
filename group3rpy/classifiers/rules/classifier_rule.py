"""Port of LibSnaffle/Classifiers/Rules/ClassifierRule.cs

A single Snaffler classifier rule. The defaults here match the C# property
initialisers exactly, because most rule definitions only set a subset of the
fields and rely on those defaults.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

from group3rpy.classifiers.constants import (
    EnumerationScope,
    MatchAction,
    MatchListType,
    MatchLoc,
    Triage,
)


@dataclass
class ClassifierRule:
    """Port of LibSnaffle.Classifiers.ClassifierRule."""

    # define in what phase this rule is applied
    enumeration_scope: EnumerationScope = EnumerationScope.FileEnumeration
    # define a way to chain rules together
    rule_name: str = "Default"
    match_action: MatchAction = MatchAction.Snaffle
    relay_target: Optional[str] = None
    description: str = "A description of what a rule does."
    # define the behaviour of this rule
    match_location: MatchLoc = MatchLoc.FileName
    word_list_type: MatchListType = MatchListType.Contains
    match_length: int = 0
    match_md5: Optional[str] = None
    word_list: List[str] = field(default_factory=list)
    # NB: in the C# this has no initialiser, i.e. it is null until
    # PrepareClassifiers() fills it in.
    regexes: Optional[List["re.Pattern[str]"]] = None
    # define the severity of any matches
    triage: Triage = Triage.Green
