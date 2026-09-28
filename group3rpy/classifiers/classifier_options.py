"""Port of LibSnaffle/Classifiers/ClassifierOptions.cs"""

from dataclasses import dataclass
from typing import Optional

from group3rpy.classifiers.rules.classifier_rules import ClassifierRules


@dataclass
class ClassifierOptions:
    """Port of LibSnaffle.Classifiers.ClassifierOptions."""

    all_rules: Optional[ClassifierRules] = None
    match_context_bytes: int = 200
    copy_file: bool = False
    max_size_to_copy: int = 10000000
    max_size_to_grep: int = 1000000
    path_to_copy_to: Optional[str] = None
