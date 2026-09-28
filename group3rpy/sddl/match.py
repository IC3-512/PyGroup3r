"""Port of LibSnaffle/Sddl.Parser/Match.cs.

PORT NOTE: C# `out` parameters have no Python equivalent, so every method that
had an `out reminder` returns a `(result, reminder)` tuple instead. Iteration
order over the dictionaries is significant (first match wins) and Python dicts
preserve insertion order exactly like the insert-only .NET Dictionary<,> the
original relies on.
"""

import re
from typing import Mapping, Sequence


class Match:
    """Port of the internal static Sddl.Parser.Match class."""

    @staticmethod
    def many_by_prefix(
        input: str, tokens_to_labels: Mapping[str, str]
    ) -> tuple[list[str], str | None]:
        labels: list[str] = []

        reminder = _substitute_empty_with_null(input)
        while reminder is not None:
            label, reminder = Match.one_by_prefix(reminder, tokens_to_labels)

            if label is not None:
                labels.append(label)
            else:
                break

        return labels, reminder

    @staticmethod
    def many_by_uint(
        mask: int, tokens_to_labels: Mapping[int, str]
    ) -> tuple[list[str], int]:
        labels: list[str] = []

        reminder = mask
        while reminder > 0:
            label, reminder = Match.one_by_uint(reminder, tokens_to_labels)

            if label is not None:
                labels.append(label)
            else:
                break

        return labels, reminder

    @staticmethod
    def one_by_prefix(
        input: str, tokens_to_labels: Mapping[str, str]
    ) -> tuple[str | None, str | None]:
        for key, value in tokens_to_labels.items():
            if input.startswith(key):
                reminder = _substitute_empty_with_null(input[len(key):])
                return value, reminder

        return None, input

    @staticmethod
    def one_by_uint(
        mask: int, tokens_to_labels: Mapping[int, str]
    ) -> tuple[str | None, int]:
        for key, value in tokens_to_labels.items():
            if (mask & key) == key:
                reminder = mask - key
                return value, reminder

        return None, mask

    @staticmethod
    def one_by_regex_or_prefix(
        input: str, tokens_to_labels: Sequence[tuple[str | None, str, str]]
    ) -> str | None:
        for prefix, regex, value in tokens_to_labels:
            if (prefix is not None and prefix != "" and input.startswith(prefix)) or re.search(regex, input):
                return value

        return None


def _substitute_empty_with_null(input: str) -> str | None:
    return None if input == "" else input
