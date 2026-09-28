"""Tests for group3rpy.classifiers -- the port of LibSnaffle/Classifiers/*.

These lock down the three things that make the ported Snaffler engine useful:
  * the rule tables have exactly as many rules as the C# builds, per source file
  * every pattern in every rule compiles under Python's `re`
  * a handful of well-known paths still classify to the rule/triage they do in
    the C# original.
"""

import re
import warnings

import pytest

from group3rpy.assessment.finding import DirResult, FileResult
from group3rpy.classifiers.classifier_options import ClassifierOptions
from group3rpy.classifiers.constants import (
    EnumerationScope,
    MatchAction,
    MatchListType,
    Triage,
)
from group3rpy.classifiers.dir_classifier import DirClassifier
from group3rpy.classifiers.file_classifier import FileClassifier, win_extension
from group3rpy.classifiers.rules.classifier_rules import ClassifierRules

# Rule counts, taken from `grep -c 'new ClassifierRule' <file>` in
# upstream/LibSnaffle/Classifiers/Rules/ minus the blocks that are commented out
# in the C# (and therefore stay commented out in the port):
#   ShareRules.cs        3 grep hits, 1 commented  -> 2
#   PathRules.cs         1 grep hit,  0 commented  -> 1
#   FileDiscardRules.cs  1 grep hit,  0 commented  -> 1
#   FileNameRules.cs     6 grep hits, 1 commented  -> 5
#   FileContentRules.cs 27 grep hits, 2 commented  -> 25
EXPECTED_COUNTS = {
    "_build_share_rules": 2,
    "_build_path_rules": 1,
    "_build_file_discard_rules": 1,
    "_build_file_name_rules": 5,
    "_build_file_content_rules": 25,
}

TOTAL_RULES = sum(EXPECTED_COUNTS.values())


@pytest.fixture()
def rules() -> ClassifierRules:
    all_rules = ClassifierRules()
    all_rules.build_default_classifiers()
    # `[[:space:]]` in the upstream patterns makes Python emit a "possible nested
    # set" FutureWarning; it is ported verbatim on purpose (see the PORT NOTE in
    # file_content_rules.py), so the warning is expected here.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        all_rules.prepare_classifiers()
    return all_rules


@pytest.fixture()
def options(rules: ClassifierRules) -> ClassifierOptions:
    return ClassifierOptions(all_rules=rules)


class FakeFs:
    """Minimal stand-in for group3rpy.smb.provider.FsProvider."""

    def __init__(self, files: dict[str, bytes] | None = None) -> None:
        self.files = files or {}

    def file_exists(self, path: str) -> bool:
        return path in self.files

    def dir_exists(self, path: str) -> bool:
        return False

    def read_file(self, path: str) -> bytes:
        try:
            return self.files[path]
        except KeyError:
            raise OSError(path) from None

    def list_dir(self, path: str) -> list[str]:
        raise OSError(path)

    def get_security_descriptor(self, path: str):
        return None

    def file_length(self, path: str) -> int:
        return len(self.files.get(path, b""))


# --------------------------------------------------------------------------
# rule counts
# --------------------------------------------------------------------------


@pytest.mark.parametrize("builder,expected", sorted(EXPECTED_COUNTS.items()))
def test_per_file_rule_counts(builder: str, expected: int) -> None:
    all_rules = ClassifierRules()
    all_rules.all_classifier_rules = []
    getattr(all_rules, builder)()
    assert len(all_rules.all_classifier_rules) == expected


def test_total_rule_count(rules: ClassifierRules) -> None:
    assert len(rules.all_classifier_rules) == TOTAL_RULES == 34


def test_build_is_idempotent() -> None:
    all_rules = ClassifierRules()
    all_rules.build_default_classifiers()
    first = [r.rule_name for r in all_rules.all_classifier_rules]
    all_rules.build_default_classifiers()
    assert [r.rule_name for r in all_rules.all_classifier_rules] == first


def test_rule_names_are_unique(rules: ClassifierRules) -> None:
    names = [r.rule_name for r in rules.all_classifier_rules]
    assert len(set(names)) == len(names)


def test_build_order_matches_csharp(rules: ClassifierRules) -> None:
    """BuildDefaultClassifiers() order: share, path, discard, filename, content."""
    names = [r.rule_name for r in rules.all_classifier_rules]
    assert names[:5] == [
        "DiscardShareEndsWith",
        "KeepShareBlack",
        "DiscardFilepathContains",
        "DiscardExtExact",
        "KeepExtExactBlack",
    ]
    assert names[-1] == "KeepCertContainsPrivKeyRed"


# --------------------------------------------------------------------------
# prepare_classifiers() partitioning + regex compilation
# --------------------------------------------------------------------------


def test_scope_partitioning(rules: ClassifierRules) -> None:
    # PathAnalyser iterates these two by name, so they must exist and be filled.
    assert len(rules.share_classifier_rules) == 2
    assert len(rules.dir_classifier_rules) == 1
    assert len(rules.file_classifier_rules) == 19
    assert len(rules.contents_classifier_rules) == 12
    assert (
        len(rules.share_classifier_rules)
        + len(rules.dir_classifier_rules)
        + len(rules.file_classifier_rules)
        + len(rules.contents_classifier_rules)
        == TOTAL_RULES
    )
    for scope, bucket in (
        (EnumerationScope.ShareEnumeration, rules.share_classifier_rules),
        (EnumerationScope.DirectoryEnumeration, rules.dir_classifier_rules),
        (EnumerationScope.FileEnumeration, rules.file_classifier_rules),
        (EnumerationScope.ContentsEnumeration, rules.contents_classifier_rules),
    ):
        assert all(r.enumeration_scope is scope for r in bucket)
    # partitions preserve AllClassifierRules order
    for bucket in (
        rules.share_classifier_rules,
        rules.dir_classifier_rules,
        rules.file_classifier_rules,
        rules.contents_classifier_rules,
    ):
        indexes = [rules.all_classifier_rules.index(r) for r in bucket]
        assert indexes == sorted(indexes)


def test_every_pattern_compiles(rules: ClassifierRules) -> None:
    """Every word/pattern in every rule must compile under Python `re`."""
    checked = 0
    for rule in rules.all_classifier_rules:
        assert rule.regexes is not None, rule.rule_name
        assert len(rule.regexes) == len(rule.word_list), rule.rule_name
        for word, compiled in zip(rule.word_list, rule.regexes):
            if rule.word_list_type is MatchListType.Regex:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", FutureWarning)
                    re.compile(word, re.IGNORECASE)
                assert compiled.pattern == word
            else:
                escaped = re.escape(word)
                if rule.word_list_type is MatchListType.Exact:
                    assert compiled.pattern == "^" + escaped + "$"
                elif rule.word_list_type is MatchListType.StartsWith:
                    assert compiled.pattern == "^" + escaped
                elif rule.word_list_type is MatchListType.EndsWith:
                    assert compiled.pattern == escaped + "$"
                else:
                    assert compiled.pattern == escaped
            assert compiled.flags & re.IGNORECASE
            checked += 1
    assert checked > 200


def test_regexes_are_none_before_prepare() -> None:
    all_rules = ClassifierRules()
    all_rules.build_default_classifiers()
    assert all(r.regexes is None for r in all_rules.all_classifier_rules)


# --------------------------------------------------------------------------
# extension handling
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("secrets.kdbx", ".kdbx"),
        (".env", ".env"),
        ("id_rsa", ""),
        ("archive.tar.gz", ".gz"),
        ("trailingdot.", ""),
    ],
)
def test_win_extension(name: str, expected: str) -> None:
    assert win_extension(name) == expected


# --------------------------------------------------------------------------
# FileClassifier spot checks
# --------------------------------------------------------------------------


def classify_path(options: ClassifierOptions, path: str, fs=None):
    """Run every file-scope rule over `path` and collect the hits."""
    classifier = FileClassifier(None, options, fs)
    hits = []
    for rule in options.all_rules.file_classifier_rules:
        result = classifier.classify(rule, path)
        if result is not None and result.matched_rule is not None:
            hits.append(result)
    return hits


@pytest.mark.parametrize(
    "path,rule_name,triage",
    [
        # exact filename, black
        (r"\\dc01\sysvol\corp.local\scripts\id_rsa", "KeepFilenameExactBlack", Triage.Black),
        (r"\\dc01\sysvol\corp.local\scripts\id_ed25519", "KeepFilenameExactBlack", Triage.Black),
        (r"C:\windows\ntds\NTDS.DIT", "KeepFilenameExactBlack", Triage.Black),
        # exact extension, black
        (r"\\fs01\share\ops\vault.kdbx", "KeepExtExactBlack", Triage.Black),
        (r"\\fs01\share\ops\legacy.kdb", "KeepExtExactBlack", Triage.Black),
        (r"\\fs01\share\vpn\corp.ovpn", "KeepExtExactBlack", Triage.Black),
        # exact filename, red
        (r"\\dc01\sysvol\corp.local\scripts\unattend.xml", "KeepFilenameExactRed", Triage.Red),
        (r"\\fs01\share\app\database.yml", "KeepFilenameExactRed", Triage.Red),
        # exact extension, red
        (r"\\fs01\share\certs\wildcard.key", "KeepExtExactRed", Triage.Red),
        (r"\\fs01\share\rdp\jump.rdp", "KeepExtExactRed", Triage.Red),
        # path contains, black
        (r"\\fs01\home\jbloggs\.ssh\authorized_keys", "KeepPathContainsBlack", Triage.Black),
        (r"\\fs01\home\jbloggs\.aws\credentials", "KeepPathContainsBlack", Triage.Black),
    ],
)
def test_known_paths_match_expected_rule(
    options: ClassifierOptions, path: str, rule_name: str, triage: Triage
) -> None:
    hits = classify_path(options, path)
    matched = {h.matched_rule.rule_name for h in hits}
    assert rule_name in matched, f"{path} -> {sorted(matched)}"
    hit = next(h for h in hits if h.matched_rule.rule_name == rule_name)
    assert isinstance(hit, FileResult)
    assert hit.matched_rule.triage is triage
    assert hit.file_path == path
    assert hit.text_result is not None


def test_bak_suffix_is_stripped_for_extension_rules(
    options: ClassifierOptions,
) -> None:
    """'thing.kdbx.bak' must still trip the .kdbx rule."""
    hits = classify_path(options, r"\\fs01\share\ops\vault.kdbx.bak")
    assert "KeepExtExactBlack" in {h.matched_rule.rule_name for h in hits}


def test_discarded_extension_yields_no_result(options: ClassifierOptions) -> None:
    """MatchAction.Discard returns null in the C#, so no hits at all."""
    assert classify_path(options, r"\\fs01\share\pics\logo.png") == []


def test_extensionless_file_is_not_matched_by_extension_rules(
    options: ClassifierOptions, rules: ClassifierRules
) -> None:
    ext_rule = next(
        r for r in rules.file_classifier_rules if r.rule_name == "KeepExtExactBlack"
    )
    classifier = FileClassifier(None, options)
    assert classifier.classify(ext_rule, r"\\fs01\share\ops\README") is None


def test_web_config_relays_to_content_rule(options: ClassifierOptions) -> None:
    """web.config -> ConfigContentByExt (Relay) -> KeepConfigRegexRed."""
    path = r"\\fs01\wwwroot\web.config"
    fs = FakeFs(
        {
            path: (
                b"<configuration>\n"
                b"-----BEGIN RSA PRIVATE KEY-----\n"
                b"</configuration>\n"
            )
        }
    )
    hits = classify_path(options, path, fs)
    assert "KeepConfigRegexRed" in {h.matched_rule.rule_name for h in hits}
    hit = next(h for h in hits if h.matched_rule.rule_name == "KeepConfigRegexRed")
    assert hit.matched_rule.triage is Triage.Red
    assert hit.text_result is not None
    assert hit.text_result.matched_strings == [
        r"-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----"
    ]


def test_relay_with_boring_content_yields_nothing(options: ClassifierOptions) -> None:
    path = r"\\fs01\wwwroot\boring.config"
    fs = FakeFs({path: b"<configuration />"})
    assert classify_path(options, path, fs) == []


def test_check_for_keys_rule_needs_a_private_key(options: ClassifierOptions) -> None:
    plain = r"\\fs01\share\certs\public.der"
    withkey = r"\\fs01\share\certs\bundle.pfx"
    fs = FakeFs(
        {
            plain: b"\x30\x82\x01\x0a not a key",
            # DER OID for pkcs8ShroudedKeyBag (1.2.840.113549.1.12.10.1.2)
            withkey: b"\x30\x82" + bytes.fromhex("060b2a864886f70d010c0a0102"),
        }
    )
    assert classify_path(options, plain, fs) == []
    hits = classify_path(options, withkey, fs)
    assert "KeepCertContainsPrivKeyRed" in {h.matched_rule.rule_name for h in hits}


# --------------------------------------------------------------------------
# DirClassifier spot checks
# --------------------------------------------------------------------------


def test_dir_classifier_discards_boring_paths(options: ClassifierOptions) -> None:
    rule = options.all_rules.dir_classifier_rules[0]
    assert rule.rule_name == "DiscardFilepathContains"
    assert rule.match_action is MatchAction.Discard
    classifier = DirClassifier(None, options)

    hit = classifier.classify(rule, r"\\host\c$\windows\system32\drivers")
    assert isinstance(hit, DirResult)
    assert hit.scan_dir is False
    assert hit.dir_path == r"\\host\c$\windows\system32\drivers"
    # PORT NOTE (upstream bug, preserved): the C# DirClassifier never sets
    # MatchedRule, so PathAnalyser's `MatchedRule != null` test never fires and
    # dir results are never recorded. Keep that behaviour pinned.
    assert hit.matched_rule is None

    miss = classifier.classify(rule, r"\\dc01\sysvol\corp.local\policies")
    assert isinstance(miss, DirResult)
    assert miss.matched_rule is None
