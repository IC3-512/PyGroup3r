"""Regression tests that pin *upstream bugs* this port deliberately reproduces.

Each of these looks like a defect and is one. They are preserved because the
brief is byte-identical findings: "fixing" any of them would make this port
report findings the original does not, or suppress findings it does. If a future
change makes one of these tests fail, that change is a behavioural divergence
from Group3r and needs to be a conscious, documented decision.
"""

from group3rpy.assessment.finding import ACEType
from group3rpy.assessment.sddl_analyser import SddlAnalyser
from group3rpy.classifiers.constants import Triage
from group3rpy.options.assessment_options import AssessmentOptions
from group3rpy.sddl.sddl import Sddl, SecurableObjectType


def test_plain_deny_ace_is_treated_as_allow():
    """Upstream: SddlAnalyser.SimplifyAC switches on "OBJECT_ACCESS_ALLOWED" /
    "OBJECT_ACCESS_DENIED", but Sddl.Parser only emits those for *object* ACEs
    (`OA`/`OD`). A plain `D;;` deny ACE parses as "ACCESS_DENIED", hits the
    switch's `default: break`, and keeps SimpleAce.ACEType at its default value --
    which is ACEType.Allow, the zero-valued enum member.

    Consequence: FsAclAnalyser's `if (denyRight) continue;` never fires for plain
    deny ACEs, so an explicit Deny can count towards can_write/can_modify.
    """
    sddl = Sddl(
        "O:BAG:BAD:(A;;GA;;;S-1-5-21-1-2-3-512)(D;;GA;;;S-1-1-0)",
        SecurableObjectType.DirectoryServiceObject,
    )
    # The parser itself is correct about the ACE type...
    assert [ace.ace_type for ace in sddl.dacl.aces] == ["ACCESS_ALLOWED", "ACCESS_DENIED"]

    aces = SddlAnalyser(AssessmentOptions()).analyse_sddl(sddl)
    # ...but the analyser's switch does not recognise it, so both come out Allow.
    deny_ace = [a for a in aces if a.trustee.display_name == "Everyone"][0]
    assert deny_ace.ace_type is ACEType.Allow, (
        "A plain deny ACE must stay Allow to match upstream. If this now reports "
        "Deny, findings will differ from the original Group3r."
    )


def test_object_deny_ace_is_the_only_recognised_deny():
    """The mirror of the above: an `OD` object-deny ACE *is* recognised."""
    sddl = Sddl(
        "O:BAG:BAD:(OD;;GA;;;S-1-1-0)",
        SecurableObjectType.DirectoryServiceObject,
    )
    assert sddl.dacl.aces[0].ace_type == "OBJECT_ACCESS_DENIED"
    aces = SddlAnalyser(AssessmentOptions()).analyse_sddl(sddl)
    assert aces[-1].ace_type is ACEType.Deny


def test_owner_becomes_a_synthetic_ace_with_the_literal_right_Owner():
    """Upstream emits the SD owner as an ACE whose only right is the string
    "Owner". FsAclAnalyser lists "Owner" in both WriteRights and ModifyRights, so
    this synthetic ACE is what makes an owned path count as writable.
    """
    sddl = Sddl("O:BAG:BAD:(A;;GR;;;S-1-1-0)", SecurableObjectType.File)
    aces = SddlAnalyser(AssessmentOptions()).analyse_sddl(sddl)
    owner = aces[0]
    assert owner.rights == ["Owner"]
    assert owner.trustee.sid is None
    assert owner.trustee.display_name == "Administrators"


def test_dir_classifier_never_sets_matched_rule():
    """Upstream DirClassifier.Classify does not assign MatchedRule, so
    PathAnalyser's `snaffResult.MatchedRule != null` guard can never pass and
    directory classifier hits are never recorded in a PathResult.
    """
    from group3rpy.classifiers.dir_classifier import DirClassifier

    options = AssessmentOptions()
    classifier = DirClassifier(None, options.classifier_options)
    rules = options.classifier_options.all_rules.dir_classifier_rules
    assert rules, "expected at least one dir classifier rule"

    for rule in rules:
        result = classifier.classify(rule, "\\\\host\\share\\.ssh\\")
        if result is not None:
            assert result.matched_rule is None, (
                "DirClassifier must not set matched_rule -- upstream does not, and "
                "setting it would add PathResult entries the original never emits."
            )


def test_interesting_rights_keeps_upstream_duplicates():
    """AssessmentOptions.InterestingRights lists SET_VALUE and CREATE_CHILD twice.
    Harmless, but the list is compared by membership and its length is observable.
    """
    rights = AssessmentOptions().interesting_rights
    assert rights.count("SET_VALUE") == 2
    assert rights.count("CREATE_CHILD") == 2
    assert len(rights) == 29


def test_posix_looking_char_classes_are_not_posix_classes():
    """14 upstream regexes contain `[[:space:]]`, which neither .NET nor Python
    treats as a POSIX class -- both read it as the set {[ : s p a c e} plus a
    literal `]`. Ported verbatim, so it matches (mis-matches) identically.
    """
    import re

    options = AssessmentOptions()
    offenders = [
        rule
        for rule in options.classifier_options.all_rules.all_classifier_rules
        if rule.word_list and any("[[:space:]]" in w for w in rule.word_list)
    ]
    assert offenders, "expected upstream patterns containing [[:space:]]"

    pattern = re.compile("x[[:space:]]*=")
    # A literal space does NOT match, because this is not a POSIX class.
    assert pattern.search("x =") is None
    # A character from the set, followed by ']', does.
    assert pattern.search("xs]=") is not None


def test_triage_ordinals_are_load_bearing():
    """Analysers compare triage numerically (`(int)MinTriage < 2`), so the
    ordinals must stay Green=0, Yellow=1, Red=2, Black=3.
    """
    assert (int(Triage.Green), int(Triage.Yellow), int(Triage.Red), int(Triage.Black)) == (
        0,
        1,
        2,
        3,
    )
    assert Triage.Green < Triage.Red and Triage.Yellow < Triage.Red
    assert not (Triage.Red < Triage.Red)


def test_empty_dacl_section_raises_like_upstream():
    """Upstream: `...D:` parses to Dacl != null with Aces == null, so
    SddlAnalyser.SimplifyAC's `sddl.Dacl.Aces.Length` throws a
    NullReferenceException. GroupCon catches it, so the setting -- or the whole
    GPO, for a GPO's own descriptor -- produces no output.

    The port must raise equivalently rather than substituting an empty list,
    otherwise it emits findings the original cannot produce.
    """
    import pytest

    sddl = Sddl("O:BAG:BAD:", SecurableObjectType.DirectoryServiceObject)
    assert sddl.dacl is not None
    assert sddl.dacl.aces is None

    with pytest.raises(TypeError):
        SddlAnalyser(AssessmentOptions()).analyse_sddl(sddl)


def test_normal_dacl_still_works_after_that_strictness():
    """Guard against over-correcting the above into a general breakage."""
    sddl = Sddl("O:BAG:BAD:(A;;GA;;;S-1-5-21-1-2-3-512)", SecurableObjectType.File)
    aces = SddlAnalyser(AssessmentOptions()).analyse_sddl(sddl)
    assert len(aces) == 2  # synthetic owner ACE + the real one
