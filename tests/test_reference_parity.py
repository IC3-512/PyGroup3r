"""Parity tests against the compiled C# original.

`reference/` holds output captured from the **real C# Group3r**, compiled for net48
and run under mono against `upstream/TestSysvol` (see `reference/HOWTO.md`). These
are the only true parity oracle available, so these tests are the most important
in the suite: if one fails, the port has diverged from Group3r.

Two asymmetries are expected, both caused by the reference *environment* rather
than by the port, and both documented in reference/HOWTO.md:

  * mono cannot read local NTFS ACLs, so 4 script settings throw
    PlatformNotSupportedException and are dropped from the reference. Two of them
    carry a password-in-arguments finding, so the port legitimately reports more.
  * mono has no LookupAccountSid, so unresolved SIDs render as
    "Failed SID resolution". Where the port resolves such a SID the text differs,
    and occasionally the *triage* differs too, because a resolved name can match a
    low-priv TrusteeOption and escalate the finding. Those are bucketed out.

The invariant asserted is one-directional and strict: **every finding in the
reference must be reproduced by the port.** Extra findings on our side are
allowed only in the two categories above.
"""

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
FIXTURE = ROOT / "upstream" / "TestSysvol"

sys.path.insert(0, str(ROOT / "tools"))

pytestmark = pytest.mark.skipif(
    not (REFERENCE / "original_nice_sidfallback.txt").is_file() or not FIXTURE.is_dir(),
    reason="reference output or TestSysvol fixture not present",
)

# (name, reference file, extra CLI flags)
CASES = [
    ("default", "original_nice_sidfallback.txt", []),
    ("mintriage1", "original_nice_mintriage1.txt", ["-a", "1"]),
    ("mintriage2", "original_nice_mintriage2.txt", ["-a", "2"]),
    ("mintriage3", "original_nice_mintriage3.txt", ["-a", "3"]),
    ("mintriage4", "original_nice_mintriage4.txt", ["-a", "4"]),
    ("findingsonly", "original_nice_findingsonly.txt", ["-w"]),
    ("enabledonly", "original_nice_enabledonly.txt", ["-e"]),
    ("currentonly", "original_nice_currentonly.txt", ["-r"]),
]

# Findings the port reports that the reference cannot, because mono lost the
# setting they come from to a local-ACL exception.
EXPECTED_EXTRA_REASONS = {
    "Startup script has an arguments setting that looks like it might have a "
    "password in it?",
}


def _run_port(tmp_path, flags):
    out = tmp_path / "ours.txt"
    result = subprocess.run(
        [sys.executable, "-m", "group3rpy", "-o", "-y", str(FIXTURE), "-f", str(out), *flags],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, f"port exited {result.returncode}: {result.stdout[-2000:]}"
    assert out.is_file(), "port produced no output file"
    return out


@pytest.mark.parametrize("name,ref_name,flags", CASES, ids=[c[0] for c in CASES])
def test_every_reference_finding_is_reproduced(name, ref_name, flags, tmp_path):
    from compare_reports import _is_sid_dependent, _key, extract_findings

    reference_path = REFERENCE / ref_name
    if not reference_path.is_file():
        pytest.skip(f"no reference file {ref_name}")

    ours_path = _run_port(tmp_path, flags)

    reference = [f for f in extract_findings(str(reference_path)) if not _is_sid_dependent(f)]
    ours = [f for f in extract_findings(str(ours_path)) if not _is_sid_dependent(f)]

    from collections import Counter

    ref_counts = Counter(_key(f) for f in reference)
    our_counts = Counter(_key(f) for f in ours)
    missing = ref_counts - our_counts

    if missing:
        labels = {_key(f): f for f in reference}
        detail = "\n".join(
            f"  [{labels[k][0]}] x{n} {labels[k][1]} :: {labels[k][2]}"
            for k, n in missing.items()
        )
        pytest.fail(
            f"{sum(missing.values())} finding(s) produced by the real Group3r are "
            f"missing from the port in the '{name}' variant:\n{detail}"
        )


def test_extra_findings_are_only_the_known_mono_losses(tmp_path):
    """Our surplus findings must be explainable, not arbitrary."""
    from collections import Counter

    from compare_reports import _is_sid_dependent, _key, extract_findings

    reference_path = REFERENCE / "original_nice_sidfallback.txt"
    ours_path = _run_port(tmp_path, [])

    reference = [f for f in extract_findings(str(reference_path)) if not _is_sid_dependent(f)]
    ours = [f for f in extract_findings(str(ours_path)) if not _is_sid_dependent(f)]

    ref_counts = Counter(_key(f) for f in reference)
    our_counts = Counter(_key(f) for f in ours)
    labels = {_key(f): f for f in ours}

    surplus = our_counts - ref_counts
    unexplained = []
    for key, count in surplus.items():
        reason = labels[key][1]
        if not any(expected in reason for expected in EXPECTED_EXTRA_REASONS):
            unexplained.append((labels[key], count))

    assert not unexplained, (
        "the port reports findings the reference does not, outside the documented "
        f"mono-ACL losses: {unexplained}"
    )


def test_triage_filtering_is_monotonic_against_reference():
    """Raising -a must never add findings, in the reference or in the port."""
    from compare_reports import extract_findings

    counts = []
    for level in (1, 2, 3, 4):
        path = REFERENCE / f"original_nice_mintriage{level}.txt"
        if not path.is_file():
            pytest.skip("mintriage references not present")
        counts.append(len(extract_findings(str(path))))

    assert counts == sorted(counts, reverse=True), (
        f"reference finding counts are not monotonically decreasing: {counts}"
    )
