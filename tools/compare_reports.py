#!/usr/bin/env python3
"""Compare a Group3r `nice` report against this port's, finding by finding.

The reference reports under `reference/` were produced by the **real C# Group3r**
compiled for net48 and run under mono against `upstream/TestSysvol`. That makes
them the only true parity oracle available, so this script exists to diff against
them rather than against expectations.

It extracts `(triage, reason, detail)` triples out of the ASCII-table output,
normalising the line wrapping the printer applies at 80 columns, and reports:

  * findings in the reference but not in ours  (a real regression: we are missing
    something the original reports)
  * findings in ours but not in the reference  (usually explained -- see below)

Known, expected asymmetries when comparing against a mono reference:

  * The original loses every `Registry.pol` on Linux (upstream hard-codes a
    `\\machine\\` path test), so it under-reports registry settings.
  * The original cannot read local NTFS ACLs under mono, so some script settings
    throw and are skipped entirely.
  * SID resolution differs unless the `_sidfallback` reference is used.

Usage:
    compare_reports.py reference/original_nice_sidfallback.txt ours.txt
"""

import argparse
import re
import sys
from collections import Counter
from typing import Dict, List, Optional, Tuple

_ROW = re.compile(r"^\s*\|\s*(?P<key>[^|]*?)\s*\|\s*(?P<value>.*?)\s*\|\s*$")

Finding = Tuple[str, str, str]


def _flush(pending: Dict[str, List[str]], out: List[Finding]) -> None:
    if not pending:
        return
    triage = " ".join(pending.get("__triage__", [])).strip()
    reason = " ".join(pending.get("Reason", [])).strip()
    detail = " ".join(pending.get("Detail", [])).strip()
    if triage:
        out.append((triage, _squash(reason), _squash(detail)))
    pending.clear()


def _squash(text: str) -> str:
    """Undo the printer's 80-column wrapping so wrapped text compares equal."""
    return re.sub(r"\s+", " ", text).strip()


def _key(finding: Finding) -> Finding:
    """Whitespace-insensitive comparison key.

    The printer hard-wraps cells at 80 columns, and the wrap position depends on
    the length of the values in the row -- so the same logical sentence can break
    at different points in two runs. Rejoining wrapped fragments with a single
    space then invents differences like `S-1- 5-19`. Comparing with all
    whitespace removed sidesteps that entirely; for sentences this long the risk
    of a false match is negligible.
    """
    triage, reason, detail = finding
    return (triage, re.sub(r"\s+", "", reason), re.sub(r"\s+", "", detail))


def _is_sid_dependent(finding: Finding) -> bool:
    """True if this finding's text depends on whether a SID could be resolved.

    The mono reference cannot call LookupAccountSid, so unresolved SIDs render as
    "Failed SID resolution". Where the port resolves the same SID it may produce
    different text -- and sometimes a *different triage*, because a resolved name
    can match a low-priv TrusteeOption and escalate the finding. Those are
    improvements caused by the reference environment, not logic divergences, so
    they are bucketed rather than counted as failures.
    """
    _triage, reason, detail = finding
    blob = (reason + " " + detail)
    blob = re.sub(r"\s+", "", blob).lower()
    return "failedsidresolution" in blob


def extract_findings(path: str) -> List[Finding]:
    findings: List[Finding] = []
    pending: Dict[str, List[str]] = {}
    current_key: Optional[str] = None

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = _ROW.match(line.rstrip("\n"))
            if match is None:
                # A non-table line ends any finding being accumulated.
                if pending:
                    _flush(pending, findings)
                current_key = None
                continue

            key = match.group("key")
            value = match.group("value")

            if key == "Finding":
                # Start of a new finding block; the value is the triage level.
                _flush(pending, findings)
                pending["__triage__"] = [value]
                current_key = "__triage__"
                continue

            if key in ("Reason", "Detail"):
                pending.setdefault(key, []).append(value)
                current_key = key
                continue

            if key == "" and current_key in ("Reason", "Detail") and pending:
                # Continuation line of a wrapped Reason/Detail cell.
                pending[current_key].append(value)
                continue

            # Any other labelled row (e.g. a new Setting table) closes the block.
            if pending and key not in ("", "-"):
                if not key.startswith("-"):
                    _flush(pending, findings)
                    current_key = None

    _flush(pending, findings)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reference", help="report from the real C# Group3r")
    parser.add_argument("ours", help="report from this port")
    parser.add_argument("--show", type=int, default=15, help="max examples to print")
    args = parser.parse_args()

    reference = extract_findings(args.reference)
    ours = extract_findings(args.ours)

    ref_sid = [f for f in reference if _is_sid_dependent(f)]
    our_sid = [f for f in ours if _is_sid_dependent(f)]
    ref_cmp = [f for f in reference if not _is_sid_dependent(f)]
    our_cmp = [f for f in ours if not _is_sid_dependent(f)]

    ref_counts = Counter(_key(f) for f in ref_cmp)
    our_counts = Counter(_key(f) for f in our_cmp)
    labels = {_key(f): f for f in ref_cmp + our_cmp}

    only_ref = ref_counts - our_counts
    only_ours = our_counts - ref_counts

    print(f"reference : {len(reference)} findings ({len(set(_key(f) for f in reference))} distinct)")
    print(f"ours      : {len(ours)} findings ({len(set(_key(f) for f in ours))} distinct)")
    print(f"comparable: {len(ref_cmp)} reference / {len(our_cmp)} ours "
          f"(excluded as SID-resolution dependent: {len(ref_sid)} / {len(our_sid)})")
    print(f"in common : {sum((ref_counts & our_counts).values())}")

    by_triage_ref = Counter(t for t, _r, _d in reference)
    by_triage_ours = Counter(t for t, _r, _d in ours)
    print("\ntriage      reference  ours")
    for level in ("Black", "Red", "Yellow", "Green"):
        print(f"  {level:<9} {by_triage_ref.get(level, 0):>9}  {by_triage_ours.get(level, 0):>4}")

    if only_ref:
        print(f"\n!! {sum(only_ref.values())} finding(s) in the REFERENCE but not ours:")
        for key, count in list(only_ref.items())[: args.show]:
            triage, reason, detail = labels[key]
            print(f"   [{triage}] x{count} {reason[:110]}")
            if detail:
                print(f"        detail: {detail[:110]}")
    else:
        print("\nOK: every reference finding is reproduced by the port.")

    if only_ours:
        print(f"\n?? {sum(only_ours.values())} finding(s) in OURS but not the reference:")
        for key, count in list(only_ours.items())[: args.show]:
            triage, reason, detail = labels[key]
            print(f"   [{triage}] x{count} {reason[:110]}")
            if detail:
                print(f"        detail: {detail[:110]}")

    return 1 if only_ref else 0


if __name__ == "__main__":
    sys.exit(main())
