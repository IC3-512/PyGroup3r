#!/usr/bin/env python3
"""Sweep every ported file through the string-fidelity harness and summarise.

This is the top-level fidelity gate for the port: for each C# source file it
diffs the set of *active* string literals (comments stripped, C# escapes decoded,
char and verbatim literals neutralised) against its Python counterpart.

Differences are classified rather than just counted, because some are expected:
  * MISSING  -- a C# literal absent from the port. Always worth investigating;
                this is how a dropped finding reason or rule entry shows up.
  * EXTRA    -- a Python literal with no C# counterpart. Usually benign: enum
                member names, type annotations, encoding names, ANSI escapes,
                struct format strings, argparse flag spellings.

Run:  python3 tools/verify_all.py [--verbose]
Exit code is non-zero if any file has MISSING literals.
"""

import argparse
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compare_strings import cs_strings, py_strings  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UP = os.path.join(ROOT, "upstream")
PY = os.path.join(ROOT, "group3rpy")

# Literals that are expected to appear only on the Python side. Each entry is a
# predicate over the string; anything matching is not reported as a surprise.
_BENIGN_EXTRA = [
    # Python type annotations written as strings (forward refs).
    lambda s: bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\[\], |]*(\| None)?", s)) and (
        "|" in s or s.endswith("Setting") or s in {"Sddl", "RegHive", "RegKeyValType"}
    ),
    # Encoding names and codec error modes.
    lambda s: s in {"utf-8", "utf-16-le", "utf-16-be", "utf-8-sig", "latin-1", "replace", "ignore", "strict", "ascii", "unicode"},
    # struct format strings.
    lambda s: bool(re.fullmatch(r"[<>=!@][bBhHiIlLqQfd]+", s)),
    # ANSI escapes standing in for Console.ForegroundColor.
    lambda s: s.startswith("\x1b["),
    # Trivial separators/whitespace that were C# char literals.
    lambda s: s in {"", " ", "\t", "\n", "\r\n", "\r", "\x00", ",", "=", "_", '"', "'", "*", "[]", "\\", "/", ": ", ", ", ":", "|", "-", "."},
    # Empty-Guid guard mandated by the port.
    lambda s: s == "00000000-0000-0000-0000-000000000000",
]


def is_benign(value: str) -> bool:
    return any(predicate(value) for predicate in _BENIGN_EXTRA)


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


# Explicit mapping where the filename does not transliterate mechanically.
# A value may be a list when one C# file was split across several Python modules
# (or vice versa); the comparison then unions the Python side.
OVERRIDES: Dict[str, object] = {
    "LibSnaffle/ActiveDirectory/GPO/GpoSettings/FileSecurity.cs": "settings/file_security.py",
    "LibSnaffle/ActiveDirectory/GPO/GpoSettings/ShortCutSetting.cs": "settings/shortcut_setting.py",
    "LibSnaffle/ActiveDirectory/GPO/GPO.cs": "ad/gpo.py",
    "LibSnaffle/ActiveDirectory/GPO/GpoSetting.cs": "ad/gpo.py",
    "LibSnaffle/ActiveDirectory/Users/Trustee.cs": "ad/trustee.py",
    # LoadSysvolOnline moved into GroupCon, which owns the SysvolHelper.
    "LibSnaffle/ActiveDirectory/ActiveDirectory.cs": ["ad/active_directory.py", "group_con.py"],
    "LibSnaffle/ActiveDirectory/LDAP/DirectorySearch.cs": "ad/ldap_search.py",
    "LibSnaffle/ActiveDirectory/Sysvol/Sysvol.cs": "sysvol/sysvol.py",
    "LibSnaffle/ActiveDirectory/Sysvol/SysvolHelper.cs": "sysvol/sysvol.py",
    "LibSnaffle/Classifiers/Rules/Constants.cs": "classifiers/constants.py",
    "LibSnaffle/Logging/Logging.cs": "logging_setup.py",
    # Group3rRunner.cs holds both the runner and its custom NLog colour rules;
    # the port keeps the colour table with the rest of the logging setup.
    "Group3r/Group3rRunner.cs": ["runner.py", "logging_setup.py"],
    "Group3r/GroupCon.cs": "group_con.py",
    "Group3r/Assessment/GpoFinding.cs": "assessment/finding.py",
    "Group3r/Assessment/GpoResult.cs": "assessment/finding.py",
    "Group3r/Assessment/SddlAnalyser.cs": "assessment/sddl_analyser.py",
    "Group3r/Assessment/FsAclAnalyser.cs": "assessment/fs_acl_analyser.py",
    "Group3r/Assessment/PathAnalyser.cs": "assessment/path_analyser.py",
    "Group3r/Assessment/AnalyserFactory.cs": "assessment/analyser_factory.py",
    "Group3r/Options/GrouperOptions.cs": "options/grouper_options.py",
    "Group3r/Options/OptionsParser.cs": "options/options_parser.py",
    "Group3r/Options/AssessmentOptions/AssessmentOptions.cs": "options/assessment_options.py",
    "Group3r/View/IGpoPrinter.cs": "view/gpo_printer.py",
    "Group3r/View/MessageProcessor/CliMessageProcessor.cs": "view/message_processor.py",
    "Group3r/View/MessageProcessor/IMessageProcessor.cs": "view/message_processor.py",
    "Group3r/Concurrency/GrouperMq.cs": "concurrency/grouper_mq.py",
    "Group3r/Concurrency/GpoResultMessage.cs": "concurrency/messages.py",
    "Group3r/Concurrency/FileResultMessage.cs": "concurrency/messages.py",
    "LibSnaffle/Concurrency/BlockingMq.cs": "concurrency/blocking_mq.py",
    "LibSnaffle/Classifiers/Results/Result.cs": "assessment/finding.py",
    "LibSnaffle/Classifiers/Results/FileResult.cs": "assessment/finding.py",
    "LibSnaffle/Classifiers/Results/DirResult.cs": "assessment/finding.py",
    "LibSnaffle/Classifiers/Results/TextResult.cs": "assessment/finding.py",
    "LibSnaffle/Classifiers/Results/ShareResult.cs": "classifiers/share_classifier.py",
    "LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/Parsers/SchedTaskParser.cs": "sysvol/parsers/sched_task_parser.py",
    "LibSnaffle/ActiveDirectory/Sysvol/GpoFiles/Parsers/SchedTaskV2Parser.cs": "sysvol/parsers/sched_task_v2_parser.py",
}

# C# files with no Python counterpart, and why.
SKIP: Dict[str, str] = {
    "Group3r/Group3r.cs": "entry point -> __main__.py (no literals)",
    "Group3r/Properties/AssemblyInfo.cs": "assembly metadata, not behaviour",
    "LibSnaffle/Properties/AssemblyInfo.cs": "assembly metadata, not behaviour",
    "LibSnaffle/Concurrency/BlockingStaticTaskScheduler.cs": "replaced by ThreadPoolExecutor in group_con.py",
    "LibSnaffle/FileDiscovery/CurrentUserSecurity.cs": "Windows-only ACL probe; superseded by smb/provider.py",
    "LibSnaffle/FileDiscovery/FileSystemEnumerator.cs": "replaced by FsProvider.list_all_files",
    "LibSnaffle/FileDiscovery/QueueAndPath.cs": "unused helper",
    "LibSnaffle/ActiveDirectory/LDAP/Extensions.cs": "folded into ad/ldap_search.py",
    "LibSnaffle/ActiveDirectory/LDAP/Helpers.cs": "folded into ad/ldap_search.py",
    "LibSnaffle/ActiveDirectory/LDAP/LdapTypeEnum.cs": "unused by Group3r",
    "Group3r/Assessment/Analysers/Analyser.cs": "abstract base -> assessment/analysers/analyser.py",
}


def resolve(rel: str) -> Optional[List[str]]:
    if rel in SKIP:
        return None
    if rel in OVERRIDES:
        value = OVERRIDES[rel]
        names = value if isinstance(value, list) else [value]
        return [os.path.join(PY, name) for name in names]

    base = os.path.basename(rel)[:-3]
    parts = rel.split("/")

    # (directory marker, package path segments) -- first match wins.
    routes = [
        ("Analysers", ("assessment", "analysers")),
        ("GpoSettings", ("settings",)),
        ("Sddl.Parser", ("sddl",)),
        ("GpoFiles", ("sysvol",)),
        ("Rules", ("classifiers", "rules")),
        ("Classifiers", ("classifiers",)),
        ("AssessmentOptions", ("options",)),
        ("View", ("view",)),
    ]
    for marker, segments in routes:
        if marker in parts:
            return [os.path.join(PY, *segments, snake(base) + ".py")]

    if "MessageTypes" in parts:
        return [os.path.join(PY, "concurrency", "messages.py")]
    if "Errors" in parts:
        return [os.path.join(PY, "sysvol", "sysvol.py")]
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    cs_files: List[str] = []
    for dirpath, _dirs, files in os.walk(UP):
        if ".git" in dirpath:
            continue
        for name in sorted(files):
            if name.endswith(".cs"):
                cs_files.append(os.path.relpath(os.path.join(dirpath, name), UP))
    cs_files.sort()

    # Group by target, because several C# files map onto one Python module.
    by_target: Dict[str, List[str]] = {}
    skipped: List[Tuple[str, str]] = []
    unmapped: List[str] = []

    for rel in cs_files:
        if rel in SKIP:
            skipped.append((rel, SKIP[rel]))
            continue
        targets = resolve(rel)
        if targets is None:
            unmapped.append(rel)
            continue
        by_target.setdefault(tuple(targets), []).append(rel)

    clean = 0
    with_missing: List[Tuple[str, List[str]]] = []
    with_extra = 0
    missing_files: List[str] = []
    total_cs_literals = 0

    for targets in sorted(by_target):
        sources = by_target[targets]
        absent = [t for t in targets if not os.path.isfile(t)]
        if absent:
            missing_files.append(
                f"{', '.join(sources)} -> {', '.join(os.path.relpath(t, ROOT) for t in absent)}"
            )
            continue

        cs_set = set()
        for rel in sources:
            cs_set |= set(cs_strings(os.path.join(UP, rel)))
        total_cs_literals += len(cs_set)
        py_set = set()
        for target in targets:
            py_set |= set(py_strings(target))

        missing = sorted(cs_set - py_set)
        extra = [s for s in sorted(py_set - cs_set) if not is_benign(s)]

        label = " + ".join(os.path.relpath(t, ROOT) for t in targets)
        if missing:
            with_missing.append((label, missing))
            print(f"MISSING  {label}  ({len(missing)} C# literals absent)")
            for item in missing[: (None if args.verbose else 6)]:
                print(f"           - {item!r}")
            if not args.verbose and len(missing) > 6:
                print(f"           ... {len(missing) - 6} more (use --verbose)")
        elif extra:
            with_extra += 1
            print(f"ok+extra {label}  ({len(extra)} non-benign Python-only literals)")
            if args.verbose:
                for item in extra[:12]:
                    print(f"           + {item!r}")
        else:
            clean += 1
            if args.verbose:
                print(f"OK       {label}")

    print()
    print("=" * 72)
    print(f"C# files considered     : {len(cs_files)}")
    print(f"  mapped to a port      : {sum(len(v) for v in by_target.values())}")
    print(f"  intentionally skipped : {len(skipped)}")
    print(f"  unmapped (review!)    : {len(unmapped)}")
    print(f"Python modules compared : {len(by_target) - len(missing_files)}")
    print(f"  identical string sets : {clean}")
    print(f"  extra-only            : {with_extra}")
    print(f"  WITH MISSING LITERALS : {len(with_missing)}")
    print(f"Distinct C# literals    : {total_cs_literals}")
    if missing_files:
        print(f"Port file not found     : {len(missing_files)}")
        for item in missing_files:
            print(f"  ! {item}")
    if unmapped:
        print("Unmapped C# files:")
        for item in unmapped:
            print(f"  ? {item}")
    print("=" * 72)

    return 1 if (with_missing or missing_files or unmapped) else 0


if __name__ == "__main__":
    sys.exit(main())
