#!/usr/bin/env python3
"""Fidelity harness: diff the *active* string literals in a C# source file
against those in its Python port.

The point is to catch the failure mode that matters most in this port -- a
finding string, regex or wordlist entry that was silently altered, dropped, or
un-commented during translation.

C# side:  strips // and /* */ comments, then extracts "..." literals and
          unescapes C# escape sequences.
Python side: parses with ast, so comments are excluded for free, and collects
          every string constant.

Usage:
    compare_strings.py <file.cs> <file.py>
    compare_strings.py --dir <cs_dir> <py_dir>     # pair by mapped filename
"""

import argparse
import ast
import os
import re
import sys
from typing import List, Set, Tuple

# ---------------------------------------------------------------- C# extraction

_CS_VERBATIM = re.compile(r'@"(?:[^"]|"")*"', re.S)
_CS_REGULAR = re.compile(r'"(?:\\.|[^"\\])*"', re.S)


def strip_cs_comments(source: str) -> str:
    """Remove // line comments and /* */ block comments, respecting strings."""
    out = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        # string literal: copy verbatim
        if ch == '"':
            # verbatim string @"..."
            if i > 0 and source[i - 1] == "@":
                j = i + 1
                while j < n:
                    if source[j] == '"':
                        if j + 1 < n and source[j + 1] == '"':
                            j += 2
                            continue
                        break
                    j += 1
                out.append(source[i : j + 1])
                i = j + 1
                continue
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == '"':
                    break
                j += 1
            out.append(source[i : j + 1])
            i = j + 1
            continue
        if ch == "'":
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == "'":
                    break
                j += 1
            out.append(source[i : j + 1])
            i = j + 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            j = source.find("\n", i)
            i = n if j == -1 else j
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            j = source.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_CS_ESCAPES = {
    "\\\\": "\\",
    '\\"': '"',
    "\\'": "'",
    "\\n": "\n",
    "\\r": "\r",
    "\\t": "\t",
    "\\0": "\0",
    "\\a": "\a",
    "\\b": "\b",
    "\\f": "\f",
    "\\v": "\v",
}


def unescape_cs(literal: str) -> str:
    """Turn a C# quoted literal into its runtime string value."""
    if literal.startswith('@"'):
        return literal[2:-1].replace('""', '"')
    body = literal[1:-1]
    out = []
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            pair = body[i : i + 2]
            if pair in _CS_ESCAPES:
                out.append(_CS_ESCAPES[pair])
                i += 2
                continue
            if body[i + 1] == "u" and i + 6 <= len(body):
                out.append(chr(int(body[i + 2 : i + 6], 16)))
                i += 6
                continue
            if body[i + 1] == "x":
                match = re.match(r"\\x([0-9a-fA-F]{1,4})", body[i:])
                if match:
                    out.append(chr(int(match.group(1), 16)))
                    i += len(match.group(0))
                    continue
            out.append(body[i + 1])
            i += 2
            continue
        out.append(body[i])
        i += 1
    return "".join(out)


# A C# char literal may itself contain a double quote -- `Trim('"')` is the
# real-world case. Left in place, that quote desynchronises the double-quoted
# string regex and every literal after it in the file is mis-parsed, which
# produces bogus "missing" entries and can hide genuine ones.
_CS_CHAR = re.compile(r"'(?:\\.|[^'\\\n])'")


def cs_strings(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8-sig") as handle:
        source = handle.read()
    source = strip_cs_comments(source)

    found: List[str] = []
    for match in _CS_VERBATIM.finditer(source):
        found.append(unescape_cs(match.group(0)))

    # Neutralise verbatim strings before the regular pass. The placeholder must
    # not itself look like a string literal, or every verbatim string in the file
    # shows up as a spurious empty-string difference.
    source = _CS_VERBATIM.sub(" VERBATIM_STRING ", source)
    # Neutralise char literals for the same reason (see _CS_CHAR above).
    source = _CS_CHAR.sub("'x'", source)

    for match in _CS_REGULAR.finditer(source):
        found.append(unescape_cs(match.group(0)))
    return found


# ------------------------------------------------------------- Python extraction


def py_strings(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    found: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append(node.value)
    # Drop docstrings, which are port commentary rather than data.
    docstrings: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    return [s for s in found if s not in docstrings]


# ------------------------------------------------------------------- comparison


def compare(cs_path: str, py_path: str, verbose: bool = True) -> Tuple[int, int]:
    cs = cs_strings(cs_path)
    py = py_strings(py_path)
    cs_set, py_set = set(cs), set(py)

    missing = sorted(cs_set - py_set)
    extra = sorted(py_set - cs_set)

    if verbose:
        label = f"{os.path.basename(cs_path)} -> {os.path.basename(py_path)}"
        print(f"\n=== {label}")
        print(f"    C#: {len(cs)} literals ({len(cs_set)} distinct)")
        print(f"    Py: {len(py)} literals ({len(py_set)} distinct)")
        if missing:
            print(f"    !! {len(missing)} in C# but NOT in Python:")
            for item in missing[:40]:
                print(f"       - {item!r}")
            if len(missing) > 40:
                print(f"       ... and {len(missing) - 40} more")
        if extra:
            print(f"    ?? {len(extra)} in Python but NOT in C#:")
            for item in extra[:40]:
                print(f"       + {item!r}")
            if len(extra) > 40:
                print(f"       ... and {len(extra) - 40} more")
        if not missing and not extra:
            print("    OK - string sets identical")
    return len(missing), len(extra)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cs")
    parser.add_argument("py")
    args = parser.parse_args()

    missing, extra = compare(args.cs, args.py)
    return 1 if (missing or extra) else 0


if __name__ == "__main__":
    sys.exit(main())
