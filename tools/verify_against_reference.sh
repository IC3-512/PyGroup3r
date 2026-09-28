#!/usr/bin/env bash
# Run this port with the same flags as the captured C# reference runs and diff the
# findings of each pair.
#
# The reference files under reference/ come from the real C# Group3r compiled for
# net48 and run under mono against upstream/TestSysvol -- see reference/HOWTO.md.
# Two asymmetries are expected and documented there:
#   * mono cannot read local NTFS ACLs, so 4 script settings throw and are lost
#     from the reference (2 of them carry a password-in-arguments finding),
#   * the reference is the *sidfallback* build so that Group3r's own well-known
#     SID table is reached.
# Therefore "in REFERENCE but not ours" must be empty; "in ours but not the
# reference" is allowed to contain those script findings.

set -uo pipefail
cd "$(dirname "$0")/.."

SYSVOL=upstream/TestSysvol
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

REF_DEFAULT=reference/original_nice_sidfallback.txt
declare -a FAILED=()

run_case() {
    local name="$1" ref="$2"; shift 2
    if [[ ! -f "$ref" ]]; then
        echo "--- $name: SKIP (no reference file $ref)"
        return
    fi
    local ours="$OUT/$name.txt"
    python3 -m group3rpy -o -y "$SYSVOL" -f "$ours" "$@" >/dev/null 2>&1
    echo "--- $name  (flags: ${*:-none})"
    if python3 tools/compare_reports.py "$ref" "$ours" --show 6 \
        | sed -n '1,3p;/^!!/,$p;/^OK:/p'
    then
        :
    else
        FAILED+=("$name")
    fi
}

echo "=== findings parity vs the compiled C# original ==="
run_case default      "$REF_DEFAULT"
run_case mintriage1   reference/original_nice_mintriage1.txt   -a 1
run_case mintriage2   reference/original_nice_mintriage2.txt   -a 2
run_case mintriage3   reference/original_nice_mintriage3.txt   -a 3
run_case mintriage4   reference/original_nice_mintriage4.txt   -a 4
run_case findingsonly reference/original_nice_findingsonly.txt -w
run_case enabledonly  reference/original_nice_enabledonly.txt  -e
run_case currentonly  reference/original_nice_currentonly.txt  -r

echo
if (( ${#FAILED[@]} )); then
    echo "FAIL: reference findings missing from the port in: ${FAILED[*]}"
    exit 1
fi
echo "PASS: every reference finding is reproduced in every variant."
