#!/usr/bin/env python3
r"""
Canonicalise Group3r console output so that two runs (or a run of the original
C# and a run of a port) can be diffed.

WHY THIS IS NEEDED
------------------
Group3r's output order is nondeterministic at two levels:

 1. Per-GPO report blocks are produced on a pool of worker threads
    (LibSnaffle.Concurrency.BlockingStaticTaskScheduler, sized from the
    hard-coded GrouperOptions.MaxSysvolThreads = 15; the -t/--threads flag
    sets MaxThreads, which does NOT control this pool), so the [GPO] blocks
    and the worker threads' log lines interleave differently every run.
 2. Within a single [GPO] block, the order of the per-setting tables also
    varies between runs (observed in 3 of the 8 TestSysvol GPOs), because the
    order in which LibSnaffle's FileSystemEnumerator yields the GPO's files
    varies.

The *content* is deterministic. This script therefore sorts at both levels.

HOW IT WORKS
------------
Every NLog console line starts with a "yyyy-MM-dd HH:mm:ss +ZZ:ZZ " timestamp;
multi-line payloads ([GPO] report tables, managed stack traces) are
continuation lines with no timestamp. So:

  * split the stream into messages on timestamped lines, strip the timestamp
  * drop the wall-clock messages ("Finished at", "Group3rin' took")
  * inside each [GPO] message, split the body on the top-level "\___" setting
    delimiters and sort those setting blocks
  * sort the messages

MODES
-----
  (default)      structure-preserving canonical form (verified stable across
                 repeated runs of the mono build)
  --sort-lines   sort every line independently: a pure line-multiset form.
                 Coarser, but the strongest "nothing was lost" check.
  --drop-stacks  drop [Error] messages together with their managed stack
                 traces. Use this when comparing across runtimes/languages,
                 where exception rendering necessarily differs. See
                 HOWTO.md "Known platform divergences".

USAGE
-----
  ./normalise.py original_nice.txt > a.canon
  ./normalise.py --drop-stacks port_output.txt > b.canon
  diff a.canon b.canon
"""
import re
import sys

TS = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{2}:\d{2} ")
DROP = re.compile(r"^\[Info\] (Finished at |Group3rin')")
SETTING_DELIM = re.compile(r"^\\___\s*$")


def split_messages(raw):
    """Split console text into NLog messages (first line + continuations)."""
    first = next((i for i, l in enumerate(raw) if TS.match(l)), len(raw))
    messages, cur = [], None
    for line in raw[first:]:
        if TS.match(line):
            if cur is not None:
                messages.append(cur)
            cur = [TS.sub("", line)]
        elif cur is not None:
            cur.append(line)
    if cur is not None:
        messages.append(cur)
    return messages


def canonicalise_gpo(msg):
    """Sort the per-setting blocks inside one [GPO] report message."""
    header, blocks, cur = [], [], None
    for line in msg:
        if SETTING_DELIM.match(line):
            if cur is not None:
                blocks.append(cur)
            cur = [line]
        elif cur is not None:
            cur.append(line)
        else:
            header.append(line)
    if cur is not None:
        blocks.append(cur)
    blocks.sort(key=lambda b: "\n".join(b))
    out = list(header)
    for b in blocks:
        out.extend(b)
    return out


def main():
    argv = sys.argv[1:]
    sort_lines = "--sort-lines" in argv
    drop_stacks = "--drop-stacks" in argv
    argv = [a for a in argv if not a.startswith("--")]
    if len(argv) != 1:
        sys.stderr.write(__doc__)
        return 2

    with open(argv[0], encoding="utf-8", errors="replace") as fh:
        raw = [l.rstrip("\r") for l in fh.read().splitlines()]

    rendered = []
    for msg in split_messages(raw):
        if DROP.match(msg[0]):
            continue
        if drop_stacks and msg[0].startswith("[Error]"):
            continue
        if msg[0].startswith("[GPO]"):
            msg = canonicalise_gpo(msg)
        rendered.append(msg)

    if sort_lines:
        lines = sorted(l for msg in rendered for l in msg)
        sys.stdout.write("".join(l + "\n" for l in lines))
    else:
        rendered.sort(key=lambda m: "\n".join(m))
        sys.stdout.write("".join("\n".join(m) + "\n" for m in rendered))
    return 0


if __name__ == "__main__":
    sys.exit(main())
