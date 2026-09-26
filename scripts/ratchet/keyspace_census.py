#!/usr/bin/env python3
"""Ratchet metric: raw `vault_meta` calls outside the typed side-table door.

Counts every call of the shape

    vault_meta . get | put | delete | prefix_iter | range | rev_range

(any receiver, `vault_meta()` included, whitespace and line breaks allowed
around the dot) in non-test Rust files under crates/oneiron/src, outside the
three places that own the table: `side_table/` (the typed keyspace every module
reads and writes its rows through), `ports/` (the storage ports) and
`store/open_gates/` (the storage ABI and manifest handshake rows). Target: 0.

Non-test file: the same definition scripts/ratchet/check.sh uses — no `tests/`
path component, filename is not `tests.rs`, does not end `_tests.rs` and does
not start `tests_`. Whole-line `//` comments (doc comments included) are not
counted, so prose that names the table is not a call.

Output: ONE integer on stdout, exit 0. With --list: one `path:line` line per
call, sorted, for humans reading the number.

Fails CLOSED like check.sh: an unreadable file or a scan that finds no source
files prints `RATCHET-ERROR: ...` on stderr and exits 1, never a silent 0.
"""

import os
import re
import sys

ROOT = "crates/oneiron/src"
DOORS = ("side_table/", "ports/", "store/open_gates/")
CALL = re.compile(r"\bvault_meta(\(\))?\s*\.\s*(get|put|delete|prefix_iter|range|rev_range)\b")


def is_test(rel):
    parts = rel.split("/")
    name = parts[-1]
    return (
        "tests" in parts[:-1]
        or name == "tests.rs"
        or name.endswith("_tests.rs")
        or name.startswith("tests_")
    )


def uncommented(text):
    return "\n".join("" if line.lstrip().startswith("//") else line for line in text.split("\n"))


def main():
    repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    root = os.path.join(repo, ROOT)
    hits = []
    scanned = 0
    for directory, _, files in os.walk(root):
        for name in files:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(directory, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if is_test(rel) or rel.startswith(DOORS):
                continue
            try:
                with open(path, encoding="utf-8") as handle:
                    text = uncommented(handle.read())
            except OSError as error:
                print(f"RATCHET-ERROR: cannot read {path}: {error}", file=sys.stderr)
                return 1
            scanned += 1
            for match in CALL.finditer(text):
                hits.append((rel, text.count("\n", 0, match.start()) + 1))
    if scanned == 0:
        print("RATCHET-ERROR: keyspace census scanned no source files", file=sys.stderr)
        return 1
    if "--list" in sys.argv[1:]:
        for rel, line in sorted(hits):
            print(f"{ROOT}/{rel}:{line}")
    else:
        print(len(hits))
    return 0


if __name__ == "__main__":
    sys.exit(main())
