#!/usr/bin/env python3
"""Ratchet metric 7, raw_hasher_starts: hashes started by hand outside the fingerprint door.

Counts every match of

    blake3::(hash|derive_key|keyed_hash)(    blake3::Hasher::new    Sha256::(new|digest)(

in .rs files under crates/*/src, with check.sh's file rule (no `tests` directory
component; the name is not tests.rs, *_tests.rs or tests_*.rs), outside what
scripts/ratchet/raw_hasher_allowlist.txt lists. The count only goes down: a new hash
goes through `oneiron_contracts::fingerprint` (a v1 purpose) or `ContentHash`, and each
PLAN-UC-04 stage 1-7 PR lowers baseline.json's count (lead, 15 Nov 13:55,
UC-04-LONG-TAIL = A). After stage 0 lands, the pipeline pre-flight runs `--check` on
the PR merged into main, against main's baseline.json.

It also prints `legacy_purposes`: the entries of the `legacy_purposes!` blocks under
crates/oneiron-fingerprint/src/purposes/, less the test-only testing.rs. That count is printed only and never gated;
it rises when a stage 1-7 PR moves a stored digest onto the K door and falls in stage 9.

Usage:
  raw_hasher_starts.py [TREE]                     both counts
  raw_hasher_starts.py --count [TREE]             the raw_hasher_starts count alone (check.sh)
  raw_hasher_starts.py --list [TREE]              every counted start, as path:line: text
  raw_hasher_starts.py --check [--baseline FILE] [TREE]
      the merge gate: exit 1 when the count is above the baseline's raw_hasher_starts
      count (default FILE: TREE/scripts/ratchet/baseline.json)

TREE defaults to the current directory. Exit 2, never a silent pass, on a missing tree,
an allowlist line without a scope or a reason, or an unreadable baseline.
"""

import argparse
import json
import pathlib
import re
import sys

START = re.compile(
    r"blake3::(?:hash|derive_key|keyed_hash)\(|blake3::Hasher::new|Sha256::(?:new|digest)\("
)
SHA256_START = re.compile(r"Sha256::(?:new|digest)\(")
ALLOWLIST = "scripts/ratchet/raw_hasher_allowlist.txt"
BASELINE = "scripts/ratchet/baseline.json"
REGISTRY = "crates/oneiron-fingerprint/src/purposes"
# An invocation at the start of a line, so the example in a doc comment never counts.
LEGACY_BLOCK = re.compile(r"^legacy_purposes!\s*\{(.*?)^\}", re.S | re.M)
LEGACY_ENTRY = re.compile(r"^\s*[A-Z][A-Z0-9_]*\s*=\s*\(", re.M)
SCOPES = ("all", "sha256")


def fail(message):
    print(f"raw_hasher_starts: ERROR: {message}", file=sys.stderr)
    sys.exit(2)


def counted_file(relative):
    """check.sh's rule: crates/<crate>/src/..., no tests dir, no test file name."""
    parts = relative.split("/")
    name = parts[-1]
    if len(parts) < 4 or parts[0] != "crates" or parts[2] != "src":
        return False
    return not (
        "tests" in parts[:-1]
        or name == "tests.rs"
        or name.endswith("_tests.rs")
        or name.startswith("tests_")
    )


def read_allowlist(tree):
    """Lines `<path> <scope>  # <reason>`; a path ending in / covers a directory."""
    path = tree / ALLOWLIST
    if not path.is_file():
        fail(f"{ALLOWLIST} is missing")
    entries = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        body, _, reason = line.partition("#")
        fields = body.split()
        if len(fields) != 2 or fields[1] not in SCOPES or not reason.strip():
            fail(f"{ALLOWLIST}:{number}: want `<path> <all|sha256>  # <reason>`: {line!r}")
        if not (tree / fields[0]).exists():
            print(f"raw_hasher_starts: stale allowlist entry {fields[0]}", file=sys.stderr)
        entries.append((fields[0], fields[1]))
    return entries


def allowed_scope(relative, entries):
    """The widest scope an allowlist entry gives this file, or None."""
    scopes = {
        scope
        for prefix, scope in entries
        if relative == prefix or (prefix.endswith("/") and relative.startswith(prefix))
    }
    if "all" in scopes:
        return "all"
    return "sha256" if scopes else None


def starts(tree):
    """Every counted start, as (path, line, text), in path order."""
    entries = read_allowlist(tree)
    hits = []
    for source in sorted((tree / "crates").glob("*/src/**/*.rs")):
        relative = source.relative_to(tree).as_posix()
        if not counted_file(relative):
            continue
        scope = allowed_scope(relative, entries)
        if scope == "all":
            continue
        text = source.read_text(errors="replace")
        lines = None
        for match in START.finditer(text):
            if scope == "sha256" and SHA256_START.match(match.group(0)):
                continue
            if lines is None:
                lines = text.splitlines()
            line = text.count("\n", 0, match.start()) + 1
            hits.append((relative, line, lines[line - 1].strip()))
    return hits


def legacy_purposes(tree):
    """Legacy purposes of the engine areas; the test-only area does not count."""
    count = 0
    for source in sorted((tree / REGISTRY).glob("**/*.rs")):
        if source.name == "testing.rs":
            continue
        for block in LEGACY_BLOCK.finditer(source.read_text()):
            count += len(LEGACY_ENTRY.findall(block.group(1)))
    return count


def baseline_count(path):
    try:
        metrics = json.loads(path.read_text())["metrics"]
        count = metrics["raw_hasher_starts"]["count"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        fail(f"cannot read the raw_hasher_starts count from {path}: {error}")
    if not isinstance(count, int) or count < 0:
        fail(f"{path}: raw_hasher_starts count is not a non-negative integer")
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--count", action="store_true")
    mode.add_argument("--list", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("tree", nargs="?", default=".", type=pathlib.Path)
    args = parser.parse_args()
    tree = args.tree.resolve()
    if not (tree / "crates").is_dir():
        fail(f"{tree} has no crates/ directory")
    hits = starts(tree)
    if args.count:
        print(len(hits))
    elif args.list:
        for relative, line, text in hits:
            print(f"{relative}:{line}: {text}")
    elif args.check:
        baseline = baseline_count(args.baseline or tree / BASELINE)
        if len(hits) > baseline:
            print(
                f"RAW-HASHER-STARTS-FAIL {len(hits)} > baseline {baseline} "
                f"(+{len(hits) - baseline}): a new hash goes through "
                "oneiron_contracts::fingerprint (a v1 purpose) or ContentHash; "
                "--list prints every start"
            )
            sys.exit(1)
        print(f"raw_hasher_starts ok: {len(hits)} <= baseline {baseline}")
    else:
        print(f"raw_hasher_starts: {len(hits)}")
        print(f"legacy_purposes: {legacy_purposes(tree)}")


if __name__ == "__main__":
    main()
