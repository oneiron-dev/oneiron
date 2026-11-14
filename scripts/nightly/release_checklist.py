#!/usr/bin/env python3
"""The release checklist (Fable's test verdict 2026-11-09, section 5, PR 10d).

Standard library only. Report only: it prints each release condition of the
verdict's merge bar (the "Release" row) as MET, NOT MET or UNKNOWN with its
evidence, then one summary line:

  ## RELEASE <date> head=<12 hex> MET|NOT-MET met=<n>/7 not_met=<n> unknown=<n>

A condition whose source is missing (an input not given, or nothing that
writes it yet) is UNKNOWN, never met. Nothing calls this script as a gate.

Usage:
  release_checklist.py --tree DIR [--history FILE] [--summary FILE]
                       [--results-store FILE] [--register FILE]
                       [--today YYYY-MM-DD]

  --tree           the checkout to release
  --history        the nights' summary lines: `NIGHTLY <date> ...`
                   (run_nightly.sh) and `NIGHTLY-E2E <date> ...`
                   (nightly_e2e.py); text before the word NIGHTLY is ignored,
                   so EVENTS.log lines and `## NIGHTLY SUMMARY` echoes work
  --summary        the last cargo night's summary.json
  --results-store  the last cargo night's results-store.json
  --register       the NO-DOOR register (JSONL); default
                   $ONEIRON_TESTKIT_NO_DOOR_REGISTER, as for
                   oneiron-testkit-pending-door
  --today          the date to report (default: today, Japan time)

Exit: 0 every condition met, 1 any condition not met or unknown, 2 an input
given cannot be read.

The nightly is sharded (each night runs the lib tests, the budget tests and
the next shards of the integration tests from a cursor), so a green night is
green over the shards it ran. Condition 1 keeps the verdict's three green
nights and prints the results store's count of tests whose last run failed
beside them: that count covers the rest of the cycle.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

MET, NOT_MET, UNKNOWN = "MET", "NOT MET", "UNKNOWN"

CONDITIONS = (
    "three nightlies green",
    "zero TODO, BLOCKED, skipped or quarantined",
    "quality within two points of the 14-day best, forbidden facts zero",
    "budgets in band",
    "upgrade from the previous tag passes the core four",
    "pending-door list empty",
    "the two office failures fixed",
)

CARGO_NIGHT, E2E_NIGHT = "NIGHTLY", "NIGHTLY-E2E"
NIGHT_STATES = ("GREEN", "RED", "NOT-STARTED")
# `NIGHTLY 2026-11-15 head=... GREEN ...` or `NIGHTLY-E2E 2026-11-15 head=... set=... RED ...`
NIGHT_LINE = re.compile(r"\b(NIGHTLY(?:-E2E)?) (\d{4}-\d{2}-\d{2}) (.*)$")
NIGHTS_NEEDED = 3

# The counts condition 2 reads from the last night of each kind.
CARGO_NIGHT_COUNTS = ("skipped", "quarantined", "quarantine_gated", "new_gates")
E2E_NIGHT_COUNTS = ("blocked", "skipped")

E2E_TODO = re.compile(r"\bsuite\.todo\(")
E2E_SKIP = re.compile(r"\bsuite\.skip\(")
E2E_PENDING_DOOR = re.compile(r"\bsuite\.pendingDoor\(")
RUST_IGNORE = re.compile(r"^\s*#\[ignore\b")

REGISTER_ENV = "ONEIRON_TESTKIT_NO_DOOR_REGISTER"
EXPIRED_ROWS_SHOWN = 10

# The two office tests that failed on main 391509654610 (fleet job 1109-201851-a9f7),
# as the nightly's results store keys them: `<binary id> <test name>`.
OFFICE_TESTS = (
    (
        "oneiron-docedit::revisions archive_preflight_refuses_entry_part_and_cumulative_inflation",
        "crates/oneiron-docedit/tests/revisions.rs",
        "#6898",
    ),
    (
        "oneiron-docedit::stemma_reader start_tag_with_many_attributes_parses_in_bounded_time",
        "crates/oneiron-docedit/tests/stemma_reader.rs",
        "#6907",
    ),
)

JAPAN = timezone(timedelta(hours=9))


class InputError(Exception):
    """An input that was given cannot be read."""


@dataclass
class Inputs:
    tree: Path
    today: str
    nights: dict[str, dict[str, dict]] | None
    summary: dict | None
    store: dict | None
    register: list[dict] | None
    register_path: str


def read_history(text: str) -> dict[str, dict[str, dict]]:
    """night date -> kind -> {"state", "fields"}; a later line of a kind on the same night wins."""
    nights: dict[str, dict[str, dict]] = {}
    for line in text.splitlines():
        match = NIGHT_LINE.search(line)
        if match is None:
            continue
        kind, night, rest = match.groups()
        words = rest.split()
        state = next((word for word in words if "=" not in word), None)
        if state not in NIGHT_STATES:
            continue
        fields = dict(word.split("=", 1) for word in words if "=" in word)
        nights.setdefault(night, {})[kind] = {"state": state, "fields": fields}
    return nights


def last_night(nights: dict[str, dict[str, dict]] | None, kind: str) -> tuple[str, dict] | None:
    if not nights:
        return None
    for night in sorted(nights, reverse=True):
        if kind in nights[night]:
            return night, nights[night][kind]
    return None


def read_json(path: str, what: str) -> dict:
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise InputError(f"{what} {path}: {error}") from error
    if not isinstance(value, dict):
        raise InputError(f"{what} {path}: not a JSON object")
    return value


def read_register(path: str) -> list[dict]:
    try:
        text = Path(path).read_text()
    except OSError as error:
        raise InputError(f"register {path}: {error}") from error
    rows = []
    for at, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as error:
            raise InputError(f"register {path} line {at}: {error}") from error
        if not isinstance(row, dict):
            raise InputError(f"register {path} line {at}: not a JSON object")
        rows.append(row)
    return rows


def workspace_sources(tree: Path) -> list[Path]:
    """The .rs files of the workspace's member packages.

    A Cargo.toml `exclude` entry is left out, and so is any package nested in a
    member's directory (vendored crates, fixtures): cargo never runs their tests.
    """
    try:
        workspace = tomllib.loads((tree / "Cargo.toml").read_text()).get("workspace", {})
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InputError(f"tree {tree}: Cargo.toml: {error}") from error
    excluded = {(tree / entry).resolve() for entry in workspace.get("exclude", [])}
    members = sorted(
        {
            path.resolve()
            for pattern in workspace.get("members", [])
            for path in tree.glob(pattern)
            if (path / "Cargo.toml").is_file()
        }
        - excluded
    )
    files = []
    for member in members:
        for directory, subdirectories, names in os.walk(member):
            here = Path(directory)
            subdirectories[:] = sorted(
                name for name in subdirectories if name != "target" and not (here / name / "Cargo.toml").is_file()
            )
            files += [here / name for name in sorted(names) if name.endswith(".rs")]
    return files


def count_lines(files: list[Path], pattern: re.Pattern[str]) -> int:
    total = 0
    for path in files:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        total += sum(1 for line in text.splitlines() if pattern.search(line))
    return total


def e2e_files(tree: Path) -> list[Path]:
    root = tree / "tests" / "e2e"
    if not root.is_dir():
        return []
    return sorted(path for path in root.rglob("*.test.ts") if "node_modules" not in path.parts)


def git(tree: Path, *args: str) -> str:
    try:
        done = subprocess.run(["git", "-C", str(tree), *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def three_nights_green(inputs: Inputs) -> tuple[str, list[str]]:
    if inputs.nights is None:
        return UNKNOWN, ["no --history given"]
    dates = sorted(night for night in inputs.nights if night <= inputs.today)[-NIGHTS_NEEDED:]
    evidence = []
    green = len(dates) == NIGHTS_NEEDED
    if not green:
        evidence.append(f"{len(dates)} night(s) in the history, {NIGHTS_NEEDED} needed")
    for night in dates:
        for kind in (CARGO_NIGHT, E2E_NIGHT):
            entry = inputs.nights[night].get(kind)
            if entry is None:
                evidence.append(f"{night} {kind}: no line")
                green = False
                continue
            evidence.append(f"{night} {kind}: {entry['state']} head={entry['fields'].get('head', '?')}")
            green = green and entry["state"] == "GREEN"
    if inputs.store is not None:
        failed = sum(1 for value in inputs.store.values() if isinstance(value, dict) and value.get("outcome") == "fail")
        evidence.append(
            f"results store: {failed} of {len(inputs.store)} test(s) failed at their last run"
            " (a night runs its own shards only)"
        )
    return (MET if green else NOT_MET), evidence


def nothing_left_out(inputs: Inputs) -> tuple[str, list[str]]:
    sources = workspace_sources(inputs.tree)
    tests = e2e_files(inputs.tree)
    counts = [
        ("e2e suite.todo cases (BLOCKED)", count_lines(tests, E2E_TODO)),
        ("e2e suite.skip cases", count_lines(tests, E2E_SKIP)),
        ("#[ignore] tests in workspace members", count_lines(sources, RUST_IGNORE)),
        (".config/test-quarantine.toml rows", quarantine_rows(inputs.tree)),
    ]
    missing = []
    for kind, keys in ((CARGO_NIGHT, CARGO_NIGHT_COUNTS), (E2E_NIGHT, E2E_NIGHT_COUNTS)):
        found = last_night(inputs.nights, kind)
        if found is None:
            missing.append(f"no {kind} line")
            continue
        night, entry = found
        for key in keys:
            value = entry["fields"].get(key, "")
            if value.isdigit():
                counts.append((f"{kind} {night} {key}", int(value)))
            else:
                missing.append(f"{kind} {night}: no {key}=")
    evidence = [f"{name}: {count}" for name, count in counts] + missing
    if any(count for _, count in counts):
        return NOT_MET, evidence
    return (UNKNOWN if missing else MET), evidence


def quarantine_rows(tree: Path) -> int:
    path = tree / ".config" / "test-quarantine.toml"
    if not path.is_file():
        return 0
    try:
        tests = tomllib.loads(path.read_text()).get("test", [])
    except tomllib.TOMLDecodeError as error:
        raise InputError(f"{path}: {error}") from error
    return len(tests)


def quality(_inputs: Inputs) -> tuple[str, list[str]]:
    return UNKNOWN, [
        "no source: nothing writes a quality score or a forbidden-facts count yet"
        " (the scores table, QC-SCORES, is not decided); FIX [RELEASE-CHECK-QUALITY-NO-SOURCE]"
    ]


def budgets_in_band(inputs: Inputs) -> tuple[str, list[str]]:
    if inputs.summary is None:
        return UNKNOWN, ["no --summary given"]
    budget = inputs.summary.get("budget")
    if not isinstance(budget, dict):
        return UNKNOWN, ["the summary has no budget report"]
    tests = budget.get("tests", [])
    not_run = budget.get("not_run", [])
    bands = Counter(test.get("band", "?") for test in tests)
    evidence = [
        f"night {inputs.summary.get('date', '?')} head={str(inputs.summary.get('head', '?'))[:12]}"
        f" on {budget.get('host', '?')}: "
        + ", ".join(f"{band} {bands[band]}" for band in sorted(bands))
        + f", not run {len(not_run)}"
    ]
    evidence += [f"{test.get('test', '?')}: {test.get('band', '?')}" for test in tests if test.get("band") != "in"]
    evidence += [f"not run: {row.get('id', '?')} ({row.get('reason', '?')})" for row in not_run]
    if not tests and not not_run:
        evidence.append("no budget test measured")
    met = bool(tests) and set(bands) == {"in"} and not not_run
    return (MET if met else NOT_MET), evidence


def upgrade(inputs: Inputs) -> tuple[str, list[str]]:
    tag = git(
        inputs.tree,
        "for-each-ref",
        "--sort=-creatordate",
        "--count=1",
        "--format=%(refname:short) %(creatordate:short)",
        "refs/tags",
    )
    return UNKNOWN, [
        "no source: no upgrade harness in the tree, and the core four E2E flows are not named in the repo;"
        " FIX [RELEASE-CHECK-UPGRADE-NO-HARNESS]",
        f"previous tag: {tag or 'none found'}",
    ]


def pending_door_empty(inputs: Inputs) -> tuple[str, list[str]]:
    counts = [("e2e suite.pendingDoor cases", count_lines(e2e_files(inputs.tree), E2E_PENDING_DOOR))]
    evidence = []
    missing = False
    if inputs.register is None:
        evidence.append(f"no register: no --register given and {REGISTER_ENV} is unset")
        missing = True
    else:
        # A row naming no test is a door row (pending_door.rs reads it the same way).
        waiting = [row for row in inputs.register if row.get("test")]
        e2e = sum(1 for row in waiting if row.get("crate") == "e2e")
        expired = sorted(
            (row for row in waiting if str(row.get("deadline", "9999-12-31")) < inputs.today),
            key=lambda row: (str(row.get("deadline")), str(row.get("row"))),
        )
        counts.append((f"register {inputs.register_path} waiting tests and cases", len(waiting)))
        evidence.append(
            f"register: {len(waiting) - e2e} Rust test(s), {e2e} E2E case(s), {len(expired)} past their deadline"
        )
        evidence += [
            f"door or delete: {row.get('row', '?')} {row.get('file', '?')}::{row.get('test')} (deadline {row.get('deadline')})"
            for row in expired[:EXPIRED_ROWS_SHOWN]
        ]
        if len(expired) > EXPIRED_ROWS_SHOWN:
            evidence.append(f"... and {len(expired) - EXPIRED_ROWS_SHOWN} more past their deadline")
    found = last_night(inputs.nights, CARGO_NIGHT)
    if found is not None:
        night, entry = found
        for key in ("pending", "expired"):
            value = entry["fields"].get(key, "")
            if value.isdigit():
                counts.append((f"{CARGO_NIGHT} {night} {key}", int(value)))
    evidence = [f"{name}: {count}" for name, count in counts] + evidence
    if any(count for _, count in counts):
        return NOT_MET, evidence
    return (UNKNOWN if missing else MET), evidence


def office_fixed(inputs: Inputs) -> tuple[str, list[str]]:
    evidence = []
    outcomes = []
    for key, file, fixed_by in OFFICE_TESTS:
        name = key.split(" ", 1)[1]
        source = inputs.tree / file
        if not source.is_file() or f"fn {name}(" not in source.read_text(errors="replace"):
            evidence.append(f"{key}: not in the tree ({file})")
            outcomes.append("absent")
            continue
        last = inputs.store.get(key) if inputs.store is not None else None
        if not isinstance(last, dict):
            where = "no --results-store given" if inputs.store is None else "not in the results store"
            evidence.append(f"{key}: {where} (fixed by {fixed_by})")
            outcomes.append("absent")
            continue
        evidence.append(f"{key}: {last.get('outcome', '?')} on {last.get('date', '?')} (fixed by {fixed_by})")
        outcomes.append(str(last.get("outcome")))
    if "fail" in outcomes:
        return NOT_MET, evidence
    return (MET if set(outcomes) == {"pass"} else UNKNOWN), evidence


CHECKS = (three_nights_green, nothing_left_out, quality, budgets_in_band, upgrade, pending_door_empty, office_fixed)


def load(args: argparse.Namespace) -> Inputs:
    tree = Path(args.tree)
    if not (tree / "Cargo.toml").is_file():
        raise InputError(f"tree {tree}: no Cargo.toml")
    nights = None
    if args.history:
        try:
            nights = read_history(Path(args.history).read_text(errors="replace"))
        except OSError as error:
            raise InputError(f"history {args.history}: {error}") from error
    register_path = args.register or os.environ.get(REGISTER_ENV, "")
    return Inputs(
        tree=tree,
        today=args.today or datetime.now(JAPAN).date().isoformat(),
        nights=nights,
        summary=read_json(args.summary, "summary") if args.summary else None,
        store=read_json(args.results_store, "results store") if args.results_store else None,
        register=read_register(register_path) if register_path else None,
        register_path=register_path,
    )


def iso_date(text: str) -> str:
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not a YYYY-MM-DD date: {text}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print each release condition as MET, NOT MET or UNKNOWN.")
    parser.add_argument("--tree", required=True, help="the checkout to release")
    parser.add_argument("--history", help="the NIGHTLY and NIGHTLY-E2E summary lines")
    parser.add_argument("--summary", help="the last cargo night's summary.json")
    parser.add_argument("--results-store", help="the last cargo night's results-store.json")
    parser.add_argument("--register", help=f"the NO-DOOR register (default ${REGISTER_ENV})")
    parser.add_argument("--today", type=iso_date, help="the date to report (default: today, Japan time)")
    args = parser.parse_args(argv)
    try:
        inputs = load(args)
        results = [check(inputs) for check in CHECKS]
    except InputError as error:
        print(f"release_checklist: {error}", file=sys.stderr)
        return 2
    head = git(inputs.tree, "rev-parse", "HEAD")[:12] or "unknown"
    print(f"Release checklist {inputs.today} head={head} (Fable's test verdict, section 5; report only)")
    for number, (name, (state, evidence)) in enumerate(zip(CONDITIONS, results, strict=True), 1):
        print(f"{number}. [{state}] {name}")
        for line in evidence:
            print(f"   {line}")
    states = [state for state, _ in results]
    met = states.count(MET) == len(CONDITIONS)
    print(
        f"## RELEASE {inputs.today} head={head} {'MET' if met else 'NOT-MET'}"
        f" met={states.count(MET)}/{len(CONDITIONS)} not_met={states.count(NOT_MET)} unknown={states.count(UNKNOWN)}"
    )
    return 0 if met else 1


if __name__ == "__main__":
    sys.exit(main())
