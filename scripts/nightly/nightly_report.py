#!/usr/bin/env python3
"""The nightly test job's report tool (Fable's test verdict 2026-11-09, PR 10a).

Standard library only. scripts/nightly/run_nightly.sh calls it; each
subcommand reads files the job wrote:

  plan METADATA [--shard-files N] [--cursor FILE] [--budget-set SET]
                                  the night's selections: the lib tests, the
                                  budget tests, then the integration tests,
                                  whole or in shards from the cursor on
  advance PLAN NAME CURSOR        move the cursor past a finished shard
  deadline HH:MM                  the epoch of the next HH:MM, Japan time
  failed-units LOG...             the test build units cargo could not compile
  prune PLAN NAME FAILED METADATA leave a selection's failed units out (exit 3
                                  when the selection is dropped)
  drop PLAN NAME REASON           drop a selection
  args PLAN [--name NAME]         `<name> <args...>` per selection, or one
                                  selection's args
  tests PLAN NAME                 a selection's integration test names
  field JSON KEY                  one top-level value of a JSON object
  census ROOT                     the lib-test quarantine gates in a tree (TSV)
  budget-filter SET [--metadata METADATA]
                                  the budget set's nextest filter (none() when
                                  the set is empty), over the workspace's
                                  packages only
  summary ...                     the night's verdict: prints the one summary
                                  line and writes summary.json, summary.txt,
                                  results-store.json, flake-row.json,
                                  budget-samples.json and budget-row.json

A quarantine gate is a `// FIX [LIBTEST-QUARANTINE-<ID>]` comment followed by
`#[cfg(any())]` on the item it switches off (OPUS-MAINFIX's lib-test
quarantine, #7561). The committed baseline
(scripts/nightly/libtest-quarantine-baseline.tsv) is the census of main when
the quarantine landed (12c169344bc3, "train: #7561"; 441 gates under 401
ids); a baseline gate that is gone from the tree is ported, and the summary
names its tests' pass or fail.

The budget set (scripts/nightly/budget-set.tsv, PR 10b) names the tests whose
time the nightly tracks (Fable's test verdict, section 3: "budget tests are
separate, nightly, compared to a per-host baseline with a 20 percent band").
Their integration test binaries run every night in the `budget` selection; a
lib test row runs where the lib tests run. A host's baseline for a test is the
median of its first 5 passing nights (budget-samples.json carries them from
night to night) until a PR commits it to scripts/nightly/budget-baseline.tsv:
the night that reaches 5 writes budget-baseline-proposal.tsv. The band is
report only: it never makes the night red.
"""

from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import statistics
import sys
import time
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

COULD_NOT_COMPILE = re.compile(r"^error: could not compile `(?P<package>[^`]+)` \((?P<unit>[^)]*)\)")
UNIT = re.compile(r'^(?P<target>lib|bin|test|example|bench|build script)(?: "(?P<name>[^"]+)")?(?P<test> test)?$')

# Failed unit kinds a selection can leave out. Any other failed unit (a lib
# itself, a build script) breaks every unit that depends on it: its selection
# is dropped.
PRUNABLE_KINDS = ("lib-test", "test", "bin-test", "bin")
# Kinds no selection builds (a plan names --lib, --bins and --test only).
UNBUILT_KINDS = ("example", "example-test", "bench", "bench-test")
# Left out of every selection, as CI's full tier leaves it out (ci.yml).
ALWAYS_EXCLUDED = ("oneiron-bench",)
# The pending-door tool's own integration test. Selected with the lib tests, it
# makes cargo build the testkit's bins (cargo builds a package's bins for its
# integration tests), so oneiron-testkit-pending-door exists before the first
# verdict run needs its filters.
DOOR_TOOL_TEST = ("oneiron-testkit", "pending_door")

GATE = re.compile(r"^\s*// FIX \[(?P<id>LIBTEST-QUARANTINE-[A-Z0-9-]+)\]")
GATE_CFG = re.compile(r"^\s*#\[cfg\(any\(\)\)\]\s*$")
ATTRIBUTE = re.compile(r"^\s*#\[")
MOD_ITEM = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
FN_ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
PACKAGE_NAME = re.compile(r'^name\s*=\s*"(?P<name>[^"]+)"')
CENSUS_COLUMNS = ("id", "package", "file", "kind", "module", "item")
GATE_ITEM_WINDOW = 80  # lines from a gate comment to its item (doc comments and attributes between)

# The lib test binaries whose results the nightly reports per module with the
# exit ignored (Engine RULING 13 Nov 16:20 on ASK PR10-NIGHTLY-OVERLAP).
LIB_REPORT_PACKAGES = ("oneiron", "oneiron-server")

STAGES = ("verdict", "libtest", "quarantine", "pending")
FLIPS_IN_ROW = 50

# The budget set and its per-host baselines (PR 10b). A row's match is = (the
# exact test name), ~ (a part of it) or ^ (its start).
BUDGET_COLUMNS = ("id", "package", "kind", "binary", "match", "test", "source", "bound")
BUDGET_KINDS = ("lib", "test")
BUDGET_MATCHES = ("=", "~", "^")
BUDGET_BASELINE_COLUMNS = ("host", "test", "seconds", "nights", "first", "last")
BUDGET_BASELINE_NIGHTS = 5  # a baseline is the median of a host's first 5 passing nights
BUDGET_BAND = 0.20
BUDGET_SAMPLES_KEPT = 30  # per host and test: the first BUDGET_BASELINE_NIGHTS, then the latest ones


def unit_kind(target: str, test: bool) -> str:
    if target == "build script":
        return "build-script"
    return f"{target}-test" if test and target != "test" else target


def failed_units(logs: list[Path]) -> list[dict[str, str]]:
    """Every `error: could not compile` unit named in the build logs, once each."""
    seen: dict[tuple[str, str, str], dict[str, str]] = {}
    for log in logs:
        for line in log.read_text(errors="replace").splitlines():
            match = COULD_NOT_COMPILE.match(line)
            if not match:
                continue
            unit = UNIT.match(match["unit"])
            if unit:
                kind = unit_kind(unit["target"], bool(unit["test"]))
                name = unit["name"] or ""
            else:
                kind, name = "other", match["unit"]
            key = (match["package"], kind, name)
            seen.setdefault(key, {"package": key[0], "kind": key[1], "name": key[2]})
    return [seen[key] for key in sorted(seen)]


def workspace_packages(metadata: dict) -> list[dict]:
    members = set(metadata["workspace_members"])
    return sorted((p for p in metadata["packages"] if p["id"] in members), key=lambda p: p["name"])


def integration_tests(package: dict) -> list[str]:
    return sorted(t["name"] for t in package["targets"] if "test" in t["kind"] and t.get("test", True))


def test_owners(metadata: dict) -> dict[str, list[str]]:
    """Integration test name -> the workspace packages that have a test target of that name."""
    owners: dict[str, list[str]] = {}
    for package in workspace_packages(metadata):
        for name in integration_tests(package):
            owners.setdefault(name, []).append(package["name"])
    return owners


def plan(
    metadata: dict,
    shard_files: int = 0,
    cursor: dict | None = None,
    always_excluded: tuple[str, ...] = ALWAYS_EXCLUDED,
    budget: list[dict[str, str]] | None = None,
) -> dict:
    """The night's selections: the lib tests, the budget tests, then the integration tests.

    `libs` selects every lib test and bin test (`--lib --bins`) and the
    pending-door tool's own test. The integration tests follow by name
    (`--test`) in sorted order: all in one selection, or in shards of
    `shard_files` names whose binaries the runner deletes once the shard has
    run. A name two packages share selects both (cargo matches a `--test` name
    in every selected package). Every selection keeps `--workspace`, so
    features unify as in a full build.

    The cursor (`{"next": <test name>, "cycle": <n>}`, Engine RULING
    NIGHTLY-SCALE 14 Nov 10:42) makes the night resumable: the shards start at
    the first name at or after `next` and wrap past the end of the list, so a
    night that stops early resumes there the next night, and a full cycle runs
    every file once. The shard that holds the list's last name ends a cycle.

    `budget` follows `libs` and runs every night: the integration tests that
    hold a budget set row (its verdict runs only the budget tests), so a host
    gets one sample a night though a shard comes round only every few nights.
    Its args are a shard's, so features unify as for the shards. It is left
    out when no row's test target is in a selected package.
    """
    owners = {
        name: [p for p in packages if p not in always_excluded] for name, packages in test_owners(metadata).items()
    }
    names = sorted(name for name, packages in owners.items() if packages)
    door_package, door_test = DOOR_TOOL_TEST
    libs_tests = [door_test] if door_package in owners.get(door_test, []) else []
    names = [name for name in names if name not in libs_tests]
    cursor = cursor or {}
    start = bisect.bisect_left(names, cursor["next"]) if cursor.get("next") else 0
    start = start if start < len(names) else 0
    ordered = names[start:] + names[:start]
    size = shard_files if shard_files > 0 else max(len(names), 1)
    selections = [{"name": "libs", "kind": "libs", "excluded": [], "bins": True, "tests": libs_tests}]
    budget_tests = sorted(
        {
            row["binary"]
            for row in budget or []
            if row["kind"] == "test" and row["package"] in owners.get(row["binary"], [])
        }
    )
    if budget_tests:
        selections.append({"name": "budget", "kind": "budget", "excluded": [], "bins": False, "tests": budget_tests})
    order = []
    for number, first in enumerate(range(0, len(ordered), size), start=1):
        tests = ordered[first : first + size]
        name = f"tests-{number:02d}"
        selections.append({"name": name, "kind": "tests", "excluded": [], "bins": False, "tests": tests})
        order.append(
            {"name": name, "first": tests[0], "last": tests[-1], "files": len(tests), "ends_cycle": names[-1] in tests}
        )
    cycle = int(cursor.get("cycle", 1))
    return {
        "always_excluded": list(always_excluded),
        "shard_files": shard_files,
        "names_total": len(names),
        "cursor_in": {"next": ordered[0] if ordered else None, "cycle": cycle},
        "cursor_out": {"next": ordered[0] if ordered else None, "cycle": cycle},
        "order": order,
        "shards_run": [],
        "selections": selections,
        "dropped": [],
        "unselected": [],
    }


def advance(chosen: dict, name: str) -> dict:
    """Move the cursor past a finished shard (run or dropped) and return it."""
    position = next(index for index, entry in enumerate(chosen["order"]) if entry["name"] == name)
    shard = chosen["order"][position]
    following = chosen["order"][(position + 1) % len(chosen["order"])]
    cursor = chosen["cursor_out"]
    cursor["next"] = following["first"]
    if shard["ends_cycle"]:
        cursor["cycle"] += 1
    if name not in chosen["shards_run"]:
        chosen["shards_run"].append(name)
    return cursor


def deadline_epoch(stop_at: str, now: float) -> int:
    """The epoch of the next HH:MM in Japan time (UTC+9, no daylight saving) after `now`."""
    hours, _, minutes = stop_at.partition(":")
    japan = timezone(timedelta(hours=9))
    moment = datetime.fromtimestamp(now, japan).replace(hour=int(hours), minute=int(minutes), second=0, microsecond=0)
    if moment.timestamp() <= now:
        moment += timedelta(days=1)
    return int(moment.timestamp())


def find_selection(chosen: dict, name: str) -> dict:
    for entry in chosen["selections"]:
        if entry["name"] == name:
            return entry
    raise SystemExit(f"nightly_report.py: no selection {name!r} in the plan")


def selection_args(chosen: dict, entry: dict) -> list[str]:
    args = ["--workspace"]
    args += [arg for package in [*chosen["always_excluded"], *entry["excluded"]] for arg in ("--exclude", package)]
    if entry["kind"] == "libs":
        args.append("--lib")
    if entry["bins"]:
        args.append("--bins")
    args += [arg for name in entry["tests"] for arg in ("--test", name)]
    return args


def drop(chosen: dict, name: str, reason: str) -> None:
    chosen["selections"].remove(find_selection(chosen, name))
    chosen["dropped"].append({"selection": name, "reason": reason})


def prune(chosen: dict, name: str, failed: list[dict[str, str]], metadata: dict) -> bool:
    """Leave the named selection's failed units out; False when the selection is dropped.

    A failed lib test or bin excludes its package from the selection (a bin is
    built for its package's integration tests); a failed bin test drops
    `--bins`; a failed test target drops its name, and with it that name in
    the other packages that share it. A failed lib or build script, or a
    failed build that names no new unit, drops the selection: what failed
    cannot be told apart from what depends on it.
    """
    entry = find_selection(chosen, name)
    owners = test_owners(metadata)
    before = json.dumps(entry, sort_keys=True)

    def leave_out(package: str, kind: str, unit_name: str, reason: str) -> None:
        row = {"selection": name, "package": package, "kind": kind, "name": unit_name, "reason": reason}
        if row not in chosen["unselected"]:
            chosen["unselected"].append(row)

    fatal = [u for u in failed if u["kind"] not in PRUNABLE_KINDS + UNBUILT_KINDS]
    if fatal:
        units = ", ".join(f"{u['package']} ({u['kind']}{' ' + u['name'] if u['name'] else ''})" for u in fatal)
        drop(chosen, name, f"did not compile: {units}")
        return False
    for unit in failed:
        package, kind, unit_name = unit["package"], unit["kind"], unit["name"]
        if kind == "bin" and package not in entry["excluded"]:
            entry["excluded"].append(package)
            leave_out(package, "package", unit_name, "its bin did not compile")
        elif kind == "lib-test" and entry["kind"] == "libs" and package not in entry["excluded"]:
            entry["excluded"].append(package)
            leave_out(package, kind, "", "did not compile")
        elif kind == "bin-test" and entry["bins"]:
            entry["bins"] = False
            leave_out(package, kind, unit_name, "did not compile (every bin test is left out)")
        elif kind == "test" and unit_name in entry["tests"]:
            entry["tests"].remove(unit_name)
            for owner in owners.get(unit_name, []):
                shared = (
                    "did not compile" if owner == package else "shares its name with a test target that did not compile"
                )
                leave_out(owner, kind, unit_name, shared)
    excluded = set(entry["excluded"]) | set(chosen["always_excluded"])
    entry["tests"] = [t for t in entry["tests"] if not all(owner in excluded for owner in owners.get(t, []))]
    entry["excluded"].sort()
    if json.dumps(entry, sort_keys=True) == before:
        drop(chosen, name, "the build failed again and named no new failed unit")
        return False
    if entry["kind"] in ("tests", "budget") and not entry["tests"]:
        drop(chosen, name, "every unit is left out")
        return False
    return True


def build_state(chosen: dict) -> str:
    if not chosen["selections"]:
        return "failed"
    return "partial" if chosen["dropped"] or chosen["unselected"] else "ok"


def package_name(manifest: Path) -> str:
    in_package = False
    for line in manifest.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        match = PACKAGE_NAME.match(stripped)
        if in_package and match:
            return match["name"]
    return manifest.parent.name


def file_module(src: Path, file: Path) -> str:
    parts = list(file.relative_to(src).with_suffix("").parts)
    if parts and parts[-1] in ("lib", "main", "mod"):
        parts.pop()
    return "::".join(parts)


def census(root: Path) -> list[dict[str, str]]:
    """Every quarantine gate under crates/*/src: a gate comment whose item carries #[cfg(any())]."""
    rows = []
    for manifest in sorted(root.glob("crates/*/Cargo.toml")):
        src = manifest.parent / "src"
        if not src.is_dir():
            continue
        package = package_name(manifest)
        for file in sorted(src.rglob("*.rs")):
            lines = file.read_text(errors="replace").splitlines()
            for index, line in enumerate(lines):
                gate = GATE.match(line)
                if not gate:
                    continue
                gated = False
                item_line = ""
                open_brackets = 0  # an attribute spread over several lines
                for following in lines[index + 1 : index + 1 + GATE_ITEM_WINDOW]:
                    if open_brackets > 0:
                        open_brackets += following.count("[") - following.count("]")
                    elif GATE_CFG.match(following):
                        gated = True
                    elif ATTRIBUTE.match(following):
                        open_brackets = following.count("[") - following.count("]")
                    elif following.strip().startswith("//") or not following.strip():
                        continue
                    else:
                        item_line = following
                        break
                if not gated:
                    continue
                module = file_module(src, file)
                if match := MOD_ITEM.match(item_line):
                    kind, module, item = "mod", "::".join(p for p in (module, match["name"]) if p), match["name"]
                elif match := FN_ITEM.match(item_line):
                    kind, item = "fn", match["name"]
                else:
                    kind, item = "item", item_line.strip()[:60]
                rows.append(
                    {
                        "id": gate["id"],
                        "package": package,
                        "file": file.relative_to(root).as_posix(),
                        "kind": kind,
                        "module": module,
                        "item": item,
                    }
                )
    rows.sort(key=lambda row: tuple(row[column] for column in CENSUS_COLUMNS))
    return rows


def census_tsv(rows: list[dict[str, str]]) -> str:
    lines = ["\t".join(CENSUS_COLUMNS)]
    lines += ["\t".join(row[column] for column in CENSUS_COLUMNS) for row in rows]
    return "\n".join(lines) + "\n"


def read_tsv(path: Path) -> list[dict[str, str]]:
    """The rows of a TSV file whose first line names its columns."""
    lines = path.read_text().splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:] if line]


def read_census_tsv(path: Path) -> list[dict[str, str]]:
    return read_tsv(path)


def gate_key(row: dict[str, str]) -> tuple[str, str, str, str]:
    return (row["id"], row["package"], row["kind"], row["item"])


def read_junit(path: Path) -> dict[str, str]:
    """`<binary id> <test name>` -> pass | fail | skip, from one nextest JUnit file."""
    outcomes: dict[str, str] = {}
    root = ElementTree.parse(path).getroot()
    for suite in root.iter("testsuite"):
        binary = suite.get("name", "")
        for case in suite.iter("testcase"):
            if case.find("failure") is not None or case.find("error") is not None:
                outcome = "fail"
            elif case.find("skipped") is not None:
                outcome = "skip"
            else:
                outcome = "pass"
            outcomes[f"{binary} {case.get('name', '')}"] = outcome
    return outcomes


def read_junit_seconds(path: Path) -> dict[str, float]:
    """`<binary id> <test name>` -> seconds, for the passed tests of one nextest JUnit file."""
    seconds: dict[str, float] = {}
    root = ElementTree.parse(path).getroot()
    for suite in root.iter("testsuite"):
        binary = suite.get("name", "")
        for case in suite.iter("testcase"):
            if any(case.find(tag) is not None for tag in ("failure", "error", "skipped")):
                continue
            try:
                seconds[f"{binary} {case.get('name', '')}"] = float(case.get("time", ""))
            except ValueError:
                continue
    return seconds


def stage_seconds(out: Path) -> dict[str, float]:
    """The passed tests' seconds in the verdict and libtest stages, where a budget test runs."""
    seconds: dict[str, float] = {}
    for stage in ("verdict", "libtest"):
        for path in sorted(out.glob(f"junit-{stage}-*.xml")):
            seconds.update(read_junit_seconds(path))
    return seconds


def stage_results(out: Path) -> dict[str, dict[str, str]]:
    """Each stage's outcomes, merged over its selections (junit-<stage>-<selection>.xml)."""
    results: dict[str, dict[str, str]] = {stage: {} for stage in STAGES}
    for stage in STAGES:
        for path in sorted(out.glob(f"junit-{stage}-*.xml")):
            results[stage].update(read_junit(path))
    return results


def stage_ends(out: Path) -> list[dict]:
    """How each stage run ended (stages.tsv: stage, selection, exit code, JUnit yes|no, ran yes|no).

    run_nightly.sh writes one row per stage run: a stage ran when nextest
    exited 0 or 100 and wrote its JUnit.
    """
    path = out / "stages.tsv"
    if not path.is_file():
        return []
    ends = []
    for line in path.read_text().splitlines():
        stage, selection, code, junit, ran = line.split("\t")
        ends.append({"stage": stage, "selection": selection, "rc": code, "junit": junit == "yes", "ran": ran == "yes"})
    return ends


def not_run_text(end: dict) -> str:
    return f"the {end['stage']} stage of {end['selection']} did not run (exit {end['rc']}{'' if end['junit'] else ', no JUnit'})"


def counts(outcomes: dict[str, str]) -> dict[str, int]:
    values = list(outcomes.values())
    return {"passed": values.count("pass"), "failed": values.count("fail"), "skipped": values.count("skip")}


def gate_tests(row: dict[str, str], libtest: dict[str, str]) -> dict[str, str]:
    """The lib test results a gate's item holds: a module's tests, or the gated test fn."""
    found = {}
    for key, outcome in libtest.items():
        binary, _, test = key.partition(" ")
        if binary != row["package"]:
            continue
        if row["kind"] == "mod":
            hit = test.startswith(row["module"] + "::")
        elif row["kind"] == "fn":
            inside = not row["module"] or test.startswith(row["module"] + "::")
            hit = inside and (test == row["item"] or test.endswith("::" + row["item"]))
        else:
            hit = False
        if hit:
            found[test] = outcome
    return found


def quarantine_report(baseline: list[dict[str, str]], tonight: list[dict[str, str]], libtest: dict[str, str]) -> dict:
    """Each baseline quarantine id: gated, or ported with its tests green, red or absent."""
    gated_keys = {gate_key(row) for row in tonight}
    baseline_keys = {gate_key(row) for row in baseline}
    by_id: dict[str, list[dict[str, str]]] = {}
    for row in baseline:
        by_id.setdefault(row["id"], []).append(row)
    ids = {}
    for gate_id, rows in sorted(by_id.items()):
        if any(gate_key(row) in gated_keys for row in rows):
            ids[gate_id] = {"state": "gated", "tests": 0, "failed": []}
            continue
        tests: dict[str, str] = {}
        for row in rows:
            tests.update(gate_tests(row, libtest))
        failed = sorted(test for test, outcome in tests.items() if outcome == "fail")
        if failed:
            state = "red"
        elif any(outcome == "pass" for outcome in tests.values()):
            state = "green"
        else:
            state = "absent"
        ids[gate_id] = {"state": state, "tests": len(tests), "failed": failed}
    new_gates = sorted({row["id"] for row in tonight if gate_key(row) not in baseline_keys})
    states = [entry["state"] for entry in ids.values()]
    return {
        "ids": ids,
        "gated": states.count("gated"),
        "ported_green": states.count("green"),
        "ported_red": states.count("red"),
        "ported_absent": states.count("absent"),
        "new_gates": new_gates,
    }


def flips(store: dict[str, dict[str, str]], tonight: dict[str, str]) -> list[dict[str, str]]:
    """Tests run tonight that went from pass to fail or from fail to pass since their own last run.

    The store holds each test's last outcome and the night it ran, so a test in
    a shard that last ran several nights ago compares with that run (Engine
    RULING NIGHTLY-SCALE: B's rule).
    """
    changed = []
    for test in sorted(set(store) & set(tonight)):
        before, after = store[test]["outcome"], tonight[test]
        if before != after and {before, after} == {"pass", "fail"}:
            changed.append({"test": test, "from": before, "to": after, "since": store[test]["date"]})
    return changed


def updated_store(store: dict[str, dict[str, str]], tonight: dict[str, str], date: str) -> dict[str, dict[str, str]]:
    return {**store, **{test: {"outcome": outcome, "date": date} for test, outcome in tonight.items()}}


def red_nights(history: list[str], red: bool) -> int:
    """Red nights in a row, tonight included (0 on a green night)."""
    if not red:
        return 0
    streak = 1
    for line in reversed([line for line in history if line.startswith("NIGHTLY ")]):
        if " RED " not in line:
            break
        streak += 1
    return streak


def read_budget_set(path: Path) -> list[dict[str, str]]:
    """The budget set's rows, checked: every column, a known kind and match, no repeated id."""
    rows = read_tsv(path)
    seen = set()
    for row in rows:
        missing = [column for column in BUDGET_COLUMNS if not row.get(column)]
        if missing:
            raise SystemExit(f"nightly_report.py: {path}: row {row.get('id', '?')} lacks {', '.join(missing)}")
        if row["kind"] not in BUDGET_KINDS or row["match"] not in BUDGET_MATCHES:
            raise SystemExit(
                f"nightly_report.py: {path}: row {row['id']}: kind {row['kind']!r}, match {row['match']!r}"
            )
        if row["id"] in seen:
            raise SystemExit(f"nightly_report.py: {path}: id {row['id']} is repeated")
        seen.add(row["id"])
    return rows


def budget_filter(rows: list[dict[str, str]], metadata: dict | None = None) -> str:
    """One nextest filter for every test the budget set names (none() for an empty set).

    With the workspace's metadata, a row whose package is not a workspace
    member is left out: nextest refuses a package() that matches no package,
    and one stale row must not stop every verdict run.
    """
    members = {package["name"] for package in workspace_packages(metadata)} if metadata else None
    terms = []
    for row in rows:
        if members is not None and row["package"] not in members:
            continue
        binary = f" & binary(={row['binary']})" if row["kind"] == "test" else ""
        if row["match"] == "^":
            test = f"/^{re.escape(row['test'])}/"
        else:
            test = row["match"] + row["test"]
        terms.append(f"(package({row['package']}) & kind({row['kind']}){binary} & test({test}))")
    return " | ".join(terms) or "none()"


def budget_row_matches(row: dict[str, str], key: str) -> bool:
    """A JUnit key (`<binary id> <test name>`) is one of the row's tests.

    nextest's binary id is the package for a lib test and
    `<package>::<test target>` for an integration test.
    """
    binary, _, test = key.partition(" ")
    if binary != (row["package"] if row["kind"] == "lib" else f"{row['package']}::{row['binary']}"):
        return False
    if row["match"] == "=":
        return test == row["test"]
    if row["match"] == "~":
        return row["test"] in test
    return test.startswith(row["test"])


def budget_not_run_reason(row: dict[str, str], chosen: dict, gates: list[dict[str, str]]) -> str:
    if row["package"] in chosen["always_excluded"]:
        return f"{row['package']} is left out of the nightly"
    if row["kind"] == "lib":
        probe = {f"{row['package']} {row['test']}": "pass"}
        for gate in gates:
            if gate_tests(gate, probe):
                return f"quarantined ({gate['id']})"
    return "no result tonight"


def updated_samples(
    samples: dict[str, dict[str, list[dict]]], host: str, date: str, head: str, seconds: dict[str, float]
) -> dict[str, dict[str, list[dict]]]:
    """Tonight's passing budget times added to the host's samples (one per night; a rerun replaces it)."""
    kept = {name: {test: list(series) for test, series in tests.items()} for name, tests in samples.items()}
    later = BUDGET_SAMPLES_KEPT - BUDGET_BASELINE_NIGHTS
    for test, value in seconds.items():
        series = [sample for sample in kept.setdefault(host, {}).get(test, []) if sample["date"] != date]
        series.append({"date": date, "head": head[:12], "seconds": value})
        series.sort(key=lambda sample: sample["date"])
        kept[host][test] = series[:BUDGET_BASELINE_NIGHTS] + series[BUDGET_BASELINE_NIGHTS:][-later:]
    return kept


def budget_band(seconds: float, baseline: float) -> str:
    if seconds > baseline * (1 + BUDGET_BAND):
        return "over"
    if seconds < baseline * (1 - BUDGET_BAND):
        return "under"
    return "in"


def budget_report(
    rows: list[dict[str, str]],
    tonight: dict[str, str],
    seconds: dict[str, float],
    samples: dict[str, dict[str, list[dict]]],
    committed: list[dict[str, str]],
    not_run_reason: Callable[[dict[str, str]], str],
    host: str,
    date: str,
    head: str,
) -> dict:
    """Each budget test run tonight against its host's baseline: the committed row, else the first 5 samples."""
    tested = {test for row in rows for test in tonight if budget_row_matches(row, test)}
    kept = updated_samples(samples, host, date, head, {t: s for t, s in seconds.items() if t in tested})
    baselines = {(row["host"], row["test"]): row for row in committed}
    tests, not_run, proposed = [], [], []
    for row in rows:
        keys = sorted(test for test in tonight if budget_row_matches(row, test))
        if not keys:
            not_run.append({"id": row["id"], "reason": not_run_reason(row)})
        for test in keys:
            entry = {"id": row["id"], "test": test, "outcome": tonight[test], "seconds": seconds.get(test)}
            tests.append(entry)
            if entry["outcome"] != "pass" or entry["seconds"] is None:
                entry["band"] = "no-sample"
                continue
            series = kept.get(host, {}).get(test, [])
            if (host, test) in baselines:
                committed_row = baselines[(host, test)]
                entry.update(baseline=float(committed_row["seconds"]), source="committed")
            elif len(series) >= BUDGET_BASELINE_NIGHTS:
                first = series[:BUDGET_BASELINE_NIGHTS]
                entry.update(baseline=statistics.median(sample["seconds"] for sample in first), source="samples")
                proposed.append(
                    {
                        "host": host,
                        "test": test,
                        "seconds": f"{entry['baseline']:.3f}",
                        "nights": str(BUDGET_BASELINE_NIGHTS),
                        "first": first[0]["date"],
                        "last": first[-1]["date"],
                    }
                )
            else:
                entry.update(band="pending", nights=len(series))
                continue
            entry["band"] = budget_band(entry["seconds"], entry["baseline"])
    bands = [entry["band"] for entry in tests]
    proposal = sorted([*committed, *proposed], key=lambda row: (row["host"], row["test"])) if proposed else []
    return {
        "host": host,
        "tests": tests,
        "not_run": not_run,
        "in": bands.count("in"),
        "out": bands.count("over") + bands.count("under"),
        "pending": bands.count("pending"),
        "no_sample": bands.count("no-sample"),
        "proposed": len(proposed),
        "proposal": proposal,
        "samples": kept,
    }


def budget_text(entry: dict, host: str) -> str:
    if entry["band"] == "no-sample":
        return f"budget {entry['test']}: {entry['outcome']} tonight, no sample"
    if entry["band"] == "pending":
        return (
            f"budget {entry['test']}: {entry['seconds']:.2f} s, baseline pending"
            f" ({entry['nights']}/{BUDGET_BASELINE_NIGHTS} nights on {host})"
        )
    change = (entry["seconds"] / entry["baseline"] - 1) * 100 if entry["baseline"] else 0.0
    return (
        f"budget {entry['test']}: {entry['seconds']:.2f} s, baseline {entry['baseline']:.2f} s ({entry['source']}),"
        f" {entry['band']} band ({change:+.0f}%)"
    )


def summary(args: argparse.Namespace) -> int:
    out = Path(args.out)
    chosen = json.loads(Path(args.plan).read_text())
    build = build_state(chosen)
    shards_run = len(chosen["shards_run"])
    pending_door = json.loads(Path(args.pending_door).read_text()) if Path(args.pending_door).is_file() else None
    results = stage_results(out)
    stages_not_run = [end for end in stage_ends(out) if not end["ran"]]
    verdict_not_run = [end for end in stages_not_run if end["stage"] == "verdict"]
    verdict = counts(results["verdict"])
    libtest = counts(results["libtest"])
    quarantined = counts(results["quarantine"])
    pending_run = counts(results["pending"])
    gates = census(Path(args.census_root))
    report = quarantine_report(read_census_tsv(Path(args.baseline)), gates, results["libtest"])
    tonight = {**results["libtest"], **results["verdict"]}
    store = json.loads(Path(args.previous).read_text()) if args.previous and Path(args.previous).is_file() else {}
    budget_rows = read_budget_set(Path(args.budget_set)) if args.budget_set and Path(args.budget_set).is_file() else []
    budget = budget_report(
        budget_rows,
        tonight,
        stage_seconds(out),
        json.loads(Path(args.budget_samples).read_text())
        if args.budget_samples and Path(args.budget_samples).is_file()
        else {},
        read_tsv(Path(args.budget_baseline)) if args.budget_baseline and Path(args.budget_baseline).is_file() else [],
        lambda row: budget_not_run_reason(row, chosen, gates),
        args.host,
        args.date,
        args.head,
    )
    flipped = flips(store, tonight)
    history = Path(args.history).read_text().splitlines() if args.history and Path(args.history).is_file() else []

    reasons = []
    if build != "ok":
        reasons.append(
            f"build {build}: {len(chosen['dropped'])} selection(s) dropped, {len(chosen['unselected'])} unit(s) left out"
        )
    reasons += [not_run_text(end) for end in verdict_not_run]
    if not results["verdict"]:
        reasons.append("the verdict run reported no test")
    if verdict["failed"]:
        reasons.append(f"{verdict['failed']} failed")
    if pending_door is None:
        reasons.append("the pending-door tool did not run")
    elif pending_door.get("expired", 0):
        reasons.append(f"{pending_door['expired']} pending-door test(s) past their date")
    red = bool(reasons)
    streak = red_nights(history, red)

    red_ids = sorted(gate_id for gate_id, entry in report["ids"].items() if entry["state"] == "red")
    line = (
        f"NIGHTLY {args.date} head={args.head[:12]} {'RED' if red else 'GREEN'} build={build}"
        f" cycle={chosen['cursor_in']['cycle']} shards_run={shards_run}/{len(chosen['order'])}"
        f" next={chosen['cursor_out']['next']}"
        f" passed={verdict['passed']} failed={verdict['failed']} skipped={verdict['skipped']}"
        f" verdict_not_run={len(verdict_not_run)}"
        f" quarantined={quarantined['passed'] + quarantined['failed']}"
        f" pending={pending_door.get('pending', 0) if pending_door else '?'}"
        f" expired={pending_door.get('expired', 0) if pending_door else '?'}"
        f" flipped={len(flipped)}"
        f" libtest_passed={libtest['passed']} libtest_failed={libtest['failed']}"
        f" quarantine_gated={report['gated']} ported_green={report['ported_green']}"
        f" ported_red={report['ported_red']} new_gates={len(report['new_gates'])}"
        f" red_nights={streak}"
        f" budget_in={budget['in']} budget_out={budget['out']} budget_pending={budget['pending']}"
        f" budget_not_run={len(budget['not_run'])}"
    )
    if red_ids:
        line += " ported_red_ids=" + ",".join(red_ids)

    failed_tests = sorted(test for test, outcome in results["verdict"].items() if outcome == "fail")
    record = {
        "date": args.date,
        "head": args.head,
        "verdict": "red" if red else "green",
        "reasons": reasons,
        "red_nights": streak,
        "build": build,
        "plan": chosen,
        "pending_door": pending_door,
        "stages": {
            "verdict": verdict,
            "libtest": libtest,
            "quarantine": quarantined,
            "pending": pending_run,
        },
        "failed": failed_tests,
        "stages_not_run": stages_not_run,
        "libtest_failed": sorted(test for test, outcome in results["libtest"].items() if outcome == "fail"),
        "flipped": flipped,
        "quarantine": report,
        "budget": {key: value for key, value in budget.items() if key != "samples"},
    }
    (out / "summary.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    (out / "results-store.json").write_text(
        json.dumps(updated_store(store, tonight, args.date), indent=0, sort_keys=True) + "\n"
    )
    flake_row = {
        "date": args.date,
        "head": args.head,
        "host": args.host,
        "passed": verdict["passed"],
        "failed": verdict["failed"],
        "quarantined": quarantined["passed"] + quarantined["failed"],
        "pending": pending_door.get("pending", 0) if pending_door else None,
        "expired": pending_door.get("expired", 0) if pending_door else None,
        "flipped": len(flipped),
        "flipped_tests": flipped[:FLIPS_IN_ROW],
    }
    (out / "flake-row.json").write_text(json.dumps(flake_row, sort_keys=True) + "\n")
    (out / "budget-samples.json").write_text(json.dumps(budget["samples"], indent=1, sort_keys=True) + "\n")
    budget_row = {
        "date": args.date,
        "head": args.head,
        "host": args.host,
        "in": budget["in"],
        "out": budget["out"],
        "pending": budget["pending"],
        "not_run": len(budget["not_run"]),
        "out_tests": [
            {key: entry[key] for key in ("test", "seconds", "baseline", "band")}
            for entry in budget["tests"]
            if entry["band"] in ("over", "under")
        ],
    }
    (out / "budget-row.json").write_text(json.dumps(budget_row, sort_keys=True) + "\n")
    proposal_path = out / "budget-baseline-proposal.tsv"
    proposal_path.unlink(missing_ok=True)
    if budget["proposal"]:
        lines = ["\t".join(BUDGET_BASELINE_COLUMNS)]
        lines += ["\t".join(row[column] for column in BUDGET_BASELINE_COLUMNS) for row in budget["proposal"]]
        proposal_path.write_text("\n".join(lines) + "\n")

    text = [line, ""]
    text += [f"red: {reason}" for reason in reasons]
    ran = {entry["name"]: entry for entry in chosen["order"]}
    text += [
        f"shard {name}: {ran[name]['first']} .. {ran[name]['last']} ({ran[name]['files']} files)"
        + (", ends cycle" if ran[name]["ends_cycle"] else "")
        for name in chosen["shards_run"]
    ]
    not_run = len(chosen["order"]) - len(chosen["shards_run"])
    if not_run:
        text.append(f"not run tonight: {not_run} shard(s); the cursor resumes at {chosen['cursor_out']['next']}")
    text += [
        f"not run: {not_run_text(end)}" + ("" if end["stage"] == "verdict" else " (report only)")
        for end in stages_not_run
    ]
    text += [f"failed: {test}" for test in failed_tests]
    text += [f"dropped: {d['selection']} ({d['reason']})" for d in chosen["dropped"]]
    text += [
        f"unselected: {u['selection']} {u['package']} {u['kind']} {u['name']} ({u['reason']})".replace("  ", " ")
        for u in chosen["unselected"]
    ]
    text += [f"flipped: {f['test']} {f['from']} ({f['since']}) -> {f['to']}" for f in flipped]
    text += [f"libtest failed: {test}" for test in record["libtest_failed"]]
    text += [f"new quarantine gate: {gate_id}" for gate_id in report["new_gates"]]
    for gate_id, entry in report["ids"].items():
        if entry["state"] != "gated":
            detail = f" {entry['tests']} test(s)" + (
                f", failed: {', '.join(entry['failed'])}" if entry["failed"] else ""
            )
            text.append(f"ported {gate_id}: {entry['state']}{detail}")
    text += [budget_text(entry, args.host) for entry in budget["tests"]]
    text += [f"budget not run: {entry['id']} ({entry['reason']})" for entry in budget["not_run"]]
    if budget["proposed"]:
        text.append(
            f"budget baseline proposal: {budget['proposed']} new row(s) in budget-baseline-proposal.tsv"
            " (a PR commits it as scripts/nightly/budget-baseline.tsv)"
        )
    (out / "summary.txt").write_text("\n".join(text) + "\n")
    print(line)
    return 1 if red else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("failed-units")
    command.add_argument("logs", nargs="+", type=Path)
    command = commands.add_parser("plan")
    command.add_argument("metadata", type=Path)
    command.add_argument("--shard-files", type=int, default=0)
    command.add_argument("--cursor", type=Path, help="the cursor file; absent or empty starts at the first name")
    command.add_argument("--budget-set", type=Path, help="scripts/nightly/budget-set.tsv: adds the budget selection")
    command = commands.add_parser("advance")
    command.add_argument("plan", type=Path)
    command.add_argument("name")
    command.add_argument("cursor", type=Path)
    command = commands.add_parser("deadline")
    command.add_argument("stop_at", help="HH:MM, Japan time")
    command = commands.add_parser("prune")
    command.add_argument("plan", type=Path)
    command.add_argument("name")
    command.add_argument("failed", type=Path)
    command.add_argument("metadata", type=Path)
    command = commands.add_parser("drop")
    command.add_argument("plan", type=Path)
    command.add_argument("name")
    command.add_argument("reason")
    command = commands.add_parser("args")
    command.add_argument("plan", type=Path)
    command.add_argument("--name", help="print only this selection's args")
    command = commands.add_parser("tests")
    command.add_argument("plan", type=Path)
    command.add_argument("name")
    command = commands.add_parser("field")
    command.add_argument("json", type=Path)
    command.add_argument("key")
    command = commands.add_parser("census")
    command.add_argument("root", type=Path)
    command = commands.add_parser("budget-filter")
    command.add_argument("budget_set", type=Path)
    command.add_argument("--metadata", type=Path, help="cargo metadata: leave out rows whose package is not in it")
    command = commands.add_parser("summary")
    command.add_argument("--out", required=True)
    command.add_argument("--date", required=True)
    command.add_argument("--head", required=True)
    command.add_argument("--host", default=os.uname().nodename)
    command.add_argument("--plan", required=True)
    command.add_argument("--pending-door", required=True)
    command.add_argument("--baseline", required=True)
    command.add_argument("--census-root", required=True)
    command.add_argument("--previous")
    command.add_argument("--history")
    command.add_argument("--budget-set", help="the budget set (scripts/nightly/budget-set.tsv)")
    command.add_argument("--budget-baseline", help="the committed baselines (scripts/nightly/budget-baseline.tsv)")
    command.add_argument("--budget-samples", help="the last night's budget-samples.json")
    args = parser.parse_args(argv)

    if args.command == "failed-units":
        print(json.dumps(failed_units(args.logs), indent=2))
    elif args.command == "plan":
        cursor = json.loads(args.cursor.read_text()) if args.cursor and args.cursor.is_file() else None
        budget = read_budget_set(args.budget_set) if args.budget_set else None
        chosen = plan(json.loads(args.metadata.read_text()), args.shard_files, cursor, budget=budget)
        print(json.dumps(chosen, indent=2))
    elif args.command == "advance":
        chosen = json.loads(args.plan.read_text())
        cursor = advance(chosen, args.name)
        args.plan.write_text(json.dumps(chosen, indent=2) + "\n")
        args.cursor.write_text(json.dumps(cursor) + "\n")
    elif args.command == "deadline":
        if not re.fullmatch(r"([01][0-9]|2[0-3]):[0-5][0-9]", args.stop_at):
            parser.error(f"deadline {args.stop_at}: not HH:MM")
        print(deadline_epoch(args.stop_at, time.time()))
    elif args.command in ("prune", "drop"):
        chosen = json.loads(args.plan.read_text())
        if args.command == "prune":
            kept = prune(chosen, args.name, json.loads(args.failed.read_text()), json.loads(args.metadata.read_text()))
        else:
            drop(chosen, args.name, args.reason)
            kept = False
        args.plan.write_text(json.dumps(chosen, indent=2) + "\n")
        return 0 if kept else 3
    elif args.command == "args":
        chosen = json.loads(args.plan.read_text())
        for entry in chosen["selections"]:
            if args.name is None:
                print(" ".join([entry["name"], *selection_args(chosen, entry)]))
            elif entry["name"] == args.name:
                print(" ".join(selection_args(chosen, entry)))
    elif args.command == "tests":
        print("\n".join(find_selection(json.loads(args.plan.read_text()), args.name)["tests"]))
    elif args.command == "field":
        value = json.loads(args.json.read_text()).get(args.key)
        print("" if value is None else value)
    elif args.command == "census":
        sys.stdout.write(census_tsv(census(args.root)))
    elif args.command == "budget-filter":
        metadata = json.loads(args.metadata.read_text()) if args.metadata else None
        print(budget_filter(read_budget_set(args.budget_set), metadata))
    else:
        return summary(args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
