#!/usr/bin/env python3
"""The nightly test job's report tool (Fable's test verdict 2026-11-09, PR 10a).

Standard library only. scripts/nightly/run_nightly.sh calls it; each
subcommand reads files the job wrote:

  plan METADATA [--shard-files N] [--rotation I/K]
                                  the night's selections: the lib tests, then
                                  the integration tests, whole or in shards
  failed-units LOG...             the test build units cargo could not compile
  prune PLAN NAME FAILED METADATA leave a selection's failed units out (exit 3
                                  when the selection is dropped)
  drop PLAN NAME REASON           drop a selection
  args PLAN [--name NAME]         `<name> <args...>` per selection, or one
                                  selection's args
  tests PLAN NAME                 a selection's integration test names
  field JSON KEY                  one top-level value of a JSON object
  census ROOT                     the lib-test quarantine gates in a tree (TSV)
  summary ...                     the night's verdict: prints the one summary
                                  line and writes summary.json, summary.txt,
                                  results.json and flake-row.json

A quarantine gate is a `// FIX [LIBTEST-QUARANTINE-<ID>]` comment followed by
`#[cfg(any())]` on the item it switches off (OPUS-MAINFIX's lib-test
quarantine, #7561). The committed baseline
(scripts/nightly/libtest-quarantine-baseline.tsv) is the census of main when
the quarantine landed (12c169344bc3, "train: #7561"; 441 gates under 401
ids); a baseline gate that is gone from the tree is ported, and the summary
names its tests' pass or fail.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ElementTree
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
    rotation: tuple[int, int] | None = None,
    always_excluded: tuple[str, ...] = ALWAYS_EXCLUDED,
) -> dict:
    """The night's selections: the lib tests first, then the integration tests.

    `libs` selects every lib test and bin test (`--lib --bins`) and the
    pending-door tool's own test. The integration tests follow by name
    (`--test`): all in one selection, or in shards of `shard_files` names whose
    binaries the runner deletes once the shard has run. A name two packages
    share selects both (cargo matches a `--test` name in every selected
    package). `rotation` (i, k) keeps the names whose index modulo k is i, so
    each name runs once in k nights. Every selection keeps `--workspace`, so
    features unify as in a full build.
    """
    owners = {
        name: [p for p in packages if p not in always_excluded] for name, packages in test_owners(metadata).items()
    }
    names = sorted(name for name, packages in owners.items() if packages)
    door_package, door_test = DOOR_TOOL_TEST
    libs_tests = [door_test] if door_package in owners.get(door_test, []) else []
    names = [name for name in names if name not in libs_tests]
    held = 0
    if rotation:
        index, count = rotation
        kept = [name for position, name in enumerate(names) if position % count == index]
        held, names = len(names) - len(kept), kept
    size = shard_files if shard_files > 0 else max(len(names), 1)
    selections = [{"name": "libs", "kind": "libs", "excluded": [], "bins": True, "tests": libs_tests}]
    for number, start in enumerate(range(0, len(names), size), start=1):
        selections.append(
            {
                "name": f"tests-{number:02d}",
                "kind": "tests",
                "excluded": [],
                "bins": False,
                "tests": names[start : start + size],
            }
        )
    return {
        "always_excluded": list(always_excluded),
        "shard_files": shard_files,
        "rotation": f"{rotation[0]}/{rotation[1]}" if rotation else None,
        "held_for_other_nights": held,
        "selections": selections,
        "dropped": [],
        "unselected": [],
    }


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
    if entry["kind"] == "tests" and not entry["tests"]:
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


def read_census_tsv(path: Path) -> list[dict[str, str]]:
    lines = path.read_text().splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:] if line]


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


def stage_results(out: Path) -> dict[str, dict[str, str]]:
    """Each stage's outcomes, merged over its selections (junit-<stage>-<selection>.xml)."""
    results: dict[str, dict[str, str]] = {stage: {} for stage in STAGES}
    for stage in STAGES:
        for path in sorted(out.glob(f"junit-{stage}-*.xml")):
            results[stage].update(read_junit(path))
    return results


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


def flips(previous: dict[str, str], tonight: dict[str, str]) -> list[dict[str, str]]:
    """Tests that went from pass to fail or from fail to pass since the last night."""
    changed = []
    for test in sorted(set(previous) & set(tonight)):
        before, after = previous[test], tonight[test]
        if before != after and {before, after} == {"pass", "fail"}:
            changed.append({"test": test, "from": before, "to": after})
    return changed


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


def summary(args: argparse.Namespace) -> int:
    out = Path(args.out)
    chosen = json.loads(Path(args.plan).read_text())
    build = build_state(chosen)
    shards = sum(1 for entry in chosen["selections"] if entry["kind"] == "tests")
    pending_door = json.loads(Path(args.pending_door).read_text()) if Path(args.pending_door).is_file() else None
    results = stage_results(out)
    verdict = counts(results["verdict"])
    libtest = counts(results["libtest"])
    quarantined = counts(results["quarantine"])
    pending_run = counts(results["pending"])
    report = quarantine_report(read_census_tsv(Path(args.baseline)), census(Path(args.census_root)), results["libtest"])
    tonight = {**results["libtest"], **results["verdict"]}
    previous = json.loads(Path(args.previous).read_text()) if args.previous and Path(args.previous).is_file() else {}
    flipped = flips(previous, tonight)
    history = Path(args.history).read_text().splitlines() if args.history and Path(args.history).is_file() else []

    reasons = []
    if build != "ok":
        reasons.append(
            f"build {build}: {len(chosen['dropped'])} selection(s) dropped, {len(chosen['unselected'])} unit(s) left out"
        )
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
        f"NIGHTLY {args.date} head={args.head[:12]} {'RED' if red else 'GREEN'} build={build} shards={shards}"
        + (f" rotation={chosen['rotation']} held={chosen['held_for_other_nights']}" if chosen.get("rotation") else "")
        + f" passed={verdict['passed']} failed={verdict['failed']} skipped={verdict['skipped']}"
        f" quarantined={quarantined['passed'] + quarantined['failed']}"
        f" pending={pending_door.get('pending', 0) if pending_door else '?'}"
        f" expired={pending_door.get('expired', 0) if pending_door else '?'}"
        f" flipped={len(flipped)}"
        f" libtest_passed={libtest['passed']} libtest_failed={libtest['failed']}"
        f" quarantine_gated={report['gated']} ported_green={report['ported_green']}"
        f" ported_red={report['ported_red']} new_gates={len(report['new_gates'])}"
        f" red_nights={streak}"
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
        "libtest_failed": sorted(test for test, outcome in results["libtest"].items() if outcome == "fail"),
        "flipped": flipped,
        "quarantine": report,
    }
    (out / "summary.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    (out / "results.json").write_text(json.dumps(tonight, indent=0, sort_keys=True) + "\n")
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

    text = [line, ""]
    text += [f"red: {reason}" for reason in reasons]
    text += [f"failed: {test}" for test in failed_tests]
    text += [f"dropped: {d['selection']} ({d['reason']})" for d in chosen["dropped"]]
    text += [
        f"unselected: {u['selection']} {u['package']} {u['kind']} {u['name']} ({u['reason']})".replace("  ", " ")
        for u in chosen["unselected"]
    ]
    text += [f"flipped: {f['test']} {f['from']} -> {f['to']}" for f in flipped]
    text += [f"libtest failed: {test}" for test in record["libtest_failed"]]
    text += [f"new quarantine gate: {gate_id}" for gate_id in report["new_gates"]]
    for gate_id, entry in report["ids"].items():
        if entry["state"] != "gated":
            detail = f" {entry['tests']} test(s)" + (
                f", failed: {', '.join(entry['failed'])}" if entry["failed"] else ""
            )
            text.append(f"ported {gate_id}: {entry['state']}{detail}")
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
    command.add_argument("--rotation", help="I/K: the integration tests whose index modulo K is I")
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
    args = parser.parse_args(argv)

    if args.command == "failed-units":
        print(json.dumps(failed_units(args.logs), indent=2))
    elif args.command == "plan":
        rotation = None
        if args.rotation:
            index, _, count = args.rotation.partition("/")
            rotation = (int(index), int(count))
            if not 0 <= rotation[0] < rotation[1]:
                parser.error(f"--rotation {args.rotation}: I/K needs 0 <= I < K")
        print(json.dumps(plan(json.loads(args.metadata.read_text()), args.shard_files, rotation), indent=2))
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
    else:
        return summary(args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
