#!/usr/bin/env python3
"""The nightly E2E stage (Fable's test verdict 2026-11-09, sections 4 and 6; PR 10c).

Standard library only. Runs the files of tests/e2e against a prebuilt artifact
set, in runs of tests/e2e/support/run.ts that each stay under the runner's
600-second cap, and writes the night's E2E verdict. One booked fleet job runs
it each night; no PR's CI runs it.

  plan SUITE_PLAN [--state FILE] [--workers N] [--bound S] [--factor F]
       the night's runs as JSON: the files of each run and its planned seconds
  night --set DIR --out DIR [--checkout DIR] [--node-modules DIR]
        [--state FILE] [--workers N] [--bound S] [--factor F]
        [--stop-at HH:MM | --deadline-epoch S] [--date YYYY-MM-DD]
       runs the night; prints one `## NIGHTLY-E2E ...` line per step and the
       summary line (`## NIGHTLY-E2E SUMMARY NIGHTLY-E2E <date> ...`); writes
       summary.json, summary.txt and e2e-state.json (the next night's --state)
       in --out. Exit: 0 green night, 1 red night, 2 the night could not start.

The set. The suite never builds (tests/e2e/README.md: "There is no
build/download fallback"); the booking builds or reuses a READY set for the
checkout's commit before this runs. This stage reads only the set's README
contract: READY ({"format":1,"manifestSha256":...}), manifest.json (its `head`
must be the checkout's commit, and its `bun` and `node` assets run the suite),
manifest.sha256, and the suite's installed node_modules (--node-modules,
default <set>/src/tests/e2e/node_modules), which the checkout links to.

The runs. run.ts has no shard flag, so a run is a `--files` list. A run's wall
is about the sum over its cases of the case wall times the file's slots,
divided by --workers (one child per case, longest first). A case's wall is the
longest of its last three measured walls (e2e-state.json), else its plan
estimate (fixtures/suite-plan.json: the case's own estimatedSeconds, else its
file's divided by its case count) times --factor: the plan's file estimates
were mostly never measured, and fleet walls ran 0.5 to 8.5 times them. Files go
into runs first-fit by decreasing load, each run at most --bound seconds
(default 400 of the cap's 600, with 30 s for the set re-hash and start-up); a
file over the bound runs alone. The runs whose files ran longest ago go first,
so a night cut short by --stop-at leaves the same files first in line the next
night.

The verdict. Per planned case: PASS, FAIL, BLOCKED (a todo case or a pending
door: pending, not red), SKIPPED (owner-deferred), DEADLINE (the runner's cap
cut the run before the case: counted apart, not red, and the next night packs
on the walls measured tonight), NOT-RUN (the night stopped before its run, or
its run did not run) and MISSING (the run's report has no row for it). The
night is red on a FAIL, a MISSING, or a run that did not run (no report, a
preflight refusal, a scheduler failure, or no exit past the cap). A flip is a
case whose PASS or FAIL differs from its own last PASS or FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from nightly_report import deadline_epoch  # noqa: E402

RUNNER_CAP_SECONDS = 600  # LIMITS.suiteMs in tests/e2e/support/run.ts
RUN_OVERHEAD_SECONDS = 30  # the runner re-hashes the set (11-22 s on the fleet) and starts its children
RUN_GRACE_SECONDS = 120  # past the cap, the runner gets this long to write its report and exit
DEFAULT_BOUND = 400
DEFAULT_FACTOR = 2.0
DEFAULT_WORKERS = 2
MAX_WORKERS = 6  # LIMITS.slots
WALL_SAMPLES = 3
DEADLINE_REASON = "Suite deadline/interruption before completion"
RED_OUTCOMES = ("FAIL", "MISSING")
RUN_DID_NOT_RUN = ("no-report", "preflight", "scheduler", "timeout")


class NightCannotStart(Exception):
    """The night cannot start: a bad set, checkout or argument."""


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def empty_state() -> dict:
    return {"cases": {}, "files": {}}


def read_state(path: str | None) -> dict:
    if not path or not Path(path).is_file():
        return empty_state()
    state = read_json(Path(path))
    return {"cases": state.get("cases", {}), "files": state.get("files", {})}


def plan_files(suite_plan: dict) -> list[dict]:
    return suite_plan["files"]


def case_seconds(entry: dict, test: dict, state: dict, factor: float) -> float:
    """The planned wall of one case: its longest recent measured wall, else its plan estimate times `factor`."""
    walls = state["cases"].get(test["id"], {}).get("walls", [])
    if walls:
        return max(walls) / 1000
    estimate = test.get("estimatedSeconds")
    if estimate is None:
        estimate = entry["estimatedSeconds"] / max(1, len(entry["tests"]))
    return estimate * factor


def file_load(entry: dict, state: dict, factor: float) -> float:
    """Slot-seconds of one file: the sum of its case walls times its slots."""
    return sum(case_seconds(entry, test, state, factor) for test in entry["tests"]) * entry.get("slots", 1)


def run_seconds(load: float, workers: int) -> float:
    return load / workers + RUN_OVERHEAD_SECONDS


def plan_runs(files: list[dict], state: dict, workers: int, bound: float, factor: float) -> list[dict]:
    """The night's runs: files packed first-fit by decreasing load, the longest-unrun files first."""
    loads = {entry["file"]: file_load(entry, state, factor) for entry in files}
    bins: list[list[str]] = []
    for name in sorted(loads, key=lambda name: (-loads[name], name)):
        for chosen in bins:
            if run_seconds(sum(loads[f] for f in chosen) + loads[name], workers) <= bound:
                chosen.append(name)
                break
        else:
            bins.append([name])
    last_run = state["files"]

    def order(chosen: list[str]) -> tuple[str, str]:
        return (min(last_run.get(name, "") for name in chosen), min(chosen))

    runs = []
    for index, chosen in enumerate(sorted(bins, key=order), start=1):
        chosen.sort()
        runs.append(
            {
                "name": "e2e-%02d" % index,
                "files": chosen,
                "seconds": math.ceil(run_seconds(sum(loads[f] for f in chosen), workers)),
            }
        )
    return runs


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def check_set(set_dir: Path, head: str) -> dict:
    """The set's manifest facts, or NightCannotStart when the set is not READY for `head`."""
    ready_path, manifest_path, digest_path = set_dir / "READY", set_dir / "manifest.json", set_dir / "manifest.sha256"
    for path in (ready_path, manifest_path, digest_path):
        if not path.is_file():
            raise NightCannotStart("the set has no " + path.name + ": " + str(set_dir))
    ready = read_json(ready_path)
    digest = digest_path.read_text().strip()
    actual = file_sha256(manifest_path)
    if ready.get("format") != 1 or ready.get("manifestSha256") != actual or digest != actual:
        raise NightCannotStart("the set is not READY: READY, manifest.sha256 and manifest.json disagree")
    manifest = read_json(manifest_path)
    if manifest.get("head") != head:
        raise NightCannotStart(
            "the set was built from " + str(manifest.get("head"))[:12] + ", the checkout is " + head[:12]
        )
    try:
        bun, node = manifest["assets"]["bun"]["path"], manifest["assets"]["node"]["path"]
    except (KeyError, TypeError):
        raise NightCannotStart("the set's manifest has no bun or node asset") from None
    return {"manifest": str(manifest_path), "sha256": actual, "bun": bun, "node": node}


def link_node_modules(checkout: Path, source: Path) -> None:
    """Link the checkout's tests/e2e/node_modules to the set's installed one."""
    if not source.is_dir():
        raise NightCannotStart("the set has no installed node_modules: " + str(source))
    modules = checkout / "tests/e2e/node_modules"
    if modules.is_symlink() or modules.exists():
        if not (modules.is_symlink() and modules.resolve() == source.resolve()):
            raise NightCannotStart("the checkout has its own tests/e2e/node_modules")
        return
    modules.symlink_to(source)


def git_head(checkout: Path) -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=checkout, capture_output=True, text=True)
    if result.returncode != 0:
        raise NightCannotStart("the checkout is not a git work tree: " + str(checkout))
    return result.stdout.strip()


def runner_env(facts: dict, report: Path, temp: Path) -> dict[str, str]:
    path = str(Path(facts["bun"]).parent) + ":" + str(Path(facts["node"]).parent) + ":/usr/bin:/bin"
    return {
        "PATH": path,
        "HOME": str(temp),
        "TMPDIR": str(temp),
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "E2E_REPORT_DIR": str(report),
        "E2E_TEMP_ROOT": str(temp),
        "E2E_BUILD_MANIFEST": facts["manifest"],
        "E2E_BUILD_MANIFEST_SHA256": facts["sha256"],
    }


def stop_group(process: subprocess.Popen) -> None:
    """TERM the runner's process group (its handler kills its children), then KILL what is left."""
    for sent, wait in ((signal.SIGTERM, 10), (signal.SIGKILL, 10)):
        try:
            os.killpg(process.pid, sent)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def run_suite(checkout: Path, facts: dict, run: dict, workers: int, run_dir: Path) -> dict:
    """One runner invocation; its end: rc, seconds and the state of its report."""
    report, temp = run_dir / "report", run_dir / "tmp"
    report.mkdir(parents=True)
    temp.mkdir()
    command = [
        facts["bun"],
        str(checkout / "tests/e2e/support/run.ts"),
        "--profile",
        "deterministic",
        "--workers",
        str(workers),
        "--files",
        ",".join(run["files"]),
    ]
    started = time.monotonic()
    timed_out = False
    # The runner's own output can carry SDK diagnostics: it stays in a private file, never the job log.
    output_path = run_dir / "runner-output.txt"
    with output_path.open("w") as output:
        os.chmod(output_path, 0o600)
        process = subprocess.Popen(
            command,
            cwd=checkout,
            env=runner_env(facts, report, temp),
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            rc = process.wait(timeout=RUNNER_CAP_SECONDS + RUN_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            stop_group(process)
            rc = process.returncode if process.returncode is not None else -signal.SIGKILL
    seconds = round(time.monotonic() - started, 1)
    subprocess.run(["rm", "-rf", str(temp)])  # the cases' vaults and homes
    rc = rc if rc >= 0 else 128 - rc
    summary = report / "report.json"
    value = read_json(summary) if summary.is_file() else None
    end = {
        "rc": rc,
        "seconds": seconds,
        "results": value.get("results", []) if value else [],
        "state": "ran",
        "reason": "",
    }
    if timed_out:
        end.update(state="timeout", reason="no exit %d s past the start" % (RUNNER_CAP_SECONDS + RUN_GRACE_SECONDS))
    elif value is None:
        end.update(state="no-report", reason="the runner wrote no report.json (rc %d)" % rc)
    elif "durationMs" not in value:  # the runner's preflight refusal writes a report without it, every case BLOCKED
        reasons = [row["reason"] for row in end["results"] if row.get("reason")]
        end.update(state="preflight", reason="preflight refused: " + (reasons[0] if reasons else "no reason"))
    elif value.get("schedulerFailure"):
        end.update(state="scheduler", reason="scheduler failure: " + str(value["schedulerFailure"]))
    return end


def reported(end: dict) -> bool:
    """The run's cases ran and its report has their rows (a refused preflight runs none)."""
    return end["state"] != "preflight" and bool(end["results"])


def case_rows(run: dict, end: dict, planned: dict[str, list[str]], owner: dict[str, str]) -> list[dict]:
    """One row per planned case of a run that was started."""
    rows = []
    ids = [case for name in run["files"] for case in planned[name]]
    if not reported(end):
        return [
            {
                "id": case,
                "file": owner[case],
                "outcome": "NOT-RUN",
                "ms": 0,
                "reason": end["reason"],
                "run": run["name"],
            }
            for case in ids
        ]
    found = {row["id"]: row for row in end["results"]}
    for case in ids:
        row = found.get(case)
        if row is None:
            rows.append(
                {
                    "id": case,
                    "file": owner[case],
                    "outcome": "MISSING",
                    "ms": 0,
                    "reason": "no row in the run's report",
                    "run": run["name"],
                }
            )
            continue
        outcome = row["outcome"]
        if outcome == "FAIL" and row.get("reason") == DEADLINE_REASON:
            outcome = "DEADLINE"
        rows.append(
            {
                "id": case,
                "file": owner[case],
                "outcome": outcome,
                "ms": round(row.get("durationMs", 0)),
                "reason": (row.get("reason") or "").replace("\n", " ")[:400],
                "run": run["name"],
            }
        )
    return rows


def updated_state(state: dict, rows: list[dict], ran_files: list[str], night: str) -> dict:
    """Tonight's walls and PASS/FAIL outcomes added to the state; the files that ran get tonight's date."""
    cases = {case: dict(entry) for case, entry in state["cases"].items()}
    for row in rows:
        if row["outcome"] in ("DEADLINE", "NOT-RUN", "MISSING"):
            continue
        entry = cases.setdefault(row["id"], {})
        entry["walls"] = (entry.get("walls", []) + [row["ms"]])[-WALL_SAMPLES:]
        if row["outcome"] in ("PASS", "FAIL"):
            entry.update(outcome=row["outcome"], date=night)
    files = {**state["files"], **{name: night for name in ran_files}}
    return {"cases": cases, "files": files}


def flips(state: dict, rows: list[dict]) -> list[dict]:
    changed = []
    for row in rows:
        before = state["cases"].get(row["id"], {})
        if (
            row["outcome"] in ("PASS", "FAIL")
            and before.get("outcome") in ("PASS", "FAIL")
            and before["outcome"] != row["outcome"]
        ):
            changed.append({"id": row["id"], "from": before["outcome"], "to": row["outcome"], "since": before["date"]})
    return changed


def count(rows: list[dict], outcome: str) -> int:
    return sum(1 for row in rows if row["outcome"] == outcome)


def verdict(rows: list[dict], ends: list[dict]) -> bool:
    """True on a red night."""
    return any(row["outcome"] in RED_OUTCOMES for row in rows) or any(end["state"] in RUN_DID_NOT_RUN for end in ends)


def summary_text(rows: list[dict], ends: list[dict], changed: list[dict]) -> str:
    lines = []
    for end in ends:
        lines.append(
            "RUN %s state=%s rc=%s seconds=%s planned=%s files=%s%s"
            % (
                end["name"],
                end["state"],
                end.get("rc", "-"),
                end.get("seconds", "-"),
                end["planned"],
                ",".join(end["files"]),
                (" reason=" + end["reason"]) if end.get("reason") else "",
            )
        )
    for row in rows:
        if row["outcome"] in ("FAIL", "MISSING", "DEADLINE"):
            lines.append(
                "%s %s %s %dms run=%s %s"
                % (row["outcome"], row["id"], row["file"], row["ms"], row["run"], row["reason"])
            )
    for flip in changed:
        lines.append("FLIP %s %s->%s since %s" % (flip["id"], flip["from"], flip["to"], flip["since"]))
    return "\n".join(lines) + "\n"


def summary_line(
    night: str,
    head: str,
    set_sha: str,
    red: bool | None,
    rows: list[dict],
    ends: list[dict],
    changed: list[dict],
    workers: int,
    seconds: float,
    reason: str = "",
) -> str:
    if red is None:
        return "NIGHTLY-E2E %s head=%s set=%s NOT-STARTED reason=%s" % (
            night,
            head[:12] or "none",
            set_sha[:12] or "none",
            reason,
        )
    ran = sum(1 for end in ends if end["state"] == "ran")
    fields = ["runs=%d/%d" % (ran, len(ends))]
    for outcome in ("PASS", "FAIL", "BLOCKED", "SKIPPED", "DEADLINE", "NOT-RUN", "MISSING"):
        fields.append("%s=%d" % (outcome.lower().replace("-", "_"), count(rows, outcome)))
    fields += ["flipped=%d" % len(changed), "workers=%d" % workers, "seconds=%d" % round(seconds)]
    return "NIGHTLY-E2E %s head=%s set=%s %s %s" % (
        night,
        head[:12],
        set_sha[:12],
        "RED" if red else "GREEN",
        " ".join(fields),
    )


def night(args: argparse.Namespace) -> int:
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    state = read_state(args.state)  # before the clear below: --state may be this --out's own e2e-state.json
    for name in ("summary.json", "summary.txt", "e2e-state.json"):
        (out / name).unlink(missing_ok=True)
    started = time.time()
    date = args.date or datetime.fromtimestamp(started, timezone(timedelta(hours=9))).strftime("%Y-%m-%d")
    write_json(out / "e2e-state.json", state)  # a night that cannot start hands the state on unchanged
    checkout = Path(args.checkout).resolve()
    head, facts = "", {"sha256": ""}
    try:
        if not 1 <= args.workers <= MAX_WORKERS:
            raise NightCannotStart("--workers must be 1 to %d" % MAX_WORKERS)
        head = git_head(checkout)
        set_dir = Path(args.set).resolve()
        facts = check_set(set_dir, head)
        link_node_modules(
            checkout, Path(args.node_modules).resolve() if args.node_modules else set_dir / "src/tests/e2e/node_modules"
        )
        files = plan_files(read_json(checkout / "tests/e2e/fixtures/suite-plan.json"))
        heaviest = max(entry.get("slots", 1) for entry in files)
        if heaviest > args.workers:
            raise NightCannotStart("a file needs %d slots, more than --workers %d" % (heaviest, args.workers))
        deadline = deadline_epoch(args.stop_at, started) if args.stop_at else args.deadline_epoch
    except NightCannotStart as error:
        line = summary_line(date, head, facts["sha256"], None, [], [], [], args.workers, 0, str(error))
        write_json(out / "summary.json", {"line": line, "started": False, "reason": str(error)})
        print("## NIGHTLY-E2E start rc=2 reason=" + str(error), flush=True)
        print("## NIGHTLY-E2E SUMMARY " + line, flush=True)
        return 2
    planned = {entry["file"]: [test["id"] for test in entry["tests"]] for entry in files}
    owner = {case: name for name, cases in planned.items() for case in cases}
    runs = plan_runs(files, state, args.workers, args.bound, args.factor)
    write_json(out / "plan.json", runs)
    print(
        "## NIGHTLY-E2E head=%s set=%s date=%s workers=%d bound=%d factor=%s runs=%d planned=%ds deadline=%s"
        % (
            head[:12],
            facts["sha256"][:12],
            date,
            args.workers,
            args.bound,
            args.factor,
            len(runs),
            sum(run["seconds"] for run in runs),
            deadline or "none",
        ),
        flush=True,
    )
    rows, ends, ran_files = [], [], []
    for index, run in enumerate(runs):
        if deadline and time.time() + run["seconds"] > deadline:
            for left in runs[index:]:
                ends.append(
                    {
                        "name": left["name"],
                        "files": left["files"],
                        "planned": left["seconds"],
                        "state": "stopped",
                        "reason": "stop-at: %d s planned past the deadline" % left["seconds"],
                    }
                )
                rows += [
                    {
                        "id": case,
                        "file": owner[case],
                        "outcome": "NOT-RUN",
                        "ms": 0,
                        "reason": "stop-at",
                        "run": left["name"],
                    }
                    for name in left["files"]
                    for case in planned[name]
                ]
            print("## NIGHTLY-E2E stop before %s (deadline)" % run["name"], flush=True)
            break
        run_dir = out / "runs" / run["name"]
        subprocess.run(["rm", "-rf", str(run_dir)])  # a reused --out must not lend an older night's report
        end = run_suite(checkout, facts, run, args.workers, run_dir)
        end.update(name=run["name"], files=run["files"], planned=run["seconds"])
        tonight = case_rows(run, end, planned, owner)
        rows += tonight
        ends.append(end)
        if reported(end):
            ran_files += run["files"]
        print(
            "## NIGHTLY-E2E run %s state=%s rc=%d seconds=%s planned=%d files=%s pass=%d fail=%d blocked=%d deadline=%d%s"
            % (
                run["name"],
                end["state"],
                end["rc"],
                end["seconds"],
                run["seconds"],
                ",".join(run["files"]),
                count(tonight, "PASS"),
                count(tonight, "FAIL"),
                count(tonight, "BLOCKED"),
                count(tonight, "DEADLINE"),
                (" reason=" + end["reason"][:300]) if end["reason"] else "",
            ),
            flush=True,
        )
        for row in tonight:
            if row["outcome"] in RED_OUTCOMES:
                print(
                    "## NIGHTLY-E2E %s %s %dms %s" % (row["outcome"], row["id"], row["ms"], row["reason"][:300]),
                    flush=True,
                )
    changed = flips(state, rows)
    red = verdict(rows, ends)
    write_json(out / "e2e-state.json", updated_state(state, rows, ran_files, date))
    line = summary_line(date, head, facts["sha256"], red, rows, ends, changed, args.workers, time.time() - started)
    write_json(
        out / "summary.json",
        {
            "line": line,
            "started": True,
            "red": red,
            "runs": [{key: value for key, value in end.items() if key != "results"} for end in ends],
            "cases": rows,
            "flips": changed,
        },
    )
    (out / "summary.txt").write_text(summary_text(rows, ends, changed))
    print("## NIGHTLY-E2E SUMMARY " + line, flush=True)
    return 1 if red else 0


def plan_command(args: argparse.Namespace) -> int:
    runs = plan_runs(
        plan_files(read_json(Path(args.suite_plan))), read_state(args.state), args.workers, args.bound, args.factor
    )
    print(json.dumps(runs, indent=2))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--state", help="the last night's e2e-state.json")
    shared.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    shared.add_argument(
        "--bound", type=int, default=DEFAULT_BOUND, help="planned seconds per run (the runner's cap is 600)"
    )
    shared.add_argument(
        "--factor", type=float, default=DEFAULT_FACTOR, help="times a plan estimate until a case is measured"
    )
    command = commands.add_parser("plan", parents=[shared])
    command.add_argument("suite_plan")
    command.set_defaults(handler=plan_command)
    command = commands.add_parser("night", parents=[shared])
    command.add_argument("--set", required=True, help="a READY artifact set built from the checkout's commit")
    command.add_argument("--out", required=True)
    command.add_argument("--checkout", default=str(Path(__file__).resolve().parents[2]))
    command.add_argument(
        "--node-modules", help="the suite's installed node_modules (default <set>/src/tests/e2e/node_modules)"
    )
    command.add_argument("--date")
    stop = command.add_mutually_exclusive_group()
    stop.add_argument("--stop-at", help="HH:MM Japan time: no run starts that would end past it")
    stop.add_argument("--deadline-epoch", type=int)
    command.set_defaults(handler=night)
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
