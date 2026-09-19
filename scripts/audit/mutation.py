#!/usr/bin/env python3
"""Run a pinned touched-crate mutation audit, or enforce a saved outcomes report."""
import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
ROOT = pathlib.Path(__file__).resolve().parents[2]

def score(report):
    outcomes = report.get("outcomes")
    if not isinstance(outcomes, list):
        raise ValueError("missing outcomes")
    caught = missed = 0
    for outcome in outcomes:
        if outcome.get("scenario") == "Baseline" or "Baseline" in outcome.get("scenario", {}):
            continue
        summary = outcome.get("summary")
        if summary == "CaughtMutant":
            caught += 1
        elif summary == "MissedMutant":
            missed += 1
        elif summary not in ("Unviable",):
            # Timeouts and interrupted/missing tests are not kills.
            raise ValueError("incomplete mutation audit: " + str(summary))
    return caught, missed

def enforce(report, baseline):
    caught, missed = score(report)
    tested = caught + missed
    value = caught / tested if tested else 0.0
    if tested < baseline["minimum_tested"] or value < baseline["minimum_score"]:
        raise ValueError(f"mutation score {value:.3f} ({caught}/{tested}) below baseline")
    return {"score": value, "caught": caught, "tested": tested}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--report", type=pathlib.Path)
    p.add_argument("--base", default="origin/main")
    p.add_argument("--all-engine", action="store_true")
    p.add_argument("--allow-no-changes", action="store_true")
    args = p.parse_args()
    baseline = json.loads((ROOT / "scripts/audit/mutation-baseline.json").read_text())
    report = args.report
    if report is None:
        version = subprocess.check_output(["cargo", "mutants", "--version"], text=True).strip()
        if version != baseline["runner"]:
            raise ValueError("required runner: " + baseline["runner"])
        changed = [] if args.all_engine else subprocess.check_output(
            ["git", "diff", "--name-only", args.base], text=True).splitlines()
        crates = sorted({path.split("/")[1] for path in changed if path.startswith("crates/") and len(path.split("/")) > 2} & set(baseline["scope"]))
        if args.all_engine:
            crates = baseline["scope"]
        if not crates and args.allow_no_changes:
            print(json.dumps({"skipped": "no touched engine crates"}))
            return
        if not crates:
            raise ValueError("no touched engine crates; supply a saved report to audit")
        parent = ROOT / "target/mutation-audit"
        parent.mkdir(parents=True, exist_ok=True)
        # A failed launch must not accidentally reuse yesterday's green report.
        with tempfile.TemporaryDirectory(prefix="run-", dir=parent) as fresh:
            command = ["cargo", "mutants", "--output", fresh, "--test-tool", "nextest",
                       "--re", baseline["mutant_filter"], "--cargo-test-arg=--lib",
                       "--cargo-test-arg=-E", "--cargo-test-arg=" + baseline["test_filter"],
                       "--jobs", "1", "--jobserver-tasks", "2"]
            for file in baseline["files"]:
                command += ["--file", file]
            for crate in crates:
                command += ["--package", crate]
            result = subprocess.run(command, cwd=ROOT, check=False)
            generated = pathlib.Path(fresh) / "mutants.out/outcomes.json"
            if not generated.is_file():
                raise ValueError(f"runner exited {result.returncode} without a fresh report")
            raw = generated.read_text()
            data = json.loads(raw)
            # Preserve failed audit evidence too; enforcement below owns the verdict.
            report = parent / "outcomes.json"
            report.write_text(raw)
            score(data)
    print(json.dumps(enforce(json.loads(report.read_text()), baseline), sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("MUTATION-AUDIT-FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
