#!/usr/bin/env python3
"""Merge LCOV lanes by canonical file/line identity; overlapping lines count once."""
import argparse
import os
import pathlib
import subprocess
import sys
ROOT = pathlib.Path(__file__).resolve().parents[2]

def merge(paths):
    files = {}
    for path in paths:
        source = None
        for line in pathlib.Path(path).read_text().splitlines():
            if line.startswith("SF:"):
                source = pathlib.Path(line[3:]).resolve().as_posix()
                files.setdefault(source, {})
            elif line.startswith("DA:"):
                if source is None:
                    raise ValueError("coverage region without source")
                region, hits, *_ = line[3:].split(",")
                region, hits = int(region), int(hits)
                if region < 1 or hits < 0:
                    raise ValueError("invalid coverage region")
                files[source][region] = max(files[source].get(region, 0), hits)
            elif line == "end_of_record":
                source = None
    if not files:
        raise ValueError("no coverage files")
    lines = []
    for source, regions in sorted(files.items()):
        lines += ["TN:merged", "SF:" + source]
        lines += [f"DA:{region},{hits}" for region, hits in sorted(regions.items())]
        lines += [f"LF:{len(regions)}", f"LH:{sum(hits > 0 for hits in regions.values())}", "end_of_record"]
    return "\n".join(lines) + "\n"

def collect(output, toolchain=None, unstable_doctests=False):
    env = os.environ.copy()
    env["CARGO_LLVM_COV_SETUP"] = "no"
    env["CARGO_BUILD_JOBS"] = "2"
    env["RUST_TEST_THREADS"] = "2"
    cargo = ["cargo"] + (["+" + toolchain] if toolchain else [])
    version = subprocess.check_output([*cargo, "llvm-cov", "--version"], env=env, text=True).strip()
    if version != "cargo-llvm-cov 0.8.7":
        raise ValueError("required cargo-llvm-cov 0.8.7")
    output.mkdir(parents=True, exist_ok=True)
    temporary = output / "tmp"
    temporary.mkdir(mode=0o700, exist_ok=True)
    env["TMPDIR"] = str(temporary.resolve())
    reports = []
    lanes = [
        ["nextest", "--workspace", "--exclude", "oneiron-napi", "--all-features", "--profile", "full", "--test-threads", "2"],
        ["--package", "oneiron", "--lib", "--no-default-features"],
        ["--doc", "--workspace", "--exclude", "oneiron-bench", "--all-features", "--doctests"],
    ]
    if sys.platform == "darwin":
        # Same seven UnsupportedPlatform cases as ci.yml; never omit the crate.
        unsupported = [
            "eval_outcome_ingest_applies_a_jsonl_file_against_the_named_vault",
            "eval_outcome_ingest_opens_a_non_device_vault_through_the_explicit_config",
            "eval_outcome_ingest_refuses_a_wrong_dict_root_on_an_empty_text_index",
            "eval_reopens_a_custom_dictionary_vault_for_outcome_ingest_and_tune",
            "eval_tune_honors_the_max_runs_bound",
            "eval_tune_opens_a_non_device_vault_through_the_explicit_config",
            "eval_tune_persists_and_prints_the_bounded_weight_table_entry",
        ]
        lanes[0] += ["-E", "not (" + " | ".join("test(=eval::tests::" + name + ")" for name in unsupported) + ")"]
    # Each lane starts with clean instrumentation data, never clean build artifacts.
    for number, lane in enumerate(lanes):
        lane_env = env.copy()
        if unstable_doctests and "--doctests" in lane:
            # cargo-llvm-cov explicitly supports this opt-in for rustdoc's
            # unstable persisted-doctest instrumentation. Production gates stay stable.
            lane_env["RUSTC_BOOTSTRAP"] = "1"
        subprocess.run([*cargo, "llvm-cov", "clean", "--workspace", "--profraw-only"], cwd=ROOT, env=lane_env, check=True)
        subprocess.run([*cargo, "llvm-cov", *lane, "--no-report"], cwd=ROOT, env=lane_env, check=True)
        path = output / f"lane-{number}.lcov"
        # Persisted doctest executables must participate in report discovery too.
        doc = ["--doctests"] if "--doctests" in lane else []
        subprocess.run([*cargo, "llvm-cov", "report", *doc, "--lcov", "--output-path", str(path)], cwd=ROOT, env=lane_env, check=True)
        reports.append(path)
    return reports

def main():
    p = argparse.ArgumentParser()
    p.add_argument("reports", nargs="*", type=pathlib.Path)
    p.add_argument("--collect", action="store_true")
    p.add_argument("--toolchain", help="installed toolchain; never installed by this script")
    p.add_argument("--unstable-doctests", action="store_true", help="opt in to RUSTC_BOOTSTRAP only for the doctest lane on the pinned stable compiler")
    p.add_argument("--output", type=pathlib.Path, default=ROOT / "target/coverage/merged.lcov")
    args = p.parse_args()
    reports = collect(args.output.parent, args.toolchain, args.unstable_doctests) if args.collect else args.reports
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(merge(reports))
    print(args.output)
if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("COVERAGE-FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
