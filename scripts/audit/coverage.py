#!/usr/bin/env python3
"""Merge LCOV lanes by canonical file/line identity; overlapping lines count once."""
import argparse
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

def collect(output):
    version = subprocess.check_output(["cargo", "llvm-cov", "--version"], text=True).strip()
    if version != "cargo-llvm-cov 0.6.16":
        raise ValueError("required cargo-llvm-cov 0.6.16")
    output.mkdir(parents=True, exist_ok=True)
    reports = []
    lanes = [
        ["nextest", "--workspace", "--exclude", "oneiron-napi", "--all-features", "--profile", "full"],
        ["--package", "oneiron", "--lib", "--no-default-features"],
        ["--doc", "--workspace", "--exclude", "oneiron-bench", "--all-features", "--doctests"],
    ]
    # Each lane starts with clean instrumentation data, never clean build artifacts.
    for number, lane in enumerate(lanes):
        subprocess.run(["cargo", "llvm-cov", "clean", "--workspace"], cwd=ROOT, check=True)
        subprocess.run(["cargo", "llvm-cov", *lane, "--no-report"], cwd=ROOT, check=True)
        path = output / f"lane-{number}.lcov"
        subprocess.run(["cargo", "llvm-cov", "report", "--lcov", "--output-path", str(path)], cwd=ROOT, check=True)
        reports.append(path)
    return reports

def main():
    p = argparse.ArgumentParser()
    p.add_argument("reports", nargs="*", type=pathlib.Path)
    p.add_argument("--collect", action="store_true")
    p.add_argument("--output", type=pathlib.Path, default=ROOT / "target/coverage/merged.lcov")
    args = p.parse_args()
    reports = collect(args.output.parent) if args.collect else args.reports
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(merge(reports))
    print(args.output)
if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("COVERAGE-FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
