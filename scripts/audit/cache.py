#!/usr/bin/env python3
"""Measure the pinned compiler cache with cold artifacts and an isolated cache."""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
ROOT = pathlib.Path(__file__).resolve().parents[2]


def measure(package, output):
    version = subprocess.check_output(["sccache", "--version"], text=True).strip()
    if version != "sccache 0.15.0":
        raise ValueError("required sccache 0.15.0")
    parent = ROOT / "target/cache-audit"
    parent.mkdir(parents=True, exist_ok=True)
    # Every target, socket and cache belongs to this run, never the CI/developer target.
    with tempfile.TemporaryDirectory(prefix="run-", dir=parent) as fresh:
        root = pathlib.Path(fresh)
        target = root / "build"
        source = root / "source"
        # Freeze source bytes so parallel lint fixes cannot change a measured lane.
        shutil.copytree(ROOT, source, symlinks=True,
                        ignore=shutil.ignore_patterns(".git", "target", ".w7", "node_modules"))
        env = os.environ.copy()
        env.pop("RUSTC_WRAPPER", None)
        env.pop("RUSTC_WORKSPACE_WRAPPER", None)
        env["CARGO_INCREMENTAL"] = "0"
        env["SCCACHE_DIR"] = str(root / "cache")
        env["SCCACHE_SERVER_UDS"] = str(root / "s.sock")
        env["SCCACHE_IDLE_TIMEOUT"] = "60"
        command = ["cargo", "check", "--locked", "-p", package, "-j", "2",
                   "--target-dir", str(target)]
        timings = {}
        stats = None
        try:
            for lane in ["uncached", "populate", "cached"]:
                if target.exists():
                    shutil.rmtree(target)
                run_env = env.copy()
                if lane != "uncached":
                    run_env["RUSTC_WRAPPER"] = "sccache"
                started = time.monotonic()
                subprocess.run(command, cwd=source, env=run_env, check=True)
                timings[lane] = time.monotonic() - started
                if lane == "populate":
                    # Reset only this run's private server counters, not its cache.
                    subprocess.run(["sccache", "--zero-stats"], env=env, check=True)
                if lane == "cached":
                    stats = json.loads(subprocess.check_output(
                        ["sccache", "--show-stats", "--stats-format", "json"], env=env, text=True))
            hits = stats["stats"]["cache_hits"]["counts"].get("Rust", 0)
            result = {"tool": version, "package": package, "cargo_jobs": 2,
                      "seconds": timings, "rust_cache_hits": hits, "stats": stats,
                      "method": "one frozen source snapshot and target path; artifact directory empty before each lane; isolated compiler cache"}
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, indent=2) + "\n")
            if hits < 1 or timings["cached"] >= timings["uncached"]:
                raise ValueError("repeat build did not demonstrate Rust hits and lower wall time; evidence retained")
            print(json.dumps({"rust_cache_hits": hits, "seconds": timings}, sort_keys=True))
        finally:
            if (root / "s.sock").exists():
                subprocess.run(["sccache", "--stop-server"], env=env, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", default="oneiron-server")
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "target/cache-audit/evidence.json")
    args = parser.parse_args()
    measure(args.package, args.output)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit("CACHE-AUDIT-FAILED: " + str(error))
