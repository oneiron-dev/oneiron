#!/usr/bin/env python3
"""Cold-artifact GHA compiler-cache proof on one approved macOS runner.

The two dispatch jobs use the same run-owned target *path* but no retained
artifacts or compiler daemon. Only the GHA cache can bridge the jobs.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

COMMAND = ["cargo", "check", "--locked", "-p", "oneiron-vault-contract", "-j", "2"]


def rust_count(stats, category):
    return stats["stats"][category]["counts"].get("Rust", 0)


def validate(populate, repeat):
    for field in ("run_id", "revision", "namespace", "target", "command", "runner", "os", "arch"):
        if populate[field] != repeat[field]:
            raise ValueError(f"mismatched proof {field}")
    if populate["version"] != "sccache 0.15.0" or repeat["version"] != populate["version"]:
        raise ValueError("unexpected compiler-cache version")
    if populate["baseline_seconds"] <= 0 or populate["populate_seconds"] <= 0:
        raise ValueError("missing baseline/population time")
    if rust_count(populate["populate_stats"], "cache_misses") < 1:
        raise ValueError("population compiled no Rust units")
    if populate["populate_stats"]["stats"]["cache_writes"] < 1:
        raise ValueError("population wrote no compiler results")
    stats = repeat["repeat_stats"]
    if not stats["cache_location"].startswith("ghac,") or not populate["populate_stats"]["cache_location"].startswith("ghac,"):
        raise ValueError("proof did not use the GitHub Actions cache")
    if stats["cache_location"] != populate["populate_stats"]["cache_location"]:
        raise ValueError("repeat read a different backend namespace")
    if rust_count(stats, "cache_hits") < 1:
        raise ValueError("repeat build has no Rust cache hits")
    if not 0 < repeat["repeat_seconds"] < populate["baseline_seconds"]:
        raise ValueError("repeat cold-artifact build was not faster than the host-target-only baseline")


def run_build(target, env):
    start = time.monotonic()
    subprocess.run(COMMAND + ["--target-dir", str(target)], check=True, env=env, timeout=1200)
    return round(time.monotonic() - start, 3)


def measure(phase, output, baseline):
    run_id = os.environ["GITHUB_RUN_ID"]
    if not re.fullmatch(r"[0-9]+", run_id):
        raise ValueError("invalid run id")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    root = temp / f"oneiron-cache-proof-{run_id}"
    if root.is_symlink():
        raise ValueError("proof root is a symlink")
    root.mkdir(mode=0o700, exist_ok=True)
    owner = root / ".run-id"
    if owner.exists() and owner.read_text() != run_id:
        raise ValueError("proof target owned by another run")
    owner.write_text(run_id)
    target = root / "target"
    if target.is_symlink():
        raise ValueError("proof target is a symlink")
    if target.exists():
        raise ValueError("proof target was not empty at job start")
    env = os.environ.copy()
    if env.get("CARGO_BUILD_BUILD_DIR"):
        raise ValueError("separate Cargo build directory would escape the run-owned target")
    namespace = env["SCCACHE_GHA_VERSION"]
    if not env.get("ACTIONS_RESULTS_URL") or not env.get("ACTIONS_RUNTIME_TOKEN") or env.get("SCCACHE_GHA_ENABLED") != "on":
        raise ValueError("GitHub cache runtime not configured")
    version = subprocess.check_output(["sccache", "--version"], text=True).strip()
    if version != "sccache 0.15.0":
        raise ValueError(f"wrong sccache version: {version}")
    # Short, run-private socket: no other runner job or host daemon can supply hits.
    env["SCCACHE_SERVER_UDS"] = f"/tmp/oneiron-cache-proof-{run_id}.sock"
    env["CARGO_INCREMENTAL"] = "0"
    env.pop("RUSTC_WORKSPACE_WRAPPER", None)
    receipt = {"run_id": run_id, "revision": env["GITHUB_SHA"],
               "namespace": namespace, "target": str(target), "command": COMMAND + ["--target-dir", str(target)],
               "version": version, "runner": env.get("RUNNER_NAME"), "os": env.get("RUNNER_OS"),
               "arch": env.get("RUNNER_ARCH"),
               "job_url": f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}/actions/runs/{run_id}"}
    try:
        if phase == "populate":
            plain = env.copy()
            plain.pop("RUSTC_WRAPPER", None)
            plain.pop("SCCACHE_GHA_ENABLED", None)
            receipt["baseline_seconds"] = run_build(target, plain)
            shutil.rmtree(target)
            cached = env.copy()
            cached["RUSTC_WRAPPER"] = "sccache"
            subprocess.run(["sccache", "--zero-stats"], env=cached, check=True)
            receipt["populate_seconds"] = run_build(target, cached)
            receipt["populate_stats"] = json.loads(subprocess.check_output(
                ["sccache", "--show-stats", "--stats-format", "json"], env=cached, text=True))
        else:
            if baseline is None:
                raise ValueError("repeat requires the population artifact")
            populated = json.loads(baseline.read_text())
            cached = env.copy()
            cached["RUSTC_WRAPPER"] = "sccache"
            subprocess.run(["sccache", "--zero-stats"], env=cached, check=True)
            receipt["repeat_seconds"] = run_build(target, cached)
            receipt["repeat_stats"] = json.loads(subprocess.check_output(
                ["sccache", "--show-stats", "--stats-format", "json"], env=cached, text=True))
            validate(populated, receipt)
        output.write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, sort_keys=True), flush=True)
    finally:
        subprocess.run(["sccache", "--stop-server"], env=env, check=False)
        if target.exists() and not target.is_symlink():
            shutil.rmtree(target)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("populate", "repeat"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    try:
        measure(args.phase, args.output, args.baseline)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f"CI-CACHE-PROOF-FAILED: {exc}")


if __name__ == "__main__":
    main()
