#!/usr/bin/env python3
"""Fail-closed fleet receipt validation and measured regression floors (stdlib only)."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

SCHEMA = "oneiron-fleet-v1"
FLOOR_SCHEMA = "oneiron-fleet-floor-v1"
PLAN_KEYS = {"profile", "host_label", "storage_label", "scratch", "agents", "listeners", "concurrency",
             "runtime_threads", "rounds", "hold_ms", "timeout_secs", "map_size",
             "ppr_nodes", "ppr_samples"}
HOST_KEYS = {"os", "arch", "hostname", "kernel", "cpu", "logical_cpus", "compiled_profile",
             "compiled_opt_level", "debug_assertions", "fd_limit"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def close(a, b):
    return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-12)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(),
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def write_new(path, value):
    with Path(path).open("x") as target:
        json.dump(value, target, sort_keys=True, indent=2, allow_nan=False)
        target.write("\n")


def validate(receipt, *, samples_required=True):
    require(set(receipt) == {"schema", "status", "plan", "host", "revision", "dirty", "binary_blake3",
                             "started_unix_ms", "held_sockets", "verified_writes", "verified_recalls",
                             "hold_observed_ms", "metrics", "optimization"}, "receipt shape mismatch")
    require(receipt.get("schema") == SCHEMA and receipt.get("status") == "complete",
            "not a complete fleet receipt")
    plan, host = receipt["plan"], receipt["host"]
    require(set(plan) == PLAN_KEYS and set(host) == HOST_KEYS, "plan/host shape mismatch")
    require(plan["profile"] == "fleet20k-v1", "fixture or unknown profiles cannot set or pass CI floors")
    require(integer(plan["agents"], 20_000, 100_000), "fleet needs 20k-100k agents")
    require(integer(plan["listeners"], 1, min(16, plan["agents"])), "invalid listeners")
    require(integer(plan["concurrency"], 1, min(1024, plan["agents"])), "invalid concurrency")
    for key, low, high in [("runtime_threads", 2, 64), ("rounds", 1, 100),
                           ("hold_ms", 1000, 3_600_000), ("timeout_secs", 1, 3600),
                           ("map_size", 32 * 1024 * 1024, 2**63 - 1),
                           ("ppr_nodes", 100, 100_000),
                           ("ppr_samples", 100, plan["ppr_nodes"])]:
        require(integer(plan[key], low, high), f"invalid {key}")
    for key in ("host_label", "storage_label", "scratch"):
        require(isinstance(plan[key], str) and plan[key].strip(), f"missing {key}")
    require(Path(plan["scratch"]).is_absolute(), "scratch must be absolute")
    require(host["os"] in ("linux", "macos") and host["compiled_opt_level"] in ("2", "3"),
            "baseline and candidate must use optimized Linux/macOS artifacts")
    require(host["debug_assertions"] is False and host["compiled_profile"] == "release",
            "debug or nonrelease artifact cannot set or pass CI floors")
    require(integer(host["logical_cpus"], 1, 65536), "invalid CPU count")
    for key in HOST_KEYS - {"logical_cpus", "debug_assertions"}:
        require(isinstance(host[key], str) and host[key].strip(), f"missing host {key}")
    provenance = receipt.get("revision")
    if provenance is None:
        require(receipt.get("dirty") is None, "partial checkout provenance")
    else:
        require(isinstance(provenance, str) and len(provenance) == 40
                and all(c in "0123456789abcdef" for c in provenance), "invalid revision")
        require(type(receipt.get("dirty")) is bool, "checkout state missing")
    for key, size in (("binary_blake3", 64),):
        value = receipt.get(key, "")
        require(isinstance(value, str) and len(value) == size
                and all(c in "0123456789abcdef" for c in value), f"invalid {key}")
    require(integer(receipt.get("started_unix_ms"), 1, 2**63 - 1), "run time missing")
    require(receipt["held_sockets"] == plan["agents"], "not all sockets were held")
    expected = plan["agents"] * plan["rounds"]
    require(receipt["verified_writes"] == expected and receipt["verified_recalls"] == expected,
            "not every write and recall was verified")
    require(number(receipt["hold_observed_ms"]) and receipt["hold_observed_ms"] >= plan["hold_ms"],
            "socket hold was not measured")
    metrics = receipt["metrics"]
    names = {"socket_open", "socket_probe_before", "socket_probe_after",
             "ppr_full", "ppr_resume", "ppr_prepare"}
    names.update(f"{verb}_{i}" for verb in ("write", "recall") for i in range(plan["rounds"]))
    require(set(metrics) == names, "missing or unexpected per-verb metrics")
    for name, metric in metrics.items():
        validate_metric(name, metric, plan["ppr_samples"] if name.startswith("ppr_") else plan["agents"],
                        samples_required=samples_required)
    validate_optimization(receipt)
    return receipt


def validate_metric(name, metric, count, *, samples_required=True):
    keys = {"completed", "elapsed_seconds", "throughput_per_second", "p99_ms"}
    if samples_required:
        keys.add("samples_ms")
    require(set(metric) == keys, f"{name}: metric shape mismatch")
    require(type(metric["completed"]) is int and metric["completed"] == count,
            f"{name}: incomplete operations")
    for key in ("elapsed_seconds", "throughput_per_second", "p99_ms"):
        require(number(metric[key]), f"{name}: invalid {key}")
    require(close(metric["throughput_per_second"], count / metric["elapsed_seconds"]),
            f"{name}: throughput inconsistent with observations")
    if samples_required:
        samples = metric["samples_ms"]
        require(isinstance(samples, list) and len(samples) == count and all(number(x) for x in samples),
                f"{name}: missing or invalid raw samples")
        require(samples == sorted(samples), f"{name}: samples not sorted")
        require(close(metric["p99_ms"], samples[math.ceil(count * .99) - 1]),
                f"{name}: p99 inconsistent with raw samples")
        require(max(samples) <= metric["elapsed_seconds"] * 1000 * (1 + 1e-9),
                f"{name}: sample exceeds phase duration")


def validate_optimization(receipt):
    opt, metrics = receipt["optimization"], receipt["metrics"]
    require(set(opt) == {"route", "equivalent_pairs", "result_blake3", "incremental_speedup",
                         "preparation_seconds", "preparation_included_speedup"}, "optimization shape mismatch")
    require(opt["route"] == "full-depth10-vs-depth5-resume-to10-v1", "unknown optimization route")
    require(opt["equivalent_pairs"] == receipt["plan"]["ppr_samples"], "PPR output equivalence missing")
    require(isinstance(opt["result_blake3"], str) and len(opt["result_blake3"]) == 64
            and all(c in "0123456789abcdef" for c in opt["result_blake3"]), "output digest missing")
    full, resume, prep = [metrics[f"ppr_{key}"]["elapsed_seconds"] for key in ("full", "resume", "prepare")]
    for key, expected in (("incremental_speedup", full / resume), ("preparation_seconds", prep),
                          ("preparation_included_speedup", full / (resume + prep))):
        require(number(opt[key]) and close(opt[key], expected), f"inconsistent {key}")


def validate_tolerances(throughput_loss, p99_increase):
    # The tolerance is an explicit regression budget, never an invented throughput target.
    for value in (throughput_loss, p99_increase):
        require(number(value) and .01 <= value <= .30, "tolerances must be 0.01..0.30")


def make_floor(receipt, throughput_loss, p99_increase):
    validate(receipt)
    validate_tolerances(throughput_loss, p99_increase)
    baseline = {**receipt, "metrics": {
        name: {key: value for key, value in metric.items() if key != "samples_ms"}
        for name, metric in receipt["metrics"].items()}}
    return {"schema": FLOOR_SCHEMA, "baseline_sha256": fingerprint(receipt),
            "throughput_loss": throughput_loss, "p99_increase": p99_increase,
            "baseline_receipt": baseline}


def validate_floor(floor):
    require(set(floor) == {"schema", "baseline_sha256", "throughput_loss", "p99_increase", "baseline_receipt"}
            and floor["schema"] == FLOOR_SCHEMA, "missing or invalid floor")
    digest = floor["baseline_sha256"]
    require(isinstance(digest, str) and len(digest) == 64
            and all(c in "0123456789abcdef" for c in digest), "invalid baseline digest")
    validate_tolerances(floor["throughput_loss"], floor["p99_increase"])
    return validate(floor["baseline_receipt"], samples_required=False)


def compare(floor, candidate):
    baseline = validate_floor(floor)
    validate(candidate)
    require(candidate["plan"] == baseline["plan"], "profile/settings mismatch")
    require(candidate["host"] == baseline["host"], "host/build-settings mismatch")
    require(candidate["optimization"]["result_blake3"] == baseline["optimization"]["result_blake3"],
            "optimization output changed")
    rows = []
    for name, before in baseline["metrics"].items():
        after = candidate["metrics"][name]
        minimum = before["throughput_per_second"] * (1 - floor["throughput_loss"])
        maximum = before["p99_ms"] * (1 + floor["p99_increase"])
        passed = after["throughput_per_second"] >= minimum and after["p99_ms"] <= maximum
        rows.append({"metric": name, "minimum_throughput_per_second": minimum,
                     "maximum_p99_ms": maximum, "observed_throughput_per_second": after["throughput_per_second"],
                     "observed_p99_ms": after["p99_ms"], "passed": passed})
    return {"schema": "oneiron-fleet-comparison-v1", "status": "pass" if all(r["passed"] for r in rows) else "regression",
            "baseline_sha256": floor["baseline_sha256"], "candidate_sha256": fingerprint(candidate), "metrics": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("make-floor", help="explicitly accept a measured fleet baseline")
    create.add_argument("--baseline", required=True)
    create.add_argument("--throughput-loss", required=True, type=float)
    create.add_argument("--p99-increase", required=True, type=float)
    create.add_argument("--out", required=True)
    for verb in ("compare", "ci"):
        sub = commands.add_parser(verb)
        sub.add_argument("--floor", required=True)
        sub.add_argument("--candidate", required=True, help="existing receipt for compare; NEW receipt path for ci")
        sub.add_argument("--out", required=True, help="NEW comparison receipt path")
        if verb == "ci":
            sub.add_argument("--bench", required=True)
            sub.add_argument("--plan", required=True)
    args = parser.parse_args(argv)
    try:
        require(not Path(args.out).exists(), "output already exists")
        if args.command == "make-floor":
            result = make_floor(read(args.baseline), args.throughput_loss, args.p99_increase)
        else:
            floor = read(args.floor)  # Missing floors fail BEFORE any load run.
            baseline = validate_floor(floor)
            if args.command == "ci":
                require(read(args.plan) == baseline["plan"], "CI plan differs from approved floor")
                require(not Path(args.candidate).exists(), "CI receipt already exists")
                run = subprocess.run([args.bench, "fleet", "run", "--plan", args.plan,
                                      "--out", args.candidate], check=False)
                require(run.returncode == 0, f"fleet process failed with {run.returncode}; inspect {args.candidate}")
            result = compare(floor, read(args.candidate))
        write_new(args.out, result)
        print(json.dumps({"status": result.get("status", "floor-created"), "receipt": args.out}))
        return 1 if result.get("status") == "regression" else 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        print(f"fleet regression gate refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
