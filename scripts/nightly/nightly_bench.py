#!/usr/bin/env python3
"""The nightly job's oneiron-bench stage (Fable's test verdict 2026-11-09, bench row; PR 10b2).

Standard library only; scripts/nightly/nightly_report.py imports it. Fable's
bench row: oneiron-bench perf and beam are "not product doors. Make them
nightly budget jobs writing scores-table rows". The nightly's `bench`
selection builds oneiron-bench's bin and tests (run_nightly.sh); then the
bench jobs (BENCH_JOBS) run that bin offline, with no model, key or network:

  perf-smoke                 the bundled synthetic perf smoke
  perf-smoke-child-override  the same, its ready children spawned through
                             ONEIRON_BENCH_PERF_CHILD
  perf-full-refusal          the smoke plan as a full run: refused at admission
  beam-smoke                 the bundled BEAM smoke
  beam-infra                 the shipped v1 infra cards beside the night's receipt
  beam-contract              the JSONL contract manifest

A job's metrics (bench_metrics: every perf p99, the beam smoke's pack query
p99, in seconds) are timed in the budget band by the `job` rows of
scripts/nightly/budget-set.tsv. The promises of the bench tests the NO-DOOR
register retired (ND-015 perf, ND-025 beam; BENCH_PROMISES) are checked on the
jobs' output wherever a job shows one; a promise its job's output cannot show
tonight (an override cohort whose memory was never measured) is not checked.
A job that ends otherwise than expected, prints no report, or breaks a promise
makes the night red.
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable
from pathlib import Path

# oneiron-bench's own selection (PR 10b2). It keeps `--workspace` and only
# drops the exclude: cargo tree at 7a27ddc68f67 (14 Nov) resolves every package
# the other selections build to the same features that way, while
# `-p oneiron-bench` alone changes 61 packages and rebuilds the core.
BENCH_PACKAGE = "oneiron-bench"
BENCH_FIXTURES = "crates/oneiron-bench/fixtures"
BENCH_CONTRACT_FILES = ("beam_128k_contract.run.json", "beam_128k_contract.run.jsonl")
# The bench jobs: (name, command, expected exit code). Every one runs offline
# (no model, key or network) from the bench bin ({bin}) in the night's bench
# work dir ({work}), which bench-inputs fills.
BENCH_JOBS = (
    ("perf-smoke", ("{bin}", "perf", "smoke"), 0),
    # the same smoke with the ready children spawned through the override, which proves readiness but never residency
    ("perf-smoke-child-override", ("env", "ONEIRON_BENCH_PERF_CHILD={bin}", "{bin}", "perf", "smoke"), 0),
    # the smoke plan as a full run with the full session curve: refused at admission, its workload is below the floors
    (
        "perf-full-refusal",
        (
            "{bin}",
            "perf",
            "run",
            "--plan",
            "{work}/perf-full-undersized.plan.json",
            "--out",
            "{work}/perf-full-undersized.report.json",
        ),
        1,
    ),  # fmt: skip
    ("beam-smoke", ("{bin}", "beam", "smoke"), 0),
    ("beam-infra", ("{bin}", "beam", "infra", "{work}/infra.json"), 0),
    ("beam-contract", ("{bin}", "beam", "run", "{work}/" + BENCH_CONTRACT_FILES[0]), 0),
)
BENCH_JOB_SECONDS = 1800  # each job's bound, where `timeout` exists
BENCH_INFRA_MEASURED = {"recall_at_k": 0.9, "latency_us": 1200, "cost_usd": 0.0001}
BENCH_FULL_SESSION_CURVE = [1, 10, 100, 300]
BENCH_LATENCY_FLOOR_REFUSAL = "a full run needs >=1000 indexed docs and >=100 queries"
PRECISION_CANDIDATES = ("f32", "f16", "int8_sq", "binary_prefix_rescore")
# Fields a merged warm-and-cold population would need on the recall/latency axis.
MERGED_SAMPLE_FIELDS = (
    "combined",
    "overall",
    "merged",
    "average",
    "all_samples",
    "samples",
    "latency_ms",
    "recall_at_k",
)


def bench_receipt(date: str, head: str) -> str:
    return f"nightly://{date}/{head[:12]}/bench"


def bench_inputs(root: Path, work: Path, date: str, head: str) -> None:
    """The bench jobs' input files in `work`.

    The contract manifest and its JSONL sit side by side, as the manifest
    names them (its packs.jsonl output lands there too); the infra input
    omits its comparators, so the job reports the shipped v1 cards beside the
    night's receipt; and the smoke plan becomes a full run with the full
    session curve, which admission must refuse for its undersized corpus.
    """
    work.mkdir(parents=True, exist_ok=True)
    fixtures = root / BENCH_FIXTURES
    for name in BENCH_CONTRACT_FILES:
        shutil.copyfile(fixtures / name, work / name)
    infra = {"measurement_receipt": bench_receipt(date, head), "measured": BENCH_INFRA_MEASURED}
    (work / "infra.json").write_text(json.dumps(infra) + "\n")
    full = json.loads((fixtures / "perf_smoke.plan.json").read_text())
    full["mode"] = "full"
    full["sessions"]["curve"] = BENCH_FULL_SESSION_CURVE
    (work / "perf-full-undersized.plan.json").write_text(json.dumps(full, indent=1) + "\n")


def bench_job_commands(binary: str, work: str) -> list[tuple[str, int, list[str]]]:
    """Each bench job's command line, bounded by `timeout` where the host has it."""
    bound = ["timeout", str(BENCH_JOB_SECONDS)] if shutil.which("timeout") else []
    return [
        (name, expected, [*bound, *(part.replace("{bin}", binary).replace("{work}", work) for part in command)])
        for name, command, expected in BENCH_JOBS
    ]


def read_report_json(path: Path) -> dict | None:
    """The JSON object a bench job printed, from its first line that opens one (perf prints a summary first)."""
    if not path.is_file():
        return None
    text = path.read_text(errors="replace")
    for match in re.finditer(r"(?m)^\{", text):
        try:
            value, _ = json.JSONDecoder().raw_decode(text, match.start())
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def percentile_metrics(value: object, path: tuple[str, ...] = ()) -> dict[str, float]:
    """`<path>.p99` -> seconds for every measured percentile set under a `*_ms` key of a perf report.

    A list item is named by its `candidate` or `sessions` field when it has
    one (precision rows, session curve points), else by its position.
    """
    found: dict[str, float] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            cell = child.get("value") if isinstance(child, dict) and child.get("status") == "measured" else None
            if key.endswith("_ms") and isinstance(cell, dict) and isinstance(cell.get("p99"), (int, float)):
                found[".".join((*path, key.removesuffix("_ms"), "p99"))] = cell["p99"] / 1000
            else:
                found.update(percentile_metrics(child, (*path, key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            label = child.get("candidate", child.get("sessions", index)) if isinstance(child, dict) else index
            found.update(percentile_metrics(child, (*path, str(label))))
    return found


def numbers_under(value: object, key: str) -> list[float]:
    """Every number held by `key` anywhere in a JSON value."""
    if isinstance(value, dict):
        return [
            number
            for name, child in value.items()
            for number in ([child] if name == key and isinstance(child, (int, float)) else numbers_under(child, key))
        ]
    if isinstance(value, list):
        return [number for child in value for number in numbers_under(child, key)]
    return []


def nearest_rank(samples: list[float], percent: float) -> float:
    """The bench's own percentile rule (perf/cells.rs): nearest rank over the sorted samples."""
    ordered = sorted(samples)
    rank = -(-percent * len(ordered) // 100)
    return ordered[min(max(int(rank), 1), len(ordered)) - 1]


def bench_metrics(job: str, report: dict) -> dict[str, float]:
    """A bench job's timed metrics, in seconds: every perf smoke p99, and the p99 of the beam smoke's pack queries."""
    if job == "perf-smoke":
        return percentile_metrics(report)
    if job == "beam-smoke":
        times = numbers_under(report, "queryTimeUs")
        return {"query_time.p99": nearest_rank(times, 99) / 1_000_000} if times else {}
    return {}


def cell_measured(cell: object) -> bool:
    return isinstance(cell, dict) and cell.get("status") == "measured"


def promise_cold_and_warm_stay_separate(reports: dict, receipt: str) -> tuple[bool, str] | None:
    report = reports.get("perf-smoke")
    if report is None:
        return None
    axis = report.get("recall_latency") or {}
    merged = sorted(field for field in MERGED_SAMPLE_FIELDS if field in axis)
    sets = [
        side
        for side in ("cold", "warm")
        if isinstance(axis.get(side), dict) and "latency_ms" in axis[side] and "recall_at_k" in axis[side]
    ]
    return sets == ["cold", "warm"] and not merged, (
        f"sample sets: {', '.join(sets) or 'none'}; merged fields: {', '.join(merged) or 'none'}"
    )


def promise_full_runs_refuse_undersized_plans(reports: dict, receipt: str) -> tuple[bool, str] | None:
    report = reports.get("perf-full-refusal")
    if report is None:
        return None
    refusal = next((line for line in report["stderr"].splitlines() if line.startswith("perf: ")), "no refusal line")
    return BENCH_LATENCY_FLOOR_REFUSAL in refusal and not report["report_written"], (
        refusal[:200] + ("; a report was written" if report["report_written"] else "")
    )


def precision_bytes_per_vector(candidate: str, dimensions: int) -> int | None:
    """perf/precision.rs bytes_per_vector: the binary row counts its u64 code words plus the f32 rescore payload."""
    sizes = {
        "f32": dimensions * 4,
        "f16": dimensions * 2,
        "int8_sq": dimensions + 4,
        "binary_prefix_rescore": -(-dimensions // 64) * 8 + dimensions * 4,
    }
    return sizes.get(candidate)


def promise_precision_rows(reports: dict, receipt: str) -> tuple[bool, str] | None:
    report = reports.get("perf-smoke")
    if report is None:
        return None
    axis = report.get("precision") or {}
    rows = axis.get("rows") or []
    dimensions = axis.get("dimensions")
    problems = []
    names = [row.get("candidate") for row in rows]
    if names != list(PRECISION_CANDIDATES):
        problems.append(f"rows {names}")
    for row in rows:
        for cell in ("mean_recall_at_k", "recall_at_k", "scan_latency_ms"):
            if not cell_measured(row.get(cell)):
                problems.append(f"{row.get('candidate')} {cell} not measured")
        if not isinstance(dimensions, int) or row.get("bytes_per_vector") != precision_bytes_per_vector(
            str(row.get("candidate")), dimensions
        ):
            problems.append(f"{row.get('candidate')} bytes_per_vector {row.get('bytes_per_vector')}")
    exact = next((row for row in rows if row.get("candidate") == "f32"), {})
    if (exact.get("mean_recall_at_k") or {}).get("value") != 1.0:
        problems.append("the f32 row's mean recall is not exactly 1.0")
    binary = next((row for row in rows if row.get("candidate") == "binary_prefix_rescore"), {})
    if binary.get("prefix_breadth") != axis.get("binary_prefix_breadth"):
        problems.append(f"binary prefix_breadth {binary.get('prefix_breadth')}")
    return not problems, "; ".join(problems) or (
        f"4 rows at {dimensions} dimensions, f32 recall 1.0, binary prefix breadth {binary.get('prefix_breadth')}"
    )


def promise_override_child_never_claims_residency(reports: dict, receipt: str) -> tuple[bool | None, str] | None:
    report = reports.get("perf-smoke-child-override")
    if report is None:
        return None
    axis = report.get("resident_memory") or {}
    harness = (reports.get("perf-smoke") or {}).get("resident_memory") or {}
    claims = axis.get("child_holds_open_vault")
    evidence = str(axis.get("vault_residency_evidence", ""))
    rss = axis.get("per_child_rss_bytes")
    # the harness-owned run may claim residency only with harness-owned evidence
    harness_claim = harness.get("child_holds_open_vault")
    harness_ok = not harness_claim or str(harness.get("vault_residency_evidence", "")).startswith("harness-owned")
    detail = (
        f"override child_holds_open_vault={claims}, rss {'measured' if cell_measured(rss) else 'not measured'};"
        f" harness-owned child_holds_open_vault={harness_claim}"
    )
    if claims is not False or not harness_ok:
        return False, detail
    if not cell_measured(rss):
        # No complete cohort was measured (a host without /proc/<pid>/status, or a child that never came up): the
        # override run claims nothing, and shows no override evidence either, so the promise is not checked tonight.
        reason = rss.get("reason", "") if isinstance(rss, dict) else ""
        return None, detail + "; not checked: " + (reason or "no complete child cohort was measured")
    return "ONEIRON_BENCH_PERF_CHILD" in evidence, detail


def promise_infra_cards_beside_the_measurement(reports: dict, receipt: str) -> tuple[bool, str] | None:
    report = reports.get("beam-infra")
    if report is None:
        return None
    rows = report.get("comparators") or []
    problems = []
    if report.get("purpose") != "cost-framing-only":
        problems.append(f"purpose {report.get('purpose')!r}")
    if report.get("measurement_receipt") != receipt:
        problems.append(f"receipt {report.get('measurement_receipt')!r}")
    if len(rows) != 3:
        problems.append(f"{len(rows)} comparator cards, not the 3 v1 cards")
    if not all(row.get("measurement") and row.get("source") and row.get("system") for row in rows):
        problems.append("a card without its measurement, source or system")
    return not problems, "; ".join(problems) or "3 v1 cards, each measured and sourced, beside the night's receipt"


def promise_contract_offline_cost_once(reports: dict, receipt: str) -> tuple[bool, str] | None:
    report = reports.get("beam-contract")
    if report is None:
        return None
    cases = report.get("cases") or []
    problems = [] if cases else ["no case"]
    if (report.get("dataset") or {}).get("sourceKind") != "jsonl":
        problems.append(f"dataset source {(report.get('dataset') or {}).get('sourceKind')!r}")
    for case in cases:
        amortized = (case.get("offlineAmortizedCost") or {}).get("elapsedUs")
        rows = [*case.get("competitors", []), *case.get("appendix", []), *case.get("dropped", [])]
        if not isinstance(amortized, int) or amortized <= 0:
            problems.append(f"case amortized offline elapsedUs {amortized}")
        elif any(((row.get("costs") or {}).get("offline") or {}).get("elapsedUs") != amortized for row in rows):
            problems.append("a row whose offline elapsedUs differs from the case's amortized cost")
    return not problems, "; ".join(
        problems
    ) or f"{len(cases)} case(s): one positive amortized offline cost in every row"


# The promises of the bench tests the NO-DOOR register retired (ND-015 perf, ND-025 beam; deleted in df854d6bb524),
# which Fable's bench row moved to the nightly bench jobs: (T3D promise row, the retired test, check). A check reads
# the jobs' reports; None means no nightly job shows the promise, and the second field says why.
BENCH_PROMISES: tuple[tuple[str, str, Callable[[dict, str], tuple[bool, str] | None] | str], ...] = (
    (
        "P-oneiron-bench-d8df5d78",
        "ND-015 perf/axes.rs cold_and_warm_samples_stay_separate",
        promise_cold_and_warm_stay_separate,
    ),
    (
        "P-oneiron-bench-d4fa7689",
        "ND-015 perf/axes.rs an_under_floor_full_run_reports_not_applicable_instead_of_numbers",
        "only a full run whose completed samples fall below the floor rewrites its cells",
    ),
    (
        "P-oneiron-bench-dd5960e1",
        "ND-015 perf/plan/tests.rs full_run_floors_and_axis_shape_are_enforced",
        promise_full_runs_refuse_undersized_plans,
    ),
    (
        "P-oneiron-bench-2f9c083e",
        "ND-015 perf/precision/tests.rs precision_candidates_report_recall_memory_and_scan_latency",
        promise_precision_rows,
    ),
    (
        "P-oneiron-bench-53839f47",
        "ND-015 perf/resident_memory.rs an_environment_overridden_child_cohort_never_claims_vault_residency",
        promise_override_child_never_claims_residency,
    ),
    (
        "P-oneiron-bench-ebb5f904",
        "ND-025 beam/infra.rs published_v1_cards_appear_beside_a_receipted_measurement",
        promise_infra_cards_beside_the_measurement,
    ),
    (
        "P-oneiron-bench-0b14d317",
        "ND-025 beam/model_scaffold/tests.rs measured_two_case_ingest_amortizes_measured_tokens_and_index_time",
        "only `beam measure` reports it, and it needs a model endpoint",
    ),
    (
        "P-oneiron-bench-158c7d72",
        "ND-025 beam/tests_jsonl_contract.rs jsonl_runner_keeps_loader_index_time_once_in_offline_cost",
        promise_contract_offline_cost_once,
    ),
)


def read_bench_jobs(out: Path) -> dict[str, dict]:
    """bench-jobs.tsv (job, exit code, seconds), as run_nightly.sh wrote it."""
    path = out / "bench-jobs.tsv"
    jobs = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            name, code, seconds = line.split("\t")
            jobs[name] = {"job": name, "rc": code, "seconds": int(seconds) if seconds.isdigit() else None}
    return jobs


def bench_report(out: Path, chosen: dict, date: str, head: str) -> dict:
    """The bench jobs' night: which ran, their metrics (seconds, keyed as JUnit keys), and each promise's check."""
    selected = any(entry["kind"] == "bench" for entry in chosen["selections"])
    ran_jobs = read_bench_jobs(out)
    receipt = bench_receipt(date, head)
    jobs, reports, reasons, metrics = {}, {}, [], {}
    for name, _, expected in BENCH_JOBS if selected else ():
        job = ran_jobs.get(name, {"job": name, "rc": "none", "seconds": None})
        job["expected"] = expected
        if name not in ran_jobs:
            why = "no run"
        elif job["rc"] != str(expected):
            why = f"exit {job['rc']}, expected {expected}"
        elif expected == 0:
            report = read_report_json(out / f"bench-{name}.out")
            why = "" if report is not None else "no JSON report"
            if report is not None:
                reports[name] = report
                metrics.update(
                    {f"{BENCH_PACKAGE}::{name} {key}": value for key, value in bench_metrics(name, report).items()}
                )
        else:
            err = out / f"bench-{name}.err"
            reports[name] = {
                "stderr": err.read_text(errors="replace") if err.is_file() else "",
                "report_written": (out / "bench-work" / "perf-full-undersized.report.json").exists(),
            }
            why = ""
        job.update(ran=not why, why=why)
        jobs[name] = job
        if why:
            reasons.append(f"the bench job {name} did not run as expected ({why})")
    promises = []
    for promise, retired, check in BENCH_PROMISES if selected else ():
        if isinstance(check, str):
            promises.append({"promise": promise, "retired": retired, "state": "not-shown", "detail": check})
            continue
        result = check(reports, receipt)
        if result is None:
            promises.append(
                {"promise": promise, "retired": retired, "state": "not-checked", "detail": "its job did not run"}
            )
            continue
        kept, detail = result
        state = "not-checked" if kept is None else "kept" if kept else "broken"
        promises.append({"promise": promise, "retired": retired, "state": state, "detail": detail})
        if kept is False:
            reasons.append(f"bench promise {promise} broken: {detail}")
    states = [entry["state"] for entry in promises]
    return {
        "selected": selected,
        "jobs": jobs,
        "ran": sum(1 for job in jobs.values() if job["ran"]),
        "planned": len(jobs),
        "metrics": metrics,
        "outcomes": dict.fromkeys(metrics, "pass"),
        "promises": promises,
        "kept": states.count("kept"),
        "checked": states.count("kept") + states.count("broken"),
        "reasons": reasons,
    }
