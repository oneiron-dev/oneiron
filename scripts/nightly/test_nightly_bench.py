"""Tests of the nightly's oneiron-bench stage (PR 10b2): scripts/nightly/nightly_bench.py and the bench parts of
nightly_report.py (the bench selection, its pruning, and the summary's bench jobs and promises).

Run: python3 -m unittest discover -s scripts/nightly -p 'test_*.py' -v
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nightly_bench  # noqa: E402
import nightly_report  # noqa: E402

HEAD = "0123456789abcdef0123456789abcdef01234567"
RECEIPT = f"nightly://2026-11-15/{HEAD[:12]}/bench"
HARNESS_EVIDENCE = "harness-owned perf wake-child opens the assigned vault before its TCP connect"
OVERRIDE_EVIDENCE = "the ready-child program was substituted through ONEIRON_BENCH_PERF_CHILD: readiness only"
UNMEASURED_EVIDENCE = "no complete child cohort was measured, so no process is claimed to hold an open vault"
NO_PROC = {"status": "not_ready", "reason": "per-child RSS needs /proc/<pid>/status, which this host does not have"}
REFUSAL = (
    "perf: a full run needs >=1000 indexed docs and >=100 queries for latency/recall; the plan asks for 48 docs and"
    " 8 queries"
)


def target(name: str, kind: str, test: bool = True) -> dict:
    return {"name": name, "kind": [kind], "test": test}


# oneiron-bench as it is: a bin (no lib), two integration tests, and a harness=false bench target nextest never runs
METADATA = {
    "workspace_members": ["oneiron 0.1.0", "oneiron-bench 0.1.0"],
    "packages": [
        {"id": "oneiron 0.1.0", "name": "oneiron", "targets": [target("oneiron", "lib"), target("alpha", "test")]},
        {
            "id": "oneiron-bench 0.1.0",
            "name": "oneiron-bench",
            "targets": [
                target("oneiron-bench", "bin"),
                target("cleanup_retrieval", "test"),
                target("materializer_mutex_contracts", "test"),
                target("materializer_mutex", "bench", test=False),
            ],
        },
    ],
}


def unit(package: str, kind: str, name: str = "") -> dict:
    return {"package": package, "kind": kind, "name": name}


def measured(value: object) -> dict:
    return {"status": "measured", "value": value}


def percentiles(p99_ms: float) -> dict:
    return {"count": 8, "p50": p99_ms / 2, "p95": p99_ms * 0.9, "p99": p99_ms, "min": 0.1, "max": p99_ms, "mean": 1.0}


def perf_report(override: bool = False) -> dict:
    """A perf smoke report in the bench's shape (perf/report.rs, axes.rs, precision.rs), at 32 dimensions."""
    rows = [
        {
            "candidate": candidate,
            "bytes_per_vector": size,
            "mean_recall_at_k": measured(1.0 if candidate == "f32" else 0.95),
            "recall_at_k": measured(percentiles(1.0)),
            "scan_latency_ms": measured(percentiles(0.2)),
            **({"prefix_breadth": 40} if candidate == "binary_prefix_rescore" else {}),
        }
        for candidate, size in zip(nightly_bench.PRECISION_CANDIDATES, (128, 64, 36, 136))
    ]
    return {
        "schema": "oneiron.bench.perf_report.v2",
        "mode": "synthetic_smoke",
        "recall_latency": {
            "k": 10,
            "cold": {
                "label": "cold",
                "latency_ms": measured(percentiles(12.0)),
                "recall_at_k": measured(percentiles(1)),
            },
            "warm": {
                "label": "warm",
                "latency_ms": measured(percentiles(4.0)),
                "recall_at_k": measured(percentiles(1)),
            },
        },
        "wake": {"samples": 2, "spawn_to_ready_ms": measured(percentiles(30.0))},
        "sessions": {
            "curve": [
                {"sessions": 1, "latency_ms": measured(percentiles(5.0))},
                {"sessions": 4, "latency_ms": measured(percentiles(9.0))},
            ]
        },
        "resident_memory": {
            "child_holds_open_vault": not override,
            "vault_residency_evidence": OVERRIDE_EVIDENCE if override else HARNESS_EVIDENCE,
            "per_child_rss_bytes": measured([1000, 1200]),
        },
        "gated_writes": {
            "commit_latency_ms": measured(percentiles(2.0)),
            "failed_attempt_latency_ms": {"status": "not_ready", "reason": "no failed attempt"},
        },
        "precision": {"dimensions": 32, "binary_prefix_breadth": 40, "rows": rows},
    }


def reports() -> dict[str, dict]:
    """Every bench job's report on a good night, as the summary reads them."""
    return {
        "perf-smoke": perf_report(),
        "perf-smoke-child-override": perf_report(override=True),
        "perf-full-refusal": {"stderr": REFUSAL + "\n", "report_written": False},
        "beam-smoke": {
            "schemaVersion": 1,
            "cases": [
                {"arms": [{"packStats": {"queryTimeUs": 1500}}, {"packStats": {"queryTimeUs": 2500}}]},
                {"arms": [{"packStats": {"queryTimeUs": 900}}]},
            ],
        },
        "beam-infra": {
            "purpose": "cost-framing-only",
            "measurement_receipt": RECEIPT,
            "measured": nightly_bench.BENCH_INFRA_MEASURED,
            "comparators": [
                {"system": f"system {n}", "source": f"https://example.com/{n}", "measurement": {"latency_us": n}}
                for n in (1, 2, 3)
            ],
        },
        "beam-contract": {
            "dataset": {"sourceKind": "jsonl"},
            "cases": [
                {
                    "offlineAmortizedCost": {"elapsedUs": 4200},
                    "competitors": [{"costs": {"offline": {"elapsedUs": 4200}}}],
                    "appendix": [],
                    "dropped": [{"costs": {"offline": {"elapsedUs": 4200}}}],
                }
            ],
        },
    }


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def write_job_outputs(out: Path, codes: dict[str, int] | None = None, report_of: dict | None = None) -> None:
    """bench-jobs.tsv and each job's output, as run_nightly.sh leaves them (perf prints a summary before its JSON)."""
    codes = codes or {}
    report_of = reports() if report_of is None else report_of
    rows = []
    for name, _, expected in nightly_bench.BENCH_JOBS:
        rows.append(f"{name}\t{codes.get(name, expected)}\t3")
        report = report_of.get(name)
        if name == "perf-full-refusal":
            write(out / f"bench-{name}.err", report["stderr"] if report else "")
            write(out / f"bench-{name}.out", "")
        else:
            preface = "== oneiron perf bench (ONE-1579) ==\nmode: synthetic_smoke\n" if name.startswith("perf") else ""
            write(out / f"bench-{name}.out", preface + (json.dumps(report, indent=2) if report else "") + "\n")
    write(out / "bench-jobs.tsv", "\n".join(rows) + "\n")


class BenchSelectionTest(unittest.TestCase):
    def test_the_bench_selection_keeps_the_workspace_and_names_the_bin_and_its_integration_tests(self) -> None:
        chosen = nightly_report.plan(METADATA, shard_files=1, bench=True)
        self.assertEqual([entry["name"] for entry in chosen["selections"]], ["libs", "bench", "tests-01"])
        bench = chosen["selections"][1]
        self.assertEqual(
            nightly_report.selection_args(chosen, bench),
            [
                "--workspace", "--bin", "oneiron-bench",
                "--test", "cleanup_retrieval", "--test", "materializer_mutex_contracts",
            ],
        )  # fmt: skip
        self.assertEqual(
            nightly_report.selection_args(chosen, chosen["selections"][2]),
            ["--workspace", "--exclude", "oneiron-bench", "--test", "alpha"],
        )
        self.assertEqual(
            nightly_report.selection_binaries(bench),
            ["cleanup_retrieval", "materializer_mutex_contracts", "oneiron-bench"],
        )
        self.assertNotIn("bench", [e["name"] for e in nightly_report.plan(METADATA, bench=False)["selections"]])

    def test_a_failed_bin_drops_the_bench_selection(self) -> None:
        chosen = nightly_report.plan(METADATA, bench=True)
        self.assertFalse(
            nightly_report.prune(chosen, "bench", [unit("oneiron-bench", "bin", "oneiron-bench")], METADATA)
        )
        self.assertEqual(
            chosen["dropped"], [{"selection": "bench", "reason": "did not compile: oneiron-bench (bin oneiron-bench)"}]
        )

    def test_a_failed_bin_test_or_test_file_leaves_only_that_unit_out_of_the_bench_selection(self) -> None:
        chosen = nightly_report.plan(METADATA, bench=True)
        failed = [
            unit("oneiron-bench", "bin-test", "oneiron-bench"),
            unit("oneiron-bench", "test", "cleanup_retrieval"),
        ]
        self.assertTrue(nightly_report.prune(chosen, "bench", failed, METADATA))
        bench = nightly_report.find_selection(chosen, "bench")
        self.assertEqual(
            nightly_report.selection_args(chosen, bench), ["--workspace", "--test", "materializer_mutex_contracts"]
        )
        self.assertEqual(
            [(u["kind"], u["name"]) for u in chosen["unselected"]],
            [("bin-test", "oneiron-bench"), ("test", "cleanup_retrieval")],
        )
        self.assertFalse(
            nightly_report.prune(
                chosen, "bench", [unit("oneiron-bench", "test", "materializer_mutex_contracts")], METADATA
            )
        )
        self.assertEqual(chosen["dropped"], [{"selection": "bench", "reason": "every unit is left out"}])


class BenchJobsTest(unittest.TestCase):
    def test_each_job_command_names_the_bin_and_the_work_dir_and_is_bounded_where_timeout_exists(self) -> None:
        with mock.patch.object(nightly_bench.shutil, "which", return_value=None):
            commands = nightly_bench.bench_job_commands("/t/oneiron-bench", "/o/bench-work")
        self.assertEqual(
            [(name, expected) for name, expected, _ in commands],
            [
                ("perf-smoke", 0), ("perf-smoke-child-override", 0), ("perf-full-refusal", 1),
                ("beam-smoke", 0), ("beam-infra", 0), ("beam-contract", 0),
            ],
        )  # fmt: skip
        self.assertEqual(
            commands[1][2], ["env", "ONEIRON_BENCH_PERF_CHILD=/t/oneiron-bench", "/t/oneiron-bench", "perf", "smoke"]
        )
        self.assertEqual(
            commands[5][2], ["/t/oneiron-bench", "beam", "run", "/o/bench-work/beam_128k_contract.run.json"]
        )
        with mock.patch.object(nightly_bench.shutil, "which", return_value="/usr/bin/timeout"):
            bounded = nightly_bench.bench_job_commands("/t/oneiron-bench", "/o/bench-work")
        self.assertEqual(bounded[0][2], ["timeout", "1800", "/t/oneiron-bench", "perf", "smoke"])

    def test_the_inputs_hold_the_contract_pair_the_infra_receipt_and_the_smoke_plan_as_a_full_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, work = Path(tmp) / "repo", Path(tmp) / "work"
            fixtures = root / nightly_bench.BENCH_FIXTURES
            plan = {"mode": "synthetic_smoke", "sessions": {"curve": [1, 4], "queries_per_session": 4}}
            write(fixtures / "perf_smoke.plan.json", json.dumps(plan))
            for name in nightly_bench.BENCH_CONTRACT_FILES:
                write(fixtures / name, name)
            nightly_report.main(["bench-inputs", str(root), str(work), "2026-11-15", HEAD])
            self.assertEqual((work / "beam_128k_contract.run.jsonl").read_text(), "beam_128k_contract.run.jsonl")
            self.assertEqual(json.loads((work / "infra.json").read_text())["measurement_receipt"], RECEIPT)
            full = json.loads((work / "perf-full-undersized.plan.json").read_text())
            self.assertEqual(full, {"mode": "full", "sessions": {"curve": [1, 10, 100, 300], "queries_per_session": 4}})

    def test_a_report_is_read_past_the_summary_perf_prints_before_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write(Path(tmp) / "out", '== oneiron perf bench ==\nmode: {smoke}\n{\n  "schema": "x"\n}\n')
            self.assertEqual(nightly_bench.read_report_json(path), {"schema": "x"})
            self.assertIsNone(nightly_bench.read_report_json(write(Path(tmp) / "bad", "perf: refused\n{ not json\n")))
            self.assertIsNone(nightly_bench.read_report_json(Path(tmp) / "absent"))

    def test_the_metrics_are_every_measured_ms_percentile_p99_and_the_beam_query_p99_in_seconds(self) -> None:
        metrics = nightly_bench.bench_metrics("perf-smoke", perf_report())
        self.assertEqual(
            sorted(metrics),
            [
                "gated_writes.commit_latency.p99",
                "precision.rows.binary_prefix_rescore.scan_latency.p99",
                "precision.rows.f16.scan_latency.p99",
                "precision.rows.f32.scan_latency.p99",
                "precision.rows.int8_sq.scan_latency.p99",
                "recall_latency.cold.latency.p99",
                "recall_latency.warm.latency.p99",
                "sessions.curve.1.latency.p99",
                "sessions.curve.4.latency.p99",
                "wake.spawn_to_ready.p99",
            ],
        )
        self.assertEqual(metrics["recall_latency.cold.latency.p99"], 0.012)
        self.assertEqual(nightly_bench.bench_metrics("beam-smoke", reports()["beam-smoke"]), {"query_time.p99": 0.0025})
        self.assertEqual(nightly_bench.bench_metrics("beam-infra", reports()["beam-infra"]), {})


class BenchPromiseTest(unittest.TestCase):
    """Each promise check keeps on a good night's reports and breaks on the change the retired test guarded."""

    def check(self, promise: str, changed: dict) -> tuple[bool, str] | None:
        function = next(check for row, _, check in nightly_bench.BENCH_PROMISES if row == promise)
        return function(changed, RECEIPT)

    def test_each_checked_promise_keeps_on_a_good_night(self) -> None:
        checked = [(row, check) for row, _, check in nightly_bench.BENCH_PROMISES if not isinstance(check, str)]
        self.assertEqual(len(checked), 6)
        for row, check in checked:
            with self.subTest(promise=row):
                kept, detail = check(reports(), RECEIPT)
                self.assertTrue(kept, detail)

    def test_each_checked_promise_breaks_on_the_change_its_retired_test_guarded(self) -> None:
        def changed(job: str, edit) -> dict:
            night = copy.deepcopy(reports())
            edit(night[job])
            return night

        cases = {
            "P-oneiron-bench-d8df5d78": changed(
                "perf-smoke", lambda r: r["recall_latency"].update(combined=measured(percentiles(8.0)))
            ),
            "P-oneiron-bench-dd5960e1": changed("perf-full-refusal", lambda r: r.update(stderr="perf: io error\n")),
            "P-oneiron-bench-2f9c083e": changed(
                "perf-smoke", lambda r: r["precision"]["rows"][2].update(bytes_per_vector=32)
            ),
            "P-oneiron-bench-53839f47": changed(
                "perf-smoke-child-override", lambda r: r["resident_memory"].update(child_holds_open_vault=True)
            ),
            "P-oneiron-bench-ebb5f904": changed("beam-infra", lambda r: r.update(comparators=r["comparators"][:2])),
            "P-oneiron-bench-158c7d72": changed(
                "beam-contract", lambda r: r["cases"][0]["dropped"][0]["costs"]["offline"].update(elapsedUs=8400)
            ),
        }
        for promise, night in cases.items():
            with self.subTest(promise=promise):
                kept, detail = self.check(promise, night)
                self.assertFalse(kept, detail)
        self.assertIsNone(self.check("P-oneiron-bench-ebb5f904", {}), "no report: the job's own failure says why")

    def test_a_written_report_breaks_the_refusal_promise(self) -> None:
        night = reports()
        night["perf-full-refusal"]["report_written"] = True
        kept, detail = self.check("P-oneiron-bench-dd5960e1", night)
        self.assertFalse(kept)
        self.assertIn("a report was written", detail)

    def test_the_harness_owned_run_may_claim_residency_only_with_harness_owned_evidence(self) -> None:
        night = reports()
        night["perf-smoke"]["resident_memory"]["vault_residency_evidence"] = OVERRIDE_EVIDENCE
        self.assertFalse(self.check("P-oneiron-bench-53839f47", night)[0])
        night["perf-smoke"]["resident_memory"]["child_holds_open_vault"] = False
        self.assertTrue(self.check("P-oneiron-bench-53839f47", night)[0], "a cohort that never came up claims nothing")

    def test_an_override_cohort_whose_memory_was_never_measured_is_not_checked_unless_it_claims_residency(self) -> None:
        night = reports()
        for job in ("perf-smoke", "perf-smoke-child-override"):  # resident_memory.rs not_ready(): a host without /proc
            night[job]["resident_memory"].update(
                child_holds_open_vault=False, vault_residency_evidence=UNMEASURED_EVIDENCE, per_child_rss_bytes=NO_PROC
            )
        kept, detail = self.check("P-oneiron-bench-53839f47", night)
        self.assertIsNone(kept, detail)
        self.assertIn("rss not measured", detail)
        self.assertIn("not checked: per-child RSS needs /proc/<pid>/status", detail)
        night["perf-smoke-child-override"]["resident_memory"]["child_holds_open_vault"] = True
        self.assertFalse(self.check("P-oneiron-bench-53839f47", night)[0], "an unmeasured cohort still claims nothing")


BUDGET_SET = "".join(
    "\t".join(row) + "\n"
    for row in (
        ("id", "package", "kind", "binary", "match", "test", "source", "bound"),
        ("alpha-props", "oneiron", "test", "alpha", "^", "props::", "crates/core/tests/alpha.rs", "30 min"),
        ("hnsw", "oneiron-bench", "test", "cleanup_retrieval", "=", "hnsw_recall", "crates/bench/tests/c.rs", "30 min"),
        ("perf-p99", "oneiron-bench", "job", "perf-smoke", "~", ".p99", "crates/bench/src/perf/cells.rs", "report only"),
        ("beam-p99", "oneiron-bench", "job", "beam-smoke", "=", "query_time.p99", "crates/bench/src/beam/r.rs", "r"),
    )
)  # fmt: skip


class BenchSummaryTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.out = base / "out"
        self.census = base / "tree"
        (self.census / "crates/core/src").mkdir(parents=True)
        write(self.census / "crates/core/Cargo.toml", '[package]\nname = "oneiron"\n')
        write(self.census / "crates/core/src/lib.rs", "pub fn a() {}\n")
        self.baseline = write(base / "baseline.tsv", "\t".join(nightly_report.CENSUS_COLUMNS) + "\n")
        self.budget_set = write(base / "budget-set.tsv", BUDGET_SET)
        self.chosen = nightly_report.plan(METADATA, bench=True)
        write(
            self.out / "pending-door.json",
            json.dumps({"pending": 0, "expired": 0, "pending_filter": "none()", "expired_filter": "none()"}),
        )
        write(
            self.out / "junit-verdict-bench.xml",
            '<testsuites><testsuite name="oneiron-bench::cleanup_retrieval">'
            '<testcase name="hnsw_recall" time="7.5"/></testsuite>'
            '<testsuite name="oneiron-bench::bin/oneiron-bench">'
            '<testcase name="swarm::tests::a_window" time="0.1"/></testsuite></testsuites>',
        )

    def summarize(self) -> tuple[int, str]:
        write(self.out / "plan.json", json.dumps(self.chosen))
        args = Namespace(
            out=str(self.out), date="2026-11-15", head=HEAD, host="nelly", plan=str(self.out / "plan.json"),
            pending_door=str(self.out / "pending-door.json"), baseline=str(self.baseline),
            census_root=str(self.census), previous=None, history=None, budget_set=str(self.budget_set),
            budget_baseline=None, budget_samples=None,
        )  # fmt: skip
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            code = nightly_report.summary(args)
        return code, printed.getvalue().strip()

    def test_a_good_bench_night_is_green_and_times_the_jobs_in_the_budget_band(self) -> None:
        write_job_outputs(self.out)
        code, line = self.summarize()
        self.assertEqual(code, 0, line)
        self.assertIn(" passed=2 failed=0 ", line)
        self.assertIn(
            " budget_in=0 budget_out=0 budget_pending=12 budget_not_run=1 bench_jobs=6/6 bench_promises=6/6", line
        )
        row = json.loads((self.out / "bench-row.json").read_text())
        self.assertEqual(row["metrics"]["perf-smoke recall_latency.cold.latency.p99"], 0.012)
        self.assertEqual(row["metrics"]["beam-smoke query_time.p99"], 0.0025)
        self.assertEqual(row["jobs"]["perf-full-refusal"], {"rc": "1", "seconds": 3, "ran": True})
        self.assertEqual(sorted(set(row["promises"].values())), ["kept", "not-shown"])
        samples = json.loads((self.out / "budget-samples.json").read_text())["nelly"]
        self.assertEqual(samples["oneiron-bench::cleanup_retrieval hnsw_recall"][0]["seconds"], 7.5)
        self.assertEqual(samples["oneiron-bench::perf-smoke wake.spawn_to_ready.p99"][0]["seconds"], 0.03)
        text = (self.out / "summary.txt").read_text()
        self.assertIn("bench job perf-full-refusal: exit 1 (expected 1), 3 s\n", text)
        self.assertIn(
            "bench promise P-oneiron-bench-0b14d317 (ND-025 beam/model_scaffold/tests.rs"
            " measured_two_case_ingest_amortizes_measured_tokens_and_index_time): not-shown,"
            " only `beam measure` reports it, and it needs a model endpoint",
            text,
        )
        self.assertIn(
            "budget oneiron-bench::perf-smoke recall_latency.cold.latency.p99: 0.012 s, baseline pending (1/5 nights",
            text,
        )
        self.assertIn("budget not run: alpha-props (no result tonight)", text)

    def test_a_job_that_ends_otherwise_makes_the_night_red_and_its_promises_and_metrics_are_not_taken(self) -> None:
        write_job_outputs(self.out, codes={"perf-smoke": 1})
        code, line = self.summarize()
        self.assertEqual(code, 1)
        self.assertIn(" bench_jobs=5/6 bench_promises=4/4", line)
        record = json.loads((self.out / "summary.json").read_text())
        self.assertIn("the bench job perf-smoke did not run as expected (exit 1, expected 0)", record["reasons"])
        states = {p["promise"]: p["state"] for p in record["bench"]["promises"]}
        self.assertEqual(states["P-oneiron-bench-d8df5d78"], "not-checked")
        self.assertIn(
            {"id": "perf-p99", "reason": "the bench job perf-smoke did not run (exit 1, expected 0)"},
            record["budget"]["not_run"],
        )

    def test_an_unmeasured_override_cohort_leaves_the_night_green_and_its_promise_not_checked(self) -> None:
        night = reports()
        night["perf-smoke-child-override"]["resident_memory"].update(
            child_holds_open_vault=False, vault_residency_evidence=UNMEASURED_EVIDENCE, per_child_rss_bytes=NO_PROC
        )
        write_job_outputs(self.out, report_of=night)
        code, line = self.summarize()
        self.assertEqual(code, 0, line)
        self.assertIn(" bench_jobs=6/6 bench_promises=5/5", line)
        record = json.loads((self.out / "summary.json").read_text())
        states = {p["promise"]: p["state"] for p in record["bench"]["promises"]}
        self.assertEqual(states["P-oneiron-bench-53839f47"], "not-checked")
        self.assertEqual(record["reasons"], [])

    def test_a_report_missing_or_a_broken_promise_makes_the_night_red(self) -> None:
        night = reports()
        night["beam-contract"]["cases"][0]["competitors"][0]["costs"]["offline"]["elapsedUs"] = 1
        del night["beam-smoke"]
        write_job_outputs(self.out, report_of=night)
        code, line = self.summarize()
        self.assertEqual(code, 1)
        reasons = json.loads((self.out / "summary.json").read_text())["reasons"]
        self.assertIn("the bench job beam-smoke did not run as expected (no JSON report)", reasons)
        self.assertIn(
            "bench promise P-oneiron-bench-158c7d72 broken:"
            " a row whose offline elapsedUs differs from the case's amortized cost",
            reasons,
        )

    def test_bench_jobs_that_never_ran_make_the_night_red(self) -> None:
        code, line = self.summarize()
        self.assertEqual(code, 1)
        self.assertIn(" bench_jobs=0/6 bench_promises=0/0", line)
        self.assertIn(
            "the bench job perf-smoke did not run as expected (no run)",
            json.loads((self.out / "summary.json").read_text())["reasons"],
        )

    def test_a_dropped_bench_selection_says_so_for_its_budget_rows_and_runs_no_job(self) -> None:
        nightly_report.prune(self.chosen, "bench", [unit("oneiron-bench", "bin", "oneiron-bench")], METADATA)
        (self.out / "junit-verdict-bench.xml").unlink()
        code, line = self.summarize()
        self.assertEqual(code, 1, "a dropped selection is a partial build")
        self.assertIn(" build=partial ", line)
        self.assertIn(" bench_jobs=0/0 bench_promises=0/0", line)
        self.assertFalse((self.out / "bench-row.json").exists())
        not_run = json.loads((self.out / "summary.json").read_text())["budget"]["not_run"]
        self.assertIn(
            {
                "id": "hnsw",
                "reason": "the bench selection was dropped (did not compile: oneiron-bench (bin oneiron-bench))",
            },
            not_run,
        )

    def test_the_budget_filter_leaves_the_job_rows_out(self) -> None:
        rows = nightly_report.read_budget_set(self.budget_set)
        self.assertEqual(
            nightly_report.budget_filter(rows, METADATA),
            "(package(oneiron) & kind(test) & binary(=alpha) & test(/^props::/))",
        )


if __name__ == "__main__":
    unittest.main()
