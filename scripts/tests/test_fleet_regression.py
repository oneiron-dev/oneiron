"""Contract-only receipt fixtures, not measured benchmark evidence."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "fleet-regression.py"
SPEC = importlib.util.spec_from_file_location("fleet_regression", PATH)
fleet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fleet)


def fixture():
    plan = dict(profile="fleet20k-v1", host_label="test-only", storage_label="test-only",
                scratch="/test-only", agents=20000, listeners=4, concurrency=64, runtime_threads=4,
                rounds=1, hold_ms=1000, timeout_secs=30, map_size=2**30,
                ppr_nodes=128, ppr_samples=100)
    host = dict(os="linux", arch="x86_64", hostname="test-only", kernel="test-only",
                cpu="test-only", logical_cpus=4, compiled_profile="release", compiled_opt_level="3",
                debug_assertions=False, fd_limit="65536")
    metrics = {}
    for name in ("write_0", "recall_0", "socket_open", "socket_probe_before", "socket_probe_after",
                 "ppr_full", "ppr_resume", "ppr_prepare"):
        count = 100 if name.startswith("ppr_") else 20000
        metrics[name] = dict(completed=count, elapsed_seconds=1.0,
                             throughput_per_second=float(count), p99_ms=1.0, samples_ms=[1.0] * count)
    return dict(schema="oneiron-fleet-v1", status="complete", plan=plan, host=host,
                revision="a" * 40, dirty=True, binary_blake3="b" * 64, started_unix_ms=1,
                metrics=metrics, held_sockets=20000, verified_writes=20000, verified_recalls=20000,
                hold_observed_ms=1000.0, optimization=dict(route="full-depth10-vs-depth5-resume-to10-v1",
                equivalent_pairs=100, result_blake3="c" * 64, incremental_speedup=1.0,
                preparation_seconds=1.0, preparation_included_speedup=.5))


class FleetRegressionTests(unittest.TestCase):
    def setUp(self):
        self.receipt = fixture()
        self.floor = fleet.make_floor(self.receipt, .15, .20)

    def test_floor_keeps_summary_and_full_receipt_digest_without_changing_receipt(self):
        original = fixture()
        expected = copy.deepcopy(original)
        for metric in expected["metrics"].values():
            del metric["samples_ms"]
        self.assertEqual(self.floor["baseline_receipt"], expected)
        self.assertEqual(fleet.validate_floor(self.floor), expected)
        self.assertEqual(self.floor["baseline_sha256"], fleet.fingerprint(original))
        self.assertNotEqual(self.floor["baseline_sha256"], fleet.fingerprint(expected))
        self.assertEqual(self.receipt, original)

    def test_floor_refuses_samples_in_any_metric(self):
        for name, metric in self.receipt["metrics"].items():
            floor = copy.deepcopy(self.floor)
            floor["baseline_receipt"]["metrics"][name]["samples_ms"] = metric["samples_ms"]
            with self.subTest(metric=name), self.assertRaises(ValueError):
                fleet.validate_floor(floor)

    def test_full_samples_are_required_to_create_floor_and_compare_candidate(self):
        for name in self.receipt["metrics"]:
            for samples in (None, [], [float("nan")], [float("inf")]):
                receipt = copy.deepcopy(self.receipt)
                if samples is None:
                    del receipt["metrics"][name]["samples_ms"]
                else:
                    receipt["metrics"][name]["samples_ms"] = samples * receipt["metrics"][name]["completed"]
                with self.subTest(metric=name, samples=samples):
                    with self.assertRaises(ValueError):
                        fleet.make_floor(receipt, .15, .20)
                    with self.assertRaises(ValueError):
                        fleet.compare(self.floor, receipt)

    def test_floor_refuses_invalid_digest(self):
        for digest in (None, 1, "", "a" * 63, "g" * 64, "A" * 64):
            floor = copy.deepcopy(self.floor)
            floor["baseline_sha256"] = digest
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                fleet.validate_floor(floor)

    def test_missing_and_unknown_keys_are_refused(self):
        paths = ((), ("plan",), ("host",), ("metrics",), ("metrics", "write_0"), ("optimization",))
        for trimmed in (False, True):
            for path in paths:
                receipt = self.floor["baseline_receipt"] if trimmed else self.receipt
                node = receipt
                for key in path:
                    node = node[key]
                for omitted in (*node, None):
                    mutated = copy.deepcopy(receipt)
                    target = mutated
                    for key in path:
                        target = target[key]
                    if omitted is None:
                        target["unexpected"] = 1
                    else:
                        del target[omitted]
                    with self.subTest(trimmed=trimmed, path=path, omitted=omitted):
                        with self.assertRaises(ValueError):
                            if trimmed:
                                fleet.validate_floor({**self.floor, "baseline_receipt": mutated})
                            else:
                                fleet.compare(self.floor, mutated)
        for omitted in (*self.floor, None):
            floor = copy.deepcopy(self.floor)
            if omitted is None:
                floor["unexpected"] = 1
            else:
                del floor[omitted]
            with self.subTest(floor_key=omitted), self.assertRaises(ValueError):
                fleet.validate_floor(floor)

    def test_floor_refuses_invalid_summary_measurements(self):
        mutations = [
            lambda r: r["metrics"]["write_0"].update(completed=19999),
            lambda r: r["metrics"]["write_0"].update(throughput_per_second=1),
            lambda r: r["optimization"].update(incremental_speedup=2),
            lambda r: r["optimization"].update(equivalent_pairs=0),
            lambda r: r.update(verified_recalls=19999),
        ]
        for mutate in mutations:
            floor = copy.deepcopy(self.floor)
            mutate(floor["baseline_receipt"])
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                fleet.validate_floor(floor)
        for key in ("elapsed_seconds", "throughput_per_second", "p99_ms"):
            for value in (0, -1, True, float("nan"), float("inf"), float("-inf")):
                floor = copy.deepcopy(self.floor)
                floor["baseline_receipt"]["metrics"]["write_0"][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    fleet.validate_floor(floor)

    def test_source_archive_has_explicit_unknown_checkout_but_real_artifact_id(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["revision"] = receipt["dirty"] = None
        floor = fleet.make_floor(receipt, .15, .20)
        self.assertEqual(fleet.compare(floor, receipt)["status"], "pass")
        receipt["binary_blake3"] = ""
        with self.assertRaises(ValueError):
            fleet.validate(receipt)

    def test_same_receipt_passes_positive_measured_thresholds(self):
        result = fleet.compare(self.floor, self.receipt)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(all(row["minimum_throughput_per_second"] > 0 for row in result["metrics"]))

    def test_throughput_regression_is_nonzero_exit(self):
        candidate = copy.deepcopy(self.receipt)
        candidate["metrics"]["write_0"]["elapsed_seconds"] = 2.0
        candidate["metrics"]["write_0"]["throughput_per_second"] = 10000.0
        self.assertEqual(fleet.compare(self.floor, candidate)["status"], "regression")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fleet.write_new(base / "floor.json", self.floor)
            fleet.write_new(base / "candidate.json", candidate)
            result = fleet.main(["compare", "--floor", str(base / "floor.json"),
                                 "--candidate", str(base / "candidate.json"), "--out", str(base / "comparison.json")])
            self.assertEqual(result, 1)

    def test_p99_regression_is_not_hidden_by_throughput(self):
        candidate = copy.deepcopy(self.receipt)
        metric = candidate["metrics"]["recall_0"]
        metric["samples_ms"] = [2.0] * 20000
        metric["p99_ms"] = 2.0
        result = fleet.compare(self.floor, candidate)
        self.assertEqual(result["status"], "regression")
        self.assertFalse(next(row for row in result["metrics"] if row["metric"] == "recall_0")["passed"])

    def test_refuses_mismatches_failed_runs_fixtures_missing_verbs_and_forged_stats(self):
        mutations = [
            lambda r: r["plan"].update(profile="fixture-v1"),
            lambda r: r["plan"].update(concurrency=32),
            lambda r: r["host"].update(hostname="different-host"),
            lambda r: r["host"].update(compiled_opt_level="0"),
            lambda r: r.update(status="failed"),
            lambda r: r.update(held_sockets=19999),
            lambda r: r.update(verified_writes=19999),
            lambda r: r["metrics"].pop("socket_probe_after"),
            lambda r: r["metrics"]["write_0"].update(p99_ms=.1),
            lambda r: r["metrics"]["write_0"].update(throughput_per_second=0),
            lambda r: r["metrics"]["write_0"].update(samples_ms=[]),
            lambda r: r["optimization"].update(equivalent_pairs=0),
            lambda r: r["optimization"].update(result_blake3="d" * 64),
        ]
        for mutate in mutations:
            candidate = copy.deepcopy(self.receipt)
            mutate(candidate)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                fleet.compare(self.floor, candidate)

    def test_floor_cannot_disable_thresholds_or_omit_measurements(self):
        for key in ("throughput_loss", "p99_increase"):
            for value in (0, 1, float("nan"), float("inf")):
                with self.subTest(key=key, value=value):
                    tolerances = {"throughput_loss": .15, "p99_increase": .20, key: value}
                    with self.assertRaises(ValueError):
                        fleet.make_floor(self.receipt, **tolerances)
                    with self.assertRaises(ValueError):
                        fleet.validate_floor({**self.floor, **tolerances})
        floor = copy.deepcopy(self.floor)
        floor["baseline_receipt"]["metrics"]["write_0"]["p99_ms"] = 0
        with self.assertRaises(ValueError):
            fleet.compare(floor, self.receipt)

    def test_ci_refuses_absent_floor_before_starting_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            result = fleet.main(["ci", "--floor", str(base / "absent.json"),
                                 "--bench", "/binary-must-not-be-started", "--plan", str(base / "plan.json"),
                                 "--candidate", str(base / "run.json"), "--out", str(base / "comparison.json")])
            self.assertEqual(result, 2)
            self.assertFalse((base / "run.json").exists())


if __name__ == "__main__":
    unittest.main()
