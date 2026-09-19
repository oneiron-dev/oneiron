import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from coverage import collect, coverage_tmp, merge
from mutation import enforce

class AuditTests(unittest.TestCase):
    def audit(self):
        baseline = {"minimum_score": 0.8, "minimum_tested": 1, "runner": "cargo-mutants 27.1.0"}
        report = {"cargo_mutants_version": "27.1.0", "end_time": "2026-09-19T00:00:00Z",
                  "total_mutants": 1, "outcomes": [
                      {"scenario": "Baseline", "summary": "Success"},
                      {"scenario": {"Mutant": {}}, "summary": "CaughtMutant"}]}
        return report, baseline

    def test_surviving_mutant_fails_gate(self):
        caught, baseline = self.audit()
        self.assertEqual(enforce(caught, baseline)["score"], 1.0)
        caught["outcomes"][1]["summary"] = "MissedMutant"
        with self.assertRaises(ValueError):
            enforce(caught, baseline)

    def test_interrupted_or_partial_audit_never_passes(self):
        for field, value in [("end_time", None), ("total_mutants", 2),
                             ("outcomes", []), ("cargo_mutants_version", "0.0")]:
            report, baseline = self.audit()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                enforce(report, baseline)
        for index, summary in [(0, "Failure"), (1, "Timeout")]:
            report, baseline = self.audit()
            report["outcomes"][index]["summary"] = summary
            with self.subTest(summary=summary), self.assertRaises(ValueError):
                enforce(report, baseline)

    def test_lanes_count_overlapping_lines_once(self):
        with tempfile.TemporaryDirectory() as root:
            files = []
            for index, regions in enumerate(["DA:1,3\nDA:2,0", "DA:1,5\nDA:2,2", "DA:3,1"]):
                path = pathlib.Path(root) / str(index)
                path.write_text("SF:/source/lib.rs\n" + regions + "\nend_of_record\n")
                files.append(path)
            report = merge(files)
            self.assertEqual(report.count("DA:1,"), 1)
            self.assertIn("LF:3\nLH:3", report)
            self.assertIn("DA:1,5", report)

    def test_coverage_temporary_directory_is_real_private_and_removed(self):
        with tempfile.TemporaryDirectory() as root:
            real = pathlib.Path(root) / "real"
            real.mkdir()
            alias = pathlib.Path(root) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with coverage_tmp(alias) as temporary:
                self.assertEqual(temporary.parent, real.resolve())
                self.assertEqual(temporary.stat().st_mode & 0o777, 0o700)
            self.assertFalse(temporary.exists())

    def test_deep_reports_do_not_lengthen_test_socket_paths(self):
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root)
            output = root / ("deep-" * 20) / "reports"
            observed = []
            def run(command, *, cwd, env, check):
                temporary = pathlib.Path(env["TMPDIR"])
                self.assertEqual(temporary.parent, root.resolve())
                self.assertEqual(temporary.stat().st_mode & 0o777, 0o700)
                observed.append(temporary)
                if "--output-path" in command:
                    pathlib.Path(command[-1]).write_text("SF:/source/lib.rs\nDA:1,1\nend_of_record\n")
            with patch("coverage.subprocess.check_output", return_value="cargo-llvm-cov 0.8.7"), patch("coverage.subprocess.run", side_effect=run):
                reports = collect(output, tmp_dir=root)
            self.assertEqual(len(reports), 3)
            self.assertTrue(all(path.is_file() for path in reports))
            self.assertTrue(observed)
            self.assertTrue(all(not path.exists() for path in observed))
