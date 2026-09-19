import json
import pathlib
import tempfile
import unittest
from coverage import merge
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
