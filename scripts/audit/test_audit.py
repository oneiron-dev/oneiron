import json
import pathlib
import tempfile
import unittest
from coverage import merge
from mutation import enforce

class AuditTests(unittest.TestCase):
    def test_surviving_mutant_fails_gate(self):
        baseline = {"minimum_score": 0.8, "minimum_tested": 1}
        caught = {"outcomes": [{"scenario": {"Mutant": {}}, "summary": "CaughtMutant"}]}
        self.assertEqual(enforce(caught, baseline)["score"], 1.0)
        caught["outcomes"][0]["summary"] = "MissedMutant"
        with self.assertRaises(ValueError):
            enforce(caught, baseline)
        with self.assertRaises(ValueError):
            enforce({"outcomes": []}, baseline)
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
