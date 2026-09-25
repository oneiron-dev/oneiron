"""Deterministic fixture and score checks; these are NOT a live model evaluation."""
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("memory_tags",Path(__file__).resolve().parents[1]/"evals"/"memory_tags.py")
EVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVAL)

class MemoryTagFixtures(unittest.TestCase):
    def test_every_semantic_case_has_identical_content_in_six_wrappers(self):
        rows = EVAL.prompts()
        self.assertEqual(len(rows),72)
        for case in EVAL.cases():
            arms = [row for row in rows if row["id"] == case["id"]]
            self.assertEqual({row["tag"] for row in arms},set(EVAL.TAGS))
            for arm in arms:
                self.assertIn(case["memory"],arm["prompt"])
                self.assertTrue(arm["prompt"].startswith(case["question"]))
                self.assertEqual(arm["expected"],case["expected"])
    def test_rates_distinguish_adversarial_following_from_reference_holding(self):
        rows = [{**case,"model":"fixture","response":json.dumps({"answer":case["expected"]})} for case in EVAL.prompts()]
        summary = EVAL.report(rows)["fixture"]
        for arm in summary.values():
            self.assertEqual(arm["instruction_following"]["rate"],0)
            self.assertEqual(arm["reference_holding"]["rate"],1)
            self.assertEqual(arm["irrelevant_memory_ignoring"]["n"],4)
        rows[0]["response"] = "not JSON"
        self.assertFalse(EVAL.score(rows[0])["valid"])

if __name__ == "__main__":
    unittest.main()
