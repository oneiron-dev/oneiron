"""Stored Office measurements are hash-bound; these tests never start Office."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/office"))
from compare_engines import compare
from corpus import load_cases

FIXTURES = ROOT / "crates/oneiron-docedit/tests/fixtures"


class StoredMeasurements(unittest.TestCase):
    def test_unchanged_formula_decision_is_recomputed_from_native_goldens(self):
        corpus = FIXTURES / "spreadsheet-compat"
        measurement = corpus / "measurements"
        inputs = [corpus / "excel/goldens.json", measurement / "libreoffice-25.8.2.2.json",
                  measurement / "formualizer-0.9.3-unchanged.json"]
        goldens, lo, formula = [json.loads(path.read_bytes()) for path in inputs]
        recorded = json.loads((measurement / "comparison.json").read_bytes())
        for path in inputs:
            self.assertEqual(recorded["input_sha256"][path.name], hashlib.sha256(path.read_bytes()).hexdigest())
        result = compare(load_cases(), goldens, {"libreoffice": lo, "formualizer_unchanged": formula})
        for key in ("counts", "exclusions", "mismatches"):
            self.assertEqual(result[key], recorded[key])
        self.assertEqual(recorded["at_or_above_libreoffice"],
                         result["counts"]["formualizer_unchanged"]["passed"] >= result["counts"]["libreoffice"]["passed"])

    def test_word_revision_receipts_bind_authored_inputs_and_native_semantics(self):
        fixtures = FIXTURES / "docx/word-semantics"
        expected = {
            "word-native-accept-4": ("text-tracked.docx", "Quarterly report (draft)\nRevenue grew gion.\nRisks remain in supply.\n", 3),
            "word-native-reject-4": ("text-tracked.docx", "Quarterly report\nRevenue grew in every region.\nRisks remain in supply.\n", 3),
            "word-join-accept-1": ("join-tracked.docx", "First second.\nUntouched third.\n", 2),
            "word-join-reject-1": ("join-tracked.docx", "First \nsecond.\nUntouched third.\n", 3),
        }
        for name, (source, text, paragraphs) in expected.items():
            with self.subTest(name=name):
                receipt = json.loads((fixtures / f"{name}.json").read_bytes())
                self.assertEqual(receipt["input_sha256"], hashlib.sha256((fixtures / source).read_bytes()).hexdigest())
                self.assertEqual(receipt["script_sha256"], hashlib.sha256((ROOT / "scripts/office/word_revision_oracle.applescript").read_bytes()).hexdigest())
                self.assertEqual(receipt["status"], "completed")
                self.assertEqual(receipt["app_version"], "16.112.4")
                self.assertEqual(receipt["after_revisions"], 0)
                self.assertEqual(receipt["paragraphs"], paragraphs)
                self.assertEqual(receipt["resolved_text"], text)
                self.assertEqual(receipt["initial_documents"], receipt["final_documents"])
                self.assertFalse(receipt["lock_retained"])


if __name__ == "__main__":
    unittest.main()
