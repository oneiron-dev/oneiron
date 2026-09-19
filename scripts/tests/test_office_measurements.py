"""Stored Office measurements are hash-bound; these tests never start Office."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

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

    def test_native_xlookup_prefix_and_value_survive_excel(self):
        fixture = FIXTURES / "spreadsheet-compat/measurements/native-xlookup"
        receipt = json.loads((fixture / "receipt.json").read_bytes())
        self.assertEqual(receipt["status"], "completed")
        self.assertFalse(receipt["lock_retained"])
        self.assertEqual(receipt["observed"], receipt["expected"])
        self.assertEqual(receipt["script_sha256"], hashlib.sha256((fixture / "observed-script.applescript").read_bytes()).hexdigest())
        ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        cells = [ET.parse(fixture / name).find('.//s:c[@r="F1"]', ns)
                 for name in ("input-sheet.xml", "native-sheet.xml", "excel-sheet.xml")]
        self.assertEqual(cells[0].find("s:v", ns).text, "0")
        self.assertTrue(cells[0].find("s:f", ns).text.startswith("XLOOKUP("))
        for cell in cells[1:]:
            self.assertTrue(cell.find("s:f", ns).text.startswith("_xlfn.XLOOKUP("))
            self.assertEqual(float(cell.find("s:v", ns).text), receipt["expected"])
        self.assertEqual(receipt["input_preparation"]["engine"]["engine"]["engine"], "oneiron-xlsx-formula")

    def test_docx_preservation_rate_comes_from_same_input_word_receipts(self):
        fixture = FIXTURES / "docx-corpus"
        native = fixture / "native-report.json"
        report = json.loads((fixture / "word-libreoffice-comparison.json").read_bytes())
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["native_report_sha256"], hashlib.sha256(native.read_bytes()).hexdigest())
        counts = {"scored": 0, "native_pass": 0, "libreoffice_pass": 0}
        for case in report["cases"].values():
            if not case["scored"]:
                self.assertEqual(case["status"], "native-refusal")
                continue
            native_word = case["word"]["native"]
            lo_word = case["word"]["libreoffice"]
            self.assertEqual(case["input_sha256"], native_word["input_sha256"])
            for observed in [native_word, lo_word]:
                self.assertEqual(observed["status"], "completed")
                self.assertEqual(observed["after_revisions"], 0)
                self.assertEqual(observed["initial_documents"], observed["final_documents"])
                self.assertFalse(observed["lock_retained"])
            lo_pass = all(native_word[key] == lo_word[key] for key in ["resolved_text", "paragraphs", "before_revisions"])
            self.assertEqual(case["libreoffice_pass"], lo_pass)
            counts["scored"] += 1
            counts["native_pass"] += 1
            counts["libreoffice_pass"] += int(lo_pass)
        self.assertEqual(report["counts"], counts)

    def test_pptarena_identity_receipt_covers_the_pinned_manifest(self):
        fixture = FIXTURES / "pptarena"
        manifest_bytes = (fixture / "manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        receipt = json.loads((fixture / "receipt.json").read_bytes())
        self.assertEqual(receipt["manifest_sha256"], hashlib.sha256(manifest_bytes).hexdigest())
        expected = {Path(row["path"]).name: row for row in manifest["files"]}
        rows = receipt["native_identity_results"]
        self.assertEqual(len(rows), len(expected))
        self.assertEqual({row["file"] for row in rows}, set(expected))
        for row in rows:
            with self.subTest(file=row["file"]):
                self.assertEqual(row["bytes"], expected[row["file"]]["size"])
                self.assertEqual(len(bytes.fromhex(row["input_blake3"])), 32)
                self.assertTrue(row["no_op_archive_exact"])
                self.assertTrue(row["edit_unknown_xml_in_place"])
                self.assertTrue(row["untouched_part_payloads_exact"])

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
                self.assertEqual(receipt["script_sha256"], hashlib.sha256((fixtures / "observed-script.txt").read_bytes()).hexdigest())
                self.assertEqual(receipt["status"], "completed")
                self.assertEqual(receipt["app_version"], "16.112.4")
                self.assertEqual(receipt["after_revisions"], 0)
                self.assertEqual(receipt["paragraphs"], paragraphs)
                self.assertEqual(receipt["resolved_text"], text)
                self.assertEqual(receipt["initial_documents"], receipt["final_documents"])
                self.assertFalse(receipt["lock_retained"])


if __name__ == "__main__":
    unittest.main()
