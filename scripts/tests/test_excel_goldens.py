"""Offline stored-value proof over the pinned native-Excel corpus."""
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/office"))
from run_excel_oracle import cached_cells, result_value, validate_setup

CORPUS = ROOT / "crates/oneiron-docedit/tests/fixtures/spreadsheet-compat"


class ExcelGoldenTests(unittest.TestCase):
    def test_native_cached_values_match_recorded_excel_and_case_shape(self):
        raw = (CORPUS / "cases.json").read_bytes()
        cases = json.loads(raw)
        goldens = json.loads((CORPUS / "excel/goldens.json").read_bytes())
        archive = (CORPUS / "excel/cached-workbooks.zip").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), goldens["input_sha256"])
        self.assertEqual(hashlib.sha256(archive).hexdigest(), goldens["archive_sha256"])
        self.assertEqual(set(goldens["cases"]), {c["id"] for c in cases})
        with zipfile.ZipFile(io.BytesIO(archive)) as packages:
            for case in cases:
                with self.subTest(case=case["id"]):
                    row = goldens["cases"][case["id"]]
                    data = packages.read(row["file"])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), row["fixture_sha256"])
                    cells = cached_cells(io.BytesIO(data))
                    validate_setup(case, cells)
                    self.assertEqual(cells.get("Z1"), 3333)
                    self.assertEqual(result_value(case, cells), row["value"])
                    self.assertIn(row["status"], ("ok", "formula-rejected"))
                    if row["status"] == "formula-rejected":
                        self.assertIsNone(row["value"])
                    else:
                        self.assertIsNotNone(row["value"])
                    with zipfile.ZipFile(io.BytesIO(data)) as workbook:
                        self.assertNotIn(b"/Users/", workbook.read("xl/workbook.xml"))


if __name__ == "__main__":
    unittest.main()
