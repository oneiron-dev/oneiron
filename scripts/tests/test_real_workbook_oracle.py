"""Input custody for the real-workbook Excel oracle; no Office calls."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/office"))
from run_real_excel_oracle import preflight
from run_real_lo_oracle import clear_formula_caches


class RealWorkbookPreflight(unittest.TestCase):
    def test_valid_package_hash_and_active_content_refusal(self):
        parts = {
            "[Content_Types].xml": b"<Types/>",
            "_rels/.rels": b"<Relationships/>",
            "xl/workbook.xml": b"<workbook/>",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.xlsx"
            with zipfile.ZipFile(path, "w") as archive:
                for name, value in parts.items():
                    archive.writestr(name, value)
            self.assertEqual(preflight(path), hashlib.sha256(path.read_bytes()).hexdigest())
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr("xl/vbaProject.bin", b"not executable")
            with self.assertRaises(ValueError):
                preflight(path)

    def test_libreoffice_input_drops_only_formula_caches(self):
        import xml.etree.ElementTree as ET
        xml = b'''<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1"><v>7</v></c><c r='B1' t='str'><f>A1+1</f><v>stale</v></c></row></sheetData><!--opaque extension--></worksheet>'''
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "input.xlsx", Path(directory) / "output.xlsx"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("xl/worksheets/sheet1.xml", xml)
                archive.writestr("opaque.bin", b"preserve-me")
            clear_formula_caches(source, output)
            with zipfile.ZipFile(output) as archive:
                result = archive.read("xl/worksheets/sheet1.xml")
                self.assertEqual(archive.read("opaque.bin"), b"preserve-me")
            self.assertIn(b"<!--opaque extension-->", result)
            tree = ET.fromstring(result)
            ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            self.assertEqual(tree.find('.//s:c[@r="A1"]/s:v', ns).text, "7")
            formula = tree.find('.//s:c[@r="B1"]', ns)
            self.assertEqual(formula.find("s:f", ns).text, "A1+1")
            self.assertIsNone(formula.find("s:v", ns))
            self.assertIsNone(formula.get("t"))

    def test_fresh_comparison_rejects_partial_or_changed_truth_and_counts_refusals(self):
        import json
        from compare_real_workbooks import compare, digest
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            excel, engine = base / "excel", base / "engine"
            excel.mkdir(); engine.mkdir()
            key = "a" * 64
            manifest = base / "manifest.jsonl"
            manifest.write_text(json.dumps(dict(sha256=key, path="source.xlsx")) + "\n")
            for folder in [excel, engine]:
                (folder / "identity.json").write_text(json.dumps(dict(manifest_sha256=digest(manifest))))
                (folder / "rows.jsonl").write_text("")
            (excel / "custody.json").write_text(json.dumps(dict(lock_retained=False)))
            with self.assertRaisesRegex(ValueError, "incomplete"):
                compare(manifest, excel, engine)
            truth_file = excel / (key + ".xlsx")
            with zipfile.ZipFile(truth_file, "w") as archive:
                archive.writestr("xl/workbook.xml", '<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" r:id="rId1"/></sheets></workbook>')
                archive.writestr("xl/_rels/workbook.xml.rels", '<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>')
                archive.writestr("xl/worksheets/sheet1.xml", '<worksheet><sheetData><row><c r="A1"><f>1+1</f><v>2</v></c></row></sheetData></worksheet>')
            row = dict(sha256=key, path="source.xlsx", status="completed", calculation="calculate full rebuild", final_workbooks=0, output_sha256=digest(truth_file))
            (excel / "rows.jsonl").write_text(json.dumps(row) + "\n")
            (engine / "rows.jsonl").write_text(json.dumps(dict(sha256=key, path="source.xlsx", recalc=dict(ok=False))) + "\n")
            summary, rows = compare(manifest, excel, engine)
            self.assertEqual(summary["formula_cells"], 1)
            self.assertEqual(summary["mismatches"], 1)
            self.assertEqual(summary["matching_workbooks"], 0)
            self.assertEqual(rows[0]["metrics"]["missing"], 1)
            truth_file.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "hash changed"):
                compare(manifest, excel, engine)

    def test_missing_invalid_and_entity_declared_input_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.xlsx"
            with self.assertRaises(ValueError):
                preflight(path)
            path.write_bytes(b"not a ZIP")
            with self.assertRaises(zipfile.BadZipFile):
                preflight(path)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("[Content_Types].xml", b"<Types/>")
                archive.writestr("_rels/.rels", b"<Relationships/>")
                archive.writestr("xl/workbook.xml", b'<!DOCTYPE workbook [<!ENTITY x "expanded">]><workbook>&x;</workbook>')
            with self.assertRaises(ValueError):
                preflight(path)


if __name__ == "__main__":
    unittest.main()
