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
