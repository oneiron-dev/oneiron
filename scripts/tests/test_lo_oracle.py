"""LO gets no Excel answer caches and keeps the native package's unknown XML."""
import importlib.util
import io
from pathlib import Path
import sys
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "office"))
from run_lo_oracle import without_cached_results


class LibreOfficeInputTests(unittest.TestCase):
    def test_cache_removal_preserves_namespaces_unknown_xml_and_inputs(self):
        original = b'''<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:u="urn:future" u:kept="true"><sheetData><row r="1"><c r="A1" t="n"><v>3</v></c><c r="F1" t="n"><f>ABS(A1)</f><v>3</v><u:v>untouched</u:v></c><c r="Z1"><f>1111+2222</f><v>3333</v></c></row></sheetData><u:unknown/></worksheet>'''
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("xl/worksheets/sheet1.xml", original)
            archive.writestr("customXml/item.xml", b"unknown bytes")
        output = without_cached_results(data.getvalue(), {"formula": "=ABS(A1)"})
        with zipfile.ZipFile(io.BytesIO(output)) as archive:
            changed = archive.read("xl/worksheets/sheet1.xml")
            self.assertEqual(changed, original.replace(b'<c r="F1" t="n">', b'<c r="F1">').replace(b'<f>ABS(A1)</f><v>3</v>', b'<f>ABS(A1)</f>').replace(b'<f>1111+2222</f><v>3333</v>', b'<f>1111+2222</f>'))
            self.assertEqual(archive.read("customXml/item.xml"), b"unknown bytes")


if __name__ == "__main__":
    unittest.main()
