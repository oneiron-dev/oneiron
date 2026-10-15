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


if __name__ == "__main__":
    unittest.main()
