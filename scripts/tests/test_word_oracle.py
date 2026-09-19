"""Offline input-safety checks; these tests never launch an Office application."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("word_oracle", ROOT / "scripts/office/run_word_oracle.py")
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)

class OfficePreflightTests(unittest.TestCase):
    def package(self, directory, extra=None):
        path = Path(directory) / "fixture.docx"
        parts = {"[Content_Types].xml": b"<Types/>", "_rels/.rels": b"<Relationships/>",
                 "word/document.xml": b"<document><body/></document>"}
        parts.update(extra or {})
        with zipfile.ZipFile(path, "w") as archive:
            for name, payload in parts.items():
                archive.writestr(name, payload)
        return path

    def test_verified_input_hash_is_the_bytes_sent_to_word(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.package(directory)
            self.assertEqual(ORACLE.preflight(path), hashlib.sha256(path.read_bytes()).hexdigest())

    def test_missing_broken_external_and_macro_inputs_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                ORACLE.preflight(Path(directory) / "missing.docx")
            path = self.package(directory)
            path.write_bytes(b"not a ZIP")
            with self.assertRaises(zipfile.BadZipFile):
                ORACLE.preflight(path)
            for extra in [{"word/_rels/document.xml.rels": b'<Relationships><Relationship Target="https://example.invalid" TargetMode="External"/></Relationships>'},
                          {"word/vbaProject.bin": b"macro"}]:
                with self.subTest(extra=tuple(extra)):
                    path = self.package(directory, extra)
                    with self.assertRaises(ValueError):
                        ORACLE.preflight(path)

if __name__ == "__main__":
    unittest.main()
