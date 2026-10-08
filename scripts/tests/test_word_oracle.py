"""Offline input-safety checks and stored Word observations; these tests never launch an Office application."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("word_oracle", ROOT / "scripts/office/run_word_oracle.py")
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)
SEMANTICS = ROOT / "crates/oneiron-docedit/tests/fixtures/docx/word-semantics"

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

class StoredWordRevisionObservations(unittest.TestCase):
    def test_word_revision_receipts_bind_authored_inputs_and_native_semantics(self):
        expected = {
            "word-native-accept-4": ("text-tracked.docx", "Quarterly report (draft)\nRevenue grew gion.\nRisks remain in supply.\n", 3),
            "word-native-reject-4": ("text-tracked.docx", "Quarterly report\nRevenue grew in every region.\nRisks remain in supply.\n", 3),
            "word-join-accept-1": ("join-tracked.docx", "First second.\nUntouched third.\n", 2),
            "word-join-reject-1": ("join-tracked.docx", "First \nsecond.\nUntouched third.\n", 3),
        }
        for name, (source, text, paragraphs) in expected.items():
            with self.subTest(name=name):
                receipt = json.loads((SEMANTICS / f"{name}.json").read_bytes())
                self.assertEqual(receipt["input_sha256"], hashlib.sha256((SEMANTICS / source).read_bytes()).hexdigest())
                self.assertEqual(receipt["script_sha256"], hashlib.sha256((SEMANTICS / "observed-script.txt").read_bytes()).hexdigest())
                self.assertEqual(receipt["status"], "completed")
                self.assertEqual(receipt["app_version"], "16.112.4")
                self.assertEqual(receipt["after_revisions"], 0)
                self.assertEqual(receipt["paragraphs"], paragraphs)
                self.assertEqual(receipt["resolved_text"], text)
                self.assertEqual(receipt["initial_documents"], receipt["final_documents"])
                self.assertFalse(receipt["lock_retained"])


if __name__ == "__main__":
    unittest.main()
