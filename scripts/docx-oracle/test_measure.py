import importlib.util
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("measure", Path(__file__).with_name("measure.py"))
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)

class MeasureTests(unittest.TestCase):
    def test_summarize_checks_revision_and_protection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "case.docx"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("[Content_Types].xml", "<Types/>")
                archive.writestr("word/document.xml", '<w:document xmlns:w="%s"><w:body><w:p><w:ins/><w:del/><w:commentRangeStart/><w:commentRangeEnd/><w:r><w:t>A</w:t></w:r></w:p></w:body></w:document>' % measure.WORD)
                archive.writestr("word/settings.xml", '<w:settings xmlns:w="%s"><w:documentProtection w:edit="trackedChanges"/></w:settings>' % measure.WORD)
            result = measure.summarize(path)
            self.assertEqual(result["revisions"], {"ins": 1, "del": 1})
            self.assertEqual(result["comments"], {"commentRangeStart": 1, "commentRangeEnd": 1})
            self.assertEqual(result["protection"], "trackedChanges")
    def test_word_requires_real_mac(self):
        with self.assertRaises(RuntimeError):
            measure.word_receipt(Path("a"), Path("b"), Path("receipt.json"), "no")
    def test_no_libreoffice_never_scores(self):
        with tempfile.TemporaryDirectory() as temporary:
            from unittest.mock import patch
            with patch.object(measure.shutil, "which", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "not installed"):
                    measure.lo_roundtrip(Path(temporary), Path(temporary) / "out")
if __name__ == "__main__": unittest.main()
