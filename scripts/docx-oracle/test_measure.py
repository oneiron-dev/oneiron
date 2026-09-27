import importlib.util
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("measure", Path(__file__).with_name("measure.py"))
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)

join_spec = importlib.util.spec_from_file_location("generate_join", Path(__file__).with_name("generate_join.py"))
join = importlib.util.module_from_spec(join_spec)
join_spec.loader.exec_module(join)

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
    def test_word_run_split_preserves_logical_text_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            digests = []
            for name, runs in (
                ("whole", "<w:r><w:t>sovereignty.</w:t></w:r>"),
                ("split", "<w:r><w:t>sovereig</w:t></w:r><w:r><w:t>nty.</w:t></w:r>"),
            ):
                path = Path(temporary) / f"{name}.docx"
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("[Content_Types].xml", "<Types/>")
                    archive.writestr("word/document.xml", f'<w:document xmlns:w="{measure.WORD}"><w:body><w:p>{runs}</w:p></w:body></w:document>')
                digests.append(measure.summarize(path)["text_sha256"])
            self.assertEqual(*digests)

    def test_join_cases_match_oracle_input_xml(self):
        known = {
            "simple": (2, "b8e94fe420b09528fbff450523476b9823be98f98a378e994ed01b03f4fa47be"),
            "table": (3, "844a50103f0278570d6ccd800315d1d504db47b976a09e1b589ddadd5887f9d5"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            for name, (paragraphs, xml_hash) in known.items():
                path = Path(temporary) / f"{name}.docx"
                join.generate(name, path)
                result = measure.summarize(path)
                self.assertEqual(result["paragraphs"], paragraphs)
                self.assertEqual(result["document_xml_sha256"], xml_hash)

    def test_word_requires_real_mac(self):
        from unittest.mock import patch
        with patch.object(measure.platform, "system", return_value="Linux"):
            with self.assertRaisesRegex(RuntimeError, "Word oracle must run"):
                measure.word_receipt(Path("a"), Path("b"), Path("receipt.json"), "no")

    def test_mac_requires_a_separate_saved_copy(self):
        from unittest.mock import patch
        with patch.object(measure.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(ValueError, "separate staged copy"):
                measure.word_receipt(Path("a"), Path("b"), Path("receipt.json"), "no")

    def test_no_libreoffice_never_scores(self):
        with tempfile.TemporaryDirectory() as temporary:
            from unittest.mock import patch
            with patch.object(measure.shutil, "which", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "not installed"):
                    measure.lo_roundtrip(Path(temporary), Path(temporary) / "out")
if __name__ == "__main__": unittest.main()
