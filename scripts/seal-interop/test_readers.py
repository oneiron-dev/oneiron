"""Opt-in pinned-reader tests using a retained two-revision PDF fixture."""
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
BIN = Path(os.environ.get("SEAL_INTEROP_HOME", "/mnt/wd16/w8-build/seal-interop")) / "bin"


@unittest.skipUnless(os.environ.get("SEAL_INTEROP_INTEGRATION") == "1",
                     "set SEAL_INTEROP_INTEGRATION=1 after installing pinned readers")
class MultiSignatureReaderTests(unittest.TestCase):
    def reader(self, name, fixture):
        path = BIN / f"seal-{name}"
        self.assertTrue(path.is_file(), f"install pinned {name} reader first: {path}")
        proc = subprocess.run([str(path), str(FIXTURES / fixture)],
                              capture_output=True, text=True, check=False)
        report = json.loads(proc.stdout)
        self.assertNotEqual(report["status"], "unavailable", report)
        return proc.returncode, report

    def test_pyhanko_checks_both_signatures_and_refuses_corrupt_latest(self):
        code, report = self.reader("pyhanko", "multi-signed.pdf")
        self.assertEqual(code, 0, report)
        self.assertEqual(report["signatures_checked"], 2)
        self.assertEqual([item["valid"] for item in report["signature_results"]], [True, True])
        code, report = self.reader("pyhanko", "second-signature-corrupt.pdf")
        self.assertEqual(code, 1, report)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["signatures_checked"], 2)
        self.assertEqual([item["valid"] for item in report["signature_results"]], [True, False])
        self.assertIn("trust override", report["detail"])

    def test_earlier_signed_revision_is_accepted_by_pdfbox_dss_and_pdfium(self):
        for name in ("pdfbox", "dss", "pdfium"):
            with self.subTest(reader=name):
                code, report = self.reader(name, "multi-signed.pdf")
                self.assertEqual(code, 0, report)
                self.assertEqual(report["status"], "pass")
                self.assertIn("signatures=2", report["detail"])
                self.assertIn("final_document_coverage=true", report["detail"])

    def test_pdfium_rejects_uncovered_contents_gaps(self):
        for fixture in ("empty-ranges.pdf", "empty-earlier-range.pdf", "nonempty-earlier-range.pdf"):
            with self.subTest(fixture=fixture):
                code, report = self.reader("pdfium", fixture)
                self.assertEqual(code, 1, report)
                self.assertEqual(report["status"], "fail")

    def test_pdfium_binds_gap_to_xref_selected_signature_object(self):
        for fixture in ("normal-contents.pdf", "escaped-normal-contents.pdf"):
            with self.subTest(fixture=fixture):
                code, report = self.reader("pdfium", fixture)
                self.assertEqual(code, 0, report)
                self.assertIn("signed_revision_coverage=true", report["detail"])
        for fixture in ("literal-duplicate.pdf", "escaped-contents-decoy.pdf"):
            with self.subTest(fixture=fixture):
                code, report = self.reader("pdfium", fixture)
                self.assertEqual(code, 1, report)
                self.assertEqual(report["status"], "fail")

    def test_pdfium_ignores_comment_contents_decoy(self):
        for fixture, expected in (
            ("normal-gap.pdf", "pass"),
            ("unhidden-comment-decoy.pdf", "fail"),
            ("comment-contents-decoy.pdf", "fail"),
        ):
            with self.subTest(fixture=fixture):
                code, report = self.reader("pdfium", fixture)
                self.assertEqual(code, 0 if expected == "pass" else 1, report)
                self.assertEqual(report["status"], expected)

    def test_pdfium_accepts_endobj_inside_signed_reason(self):
        for fixture in ("endobj-control.pdf", "endobj-in-reason.pdf"):
            with self.subTest(fixture=fixture):
                code, report = self.reader("pyhanko", fixture)
                self.assertEqual(code, 0, report)
                self.assertEqual(report["signature_results"][0]["valid"], True)
                code, report = self.reader("pdfium", fixture)
                self.assertEqual(code, 0, report)
                self.assertEqual(report["status"], "pass")

    def test_final_coverage_does_not_depend_on_field_order(self):
        for name in ("pdfbox", "dss"):
            with self.subTest(reader=name):
                code, report = self.reader(name, "reverse-fields.pdf")
                self.assertEqual(code, 0, report)
                self.assertEqual(report["status"], "pass")
                self.assertIn("signatures=2", report["detail"])
                self.assertIn("final_document_coverage=true", report["detail"])


if __name__ == "__main__":
    unittest.main()
