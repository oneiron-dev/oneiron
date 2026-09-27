"""Opt-in pinned-reader tests using a retained two-revision PDF fixture."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pdf_source import SignatureSource, SourceSpan
from reader_result import EnvelopeKind, Rejected, NotEstablished, evaluate_coverage

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
BIN = Path(os.environ.get("SEAL_INTEROP_HOME", "/mnt/wd16/w8-build/seal-interop")) / "bin"


class CoverageResultTests(unittest.TestCase):
    def test_unknown_envelope_kind_is_not_a_signature(self):
        with self.assertRaises(ValueError):
            EnvelopeKind.from_pdf_type("/UnknownEnvelope")

    def test_wrong_gap_is_rejected_but_missing_source_span_is_not_established(self):
        data = (FIXTURES / "multi-signed.pdf").read_bytes()
        byte_range = (0, 728, 5094, 605)
        source = SignatureSource(7, 0, 1, 5699, byte_range, b"CMS",
                                 SourceSpan(728, 5094), None, 5387, 5552,
                                 EnvelopeKind.SIGNATURE)
        missing = replace(source, contents_span=None, source_reason="object stream")
        outcome = evaluate_coverage(missing, byte_range, b"CMS", data)
        self.assertIsInstance(outcome, NotEstablished)
        self.assertEqual(outcome.to_json()["state"], "not_established")
        misplaced = replace(source, contents_span=SourceSpan(1, 5698))
        outcome = evaluate_coverage(misplaced, byte_range, b"CMS", data)
        self.assertIsInstance(outcome, Rejected)
        self.assertEqual(outcome.to_json()["state"], "rejected")


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

    def test_document_timestamp_dispatches_separately_and_rejects_corruption(self):
        for fixture, expected, code in (
            ("signed-with-document-timestamp.pdf", [True, True], 0),
            ("corrupt-document-timestamp.pdf", [True, False], 1),
        ):
            with self.subTest(fixture=fixture):
                exit_code, report = self.reader("pyhanko", fixture)
                self.assertEqual(exit_code, code, report)
                self.assertEqual(report["signatures_checked"], 2)
                self.assertEqual([x["kind"] for x in report["signature_results"]],
                                 ["Signature", "DocumentTimestamp"])
                self.assertEqual([x["valid"] for x in report["signature_results"]], expected)
                self.assertEqual(report["status"], "pass" if code == 0 else "fail")
                self.assertIn("trust override", report["detail"])

    def test_earlier_signed_revision_is_accepted_by_pdfbox_dss_and_pdfium(self):
        for name in ("pdfbox", "dss", "pdfium"):
            with self.subTest(reader=name):
                code, report = self.reader(name, "multi-signed.pdf")
                self.assertEqual(code, 0, report)
                self.assertEqual(report["status"], "pass")
                self.assertIn("signatures=2", report["detail"])
                self.assertIn("final_document_coverage=true", report["detail"])
                if name == "pdfium":
                    self.assertEqual(report["coverage_outcome"], "established")
                    evidence = report["signature_results"][0]["coverage"]["evidence"]
                    self.assertEqual(evidence["gap"], {"start": 728, "end": 5094})
                    self.assertEqual(evidence["source_provider"], "pyhanko-source")

    def test_missing_source_span_is_incomplete_in_runner(self):
        # Exercise the real PDFium wrapper with an unsupported source adapter,
        # not just the runner's response to a synthetic JSON row.
        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory) / "missing-source"
            wrapper.write_text(
                "#!/usr/bin/env python3\nimport sys\nfrom dataclasses import replace\n"
                f"sys.path.insert(0, {str(ROOT)!r})\nimport pdfium as reader\n"
                "original = reader.signature_sources\n"
                "def unavailable(data):\n"
                "    return [replace(source, contents_span=None, "
                "source_reason='unsupported source representation') "
                "for source in original(data)]\n"
                "reader.signature_sources = unavailable\n"
                "raise SystemExit(reader.main(sys.argv[1]))\n"
            )
            wrapper.chmod(0o755)
            python = BIN.parent / "venv/bin"
            env = {**os.environ, "SEAL_PDFIUM_BIN": str(wrapper),
                   "PATH": f"{python}:{os.environ.get('PATH', '')}"}
            run = subprocess.run(
                [sys.executable, str(ROOT / "runner.py"), "--reader", "pdfium",
                 str(FIXTURES / "multi-signed.pdf")], env=env, text=True, capture_output=True)
            self.assertEqual(run.returncode, 77, run.stdout + run.stderr)
            self.assertEqual(run.stdout.strip().split("\t")[4], "unavailable")
            direct = subprocess.run([str(wrapper), str(FIXTURES / "multi-signed.pdf")],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(direct.returncode, 77, direct.stdout)
            report = json.loads(direct.stdout)
            self.assertEqual(report["coverage_outcome"], "not_established")
            self.assertTrue(all(item["coverage"]["state"] == "not_established"
                                for item in report["signature_results"]))

    def test_pdfium_rejects_uncovered_contents_gaps(self):
        for fixture in ("empty-ranges.pdf", "empty-earlier-range.pdf", "nonempty-earlier-range.pdf"):
            with self.subTest(fixture=fixture):
                code, report = self.reader("pdfium", fixture)
                self.assertEqual(code, 1, report)
                self.assertEqual(report["status"], "fail")
                self.assertEqual(report["coverage_outcome"], "rejected")

    def test_pdfium_binds_gap_to_xref_selected_signature_object(self):
        for fixture in ("normal-contents.pdf", "escaped-normal-contents.pdf"):
            with self.subTest(fixture=fixture):
                code, report = self.reader("pdfium", fixture)
                self.assertEqual(code, 0, report)
                self.assertEqual(report["coverage_outcome"], "established")
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

    def test_pdfium_distinguishes_contents_name_value_from_key(self):
        for fixture in ("name-value-control.pdf", "contents-name-value.pdf", "complex-values.pdf"):
            with self.subTest(fixture=fixture):
                code, report = self.reader("pyhanko", fixture)
                self.assertEqual(code, 0, report)
                self.assertTrue(report["signature_results"][0]["valid"])
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
