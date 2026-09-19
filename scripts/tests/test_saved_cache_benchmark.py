"""Diagnostic corpus runs cannot masquerade as native Excel truth."""
from argparse import Namespace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/office"))
from run_saved_cache_benchmark import run


class SavedCacheBenchmark(unittest.TestCase):
    def test_failed_engine_counts_missing_cells_and_resume_stays_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            corpus = base / "corpus"
            corpus.mkdir()
            source = corpus / "one.xlsx"
            with zipfile.ZipFile(source, "w") as z:
                z.writestr("xl/workbook.xml", '<workbook xmlns:r="urn:relationships"><sheets><sheet name="S" r:id="s"/></sheets></workbook>')
                z.writestr("xl/_rels/workbook.xml.rels", '<Relationships><Relationship Id="s" Target="worksheets/s.xml"/></Relationships>')
                z.writestr("xl/worksheets/s.xml", '<worksheet><sheetData><row><c r="A1"><f>1+1</f><v>2</v></c></row></sheetData></worksheet>')
            manifest = base / "manifest.jsonl"
            manifest.write_text(json.dumps({"path":"one.xlsx", "sha256":hashlib.sha256(source.read_bytes()).hexdigest()}) + "\n")
            executable = base / "refusing-engine"
            executable.write_text("#!/usr/bin/env python3\nraise SystemExit(1)\n")
            executable.chmod(0o755)
            args = Namespace(corpus=corpus, manifest=manifest, executable=executable, output=base / "out", timeout=1)
            summary = run(args)
            self.assertFalse(summary["fresh_excel_truth"])
            self.assertEqual(summary["matching_workbooks"], 0)
            self.assertEqual(summary["formula_cells"], 1)
            self.assertEqual(summary["mismatches"], 1)
            self.assertEqual(run(args), summary)
            executable.write_text("#!/usr/bin/env python3\nraise SystemExit(2)\n")
            with self.assertRaises(ValueError):
                run(args)


if __name__ == "__main__":
    unittest.main()
