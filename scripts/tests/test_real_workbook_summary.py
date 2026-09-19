"""Fresh-truth threshold summaries refuse incomplete or non-comparable evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("workbook_summary", Path(__file__).parents[1] / "office/summarize_real_workbooks.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WorkbookSummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.config, self.provenance = {}, {}
        self.pins = dict(libreoffice="LibreOffice pinned", formualizer_unchanged="1" * 64, native="2" * 64)
        for cohort in MODULE.COHORTS:
            folder = base / cohort
            folder.mkdir()
            manifest = folder / "manifest.jsonl"
            manifest.write_text(json.dumps(dict(sha256="a" * 64, path=cohort + ".xlsx")) + "\n")
            pin = MODULE.digest(manifest.read_bytes())
            self.provenance[cohort] = dict(manifest_sha256=pin, unique=1)
            engines = {}
            for index, engine in enumerate(MODULE.ENGINES):
                directory = folder / engine
                directory.mkdir()
                engines[engine] = str(directory)
                rows = [dict(sha256="a" * 64, status="scored", engine_recalculated=True,
                             metrics=dict(formula_cells=2, mismatches=0, missing=0))]
                raw = (json.dumps(rows[0]) + "\n").encode()
                (directory / "rows.jsonl").write_bytes(raw)
                identity = dict(engine="LibreOffice pinned") if engine == "libreoffice" else dict(executable_sha256=str(index) * 64)
                summary = dict(fresh_excel_truth=True, manifest_sha256=pin, workbooks=1,
                               excel_completed=1, scored_workbooks=1, matching_workbooks=1,
                               formula_cells=2, mismatches=0, comparison_rows_sha256=MODULE.digest(raw),
                               excel_rows_sha256="excel-" + cohort, excel_identity=dict(manifest_sha256=pin),
                               comparator_sha256="comparator", engine_rows_sha256="engine-rows",
                               engine_identity=identity)
                (directory / "summary.json").write_text(json.dumps(summary))
            self.config[cohort] = dict(manifest=str(manifest), engines=engines)

    def summary_path(self, cohort="fuse", engine="native"):
        return Path(self.config[cohort]["engines"][engine]) / "summary.json"

    def alter(self, key, value, cohort="fuse", engine="native"):
        path = self.summary_path(cohort, engine)
        summary = json.loads(path.read_text())
        summary[key] = value
        path.write_text(json.dumps(summary))

    def test_complete_equal_scores_meet_threshold_but_never_change_defaults(self):
        result = MODULE.summarize(self.config, self.provenance, self.pins)
        self.assertTrue(result["real_workbooks_at_or_above_libreoffice"])
        self.assertFalse(result["runtime_default_changed"])
        self.assertEqual(result["cohorts"]["fuse"]["scores"]["native"]["matching_cells"], 2)

    def test_one_native_regression_keeps_threshold_closed(self):
        path = self.summary_path()
        rows_path = path.with_name("rows.jsonl")
        row = json.loads(rows_path.read_text())
        row["metrics"]["mismatches"] = 1
        raw = (json.dumps(row) + "\n").encode()
        rows_path.write_bytes(raw)
        self.alter("comparison_rows_sha256", MODULE.digest(raw))
        self.alter("mismatches", 1)
        self.alter("matching_workbooks", 0)
        result = MODULE.summarize(self.config, self.provenance, self.pins)
        self.assertFalse(result["real_workbooks_at_or_above_libreoffice"])
        self.assertTrue(result["cohorts"]["spreadsheetbench"]["native_at_or_above_libreoffice"])
        self.assertFalse(result["runtime_default_changed"])

    def test_partial_saved_cache_changed_truth_and_changed_engine_refuse(self):
        path = self.summary_path()
        original = path.read_bytes()
        for key, value in [("fresh_excel_truth", False), ("workbooks", 0),
                           ("excel_rows_sha256", "different-truth"),
                           ("engine_identity", {"executable_sha256": "other-binary"}),
                           ("matching_workbooks", 5)]:
            with self.subTest(key=key):
                self.alter(key, value)
                with self.assertRaises(ValueError):
                    MODULE.summarize(self.config, self.provenance, self.pins)
                path.write_bytes(original)

    def test_empty_scored_universe_does_not_pass_vacuously(self):
        for cohort in MODULE.COHORTS:
            for engine in MODULE.ENGINES:
                path = self.summary_path(cohort, engine)
                rows_path = path.with_name("rows.jsonl")
                row = json.loads(rows_path.read_text())
                row["metrics"]["formula_cells"] = 0
                raw = (json.dumps(row) + "\n").encode()
                rows_path.write_bytes(raw)
                for key, value in [("formula_cells", 0), ("scored_workbooks", 0),
                                   ("matching_workbooks", 0), ("comparison_rows_sha256", MODULE.digest(raw))]:
                    self.alter(key, value, cohort, engine)
        with self.assertRaisesRegex(ValueError, "empty scored"):
            MODULE.summarize(self.config, self.provenance, self.pins)

    def test_missing_rows_and_missing_or_substituted_cohort_refuse(self):
        rows_path = self.summary_path().with_name("rows.jsonl")
        rows_path.write_bytes(b"")
        self.alter("comparison_rows_sha256", MODULE.digest(b""))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            MODULE.summarize(self.config, self.provenance, self.pins)
        with self.assertRaisesRegex(ValueError, "both"):
            MODULE.summarize({"fuse": self.config["fuse"]}, self.provenance, self.pins)
        config = dict(self.config, fuse=self.config["spreadsheetbench"])
        with self.assertRaisesRegex(ValueError, "substituted"):
            MODULE.summarize(config, self.provenance, self.pins)


if __name__ == "__main__":
    unittest.main()
