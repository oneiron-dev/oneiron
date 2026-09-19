"""Offline integrity and arithmetic of complete corpus measurement receipts.

Saved-source caches are diagnostic only. These checks do not create fresh Excel
truth, count a partial cohort as complete, or authorize a native default.
"""
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import unittest

FIXTURES = Path(__file__).parents[2] / "crates/oneiron-docedit/tests/fixtures/real-workbooks"


def read_json(name):
    return json.loads((FIXTURES / name).read_text())


def read_rows(name, expected_hash):
    data = gzip.decompress((FIXTURES / name).read_bytes())
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("corpus receipt hash changed")
    return [json.loads(line) for line in data.splitlines()]


class CompleteCorpusReceipts(unittest.TestCase):
    def manifest(self, corpus):
        pin = read_json("provenance.json")[corpus]
        rows = read_rows(corpus + "-manifest.jsonl.gz", pin["manifest_sha256"])
        pairs = {row["sha256"]: row["path"] for row in rows}
        self.assertEqual(len(pairs), len(rows))
        self.assertEqual(len(rows), pin["unique"])
        return pairs

    def complete(self, rows, manifest):
        self.assertEqual(len(rows), len(manifest))
        self.assertEqual({row["sha256"]: row["path"] for row in rows}, manifest)
        self.assertTrue(all(type(row["recalc"]["ok"]) is bool for row in rows))

    def classification(self, rows, receipt):
        succeeded = sum(row["recalc"]["ok"] for row in rows)
        self.assertEqual(succeeded, receipt["recalculated"])
        self.assertEqual(len(rows) - succeeded, receipt["refused"])
        if "failure_counts" in receipt:
            failures = Counter(row["recalc"].get("detail", row["recalc"].get("error", "unknown"))
                               for row in rows if not row["recalc"]["ok"])
            self.assertEqual(dict(failures), receipt["failure_counts"])

    def diagnostic(self, rows, summary):
        self.assertEqual(summary["mode"], "saved-cache-diagnostic")
        self.assertIs(summary["fresh_excel_truth"], False)
        scored = [row for row in rows if row.get("comparison", {}).get("formula_cells", 0) > 0]
        self.assertEqual(len(rows), summary["workbooks"])
        self.assertEqual(len(scored), summary["scored_workbooks"])
        self.assertEqual(sum(row["recalc"]["ok"] and row["comparison"]["mismatches"] == 0
                             for row in scored), summary["matching_workbooks"])
        for metric in ["formula_cells", "mismatches"]:
            self.assertEqual(sum(row["comparison"][metric] for row in scored), summary[metric])
        for row in scored:
            metrics = row["comparison"]
            self.assertLessEqual(metrics["missing"], metrics["mismatches"])
            self.assertLessEqual(metrics["mismatches"], metrics["formula_cells"])

    def test_spreadsheetbench_complete_lanes_match_pinned_cohort(self):
        manifest = self.manifest("spreadsheetbench")
        receipt = read_json("spreadsheetbench-completed-lanes.json")
        self.assertEqual(receipt["workbooks"], len(manifest))
        lo = receipt["libreoffice"]
        pins = read_json("engine-comparison-pins.json")
        self.assertEqual(pins["libreoffice"], lo["identity"]["engine"])
        self.assertEqual(pins["native"], read_json("retained-native-v3-executable.json")["executable_sha256"])
        rows = read_rows("spreadsheetbench-libreoffice-rows.jsonl.gz", lo["rows_sha256"])
        self.complete(rows, manifest)
        self.classification(rows, lo)
        native = receipt["retained_native"]
        summary = read_json("retained-native-v1-saved-cache-diagnostic.json")
        rows = read_rows("spreadsheetbench-retained-native-v1-rows.jsonl.gz", summary["rows_sha256"])
        self.complete(rows, manifest)
        self.classification(rows, native)
        self.diagnostic(rows, summary)
        for identity in [lo["identity"], native["identity"], summary]:
            self.assertEqual(identity["manifest_sha256"], receipt["manifest_sha256"])
        self.assertEqual(native["identity"]["executable_sha256"], summary["executable_sha256"])

    def test_native_candidates_cover_complete_spreadsheetbench_cohort(self):
        manifest = self.manifest("spreadsheetbench")
        for version in [2, 3]:
            with self.subTest(version=version):
                receipt = read_json(f"spreadsheetbench-native-v{version}-classification.json")
                summary = read_json(f"retained-native-v{version}-saved-cache-diagnostic.json")
                self.assertEqual(receipt["rows_sha256"], summary["rows_sha256"])
                rows = read_rows(f"spreadsheetbench-retained-native-v{version}-rows.jsonl.gz", summary["rows_sha256"])
                self.complete(rows, manifest)
                self.classification(rows, receipt)
                self.diagnostic(rows, summary)
                self.assertEqual(summary["executable_sha256"], read_json(f"retained-native-v{version}-executable.json")["executable_sha256"])
                self.assertEqual(receipt["identity"]["executable_sha256"], summary["executable_sha256"])
                self.assertEqual(summary["manifest_sha256"], read_json("provenance.json")["spreadsheetbench"]["manifest_sha256"])

    def test_current_native_candidate_refuses_crashing_inputs_and_still_recalculates(self):
        receipt = read_json("retained-native-v3-executable.json")
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(len(receipt["cases"]), 2)
        manifest = self.manifest("fuse")
        for case in receipt["cases"]:
            self.assertIn(case["input_sha256"], manifest)
            self.assertEqual(case["exit_code"], 1)
            self.assertFalse(case["output_exists"])
        probe = receipt["positive_probe"]
        self.assertEqual(float(probe["value"]), 3)
        self.assertEqual(probe["report"]["formulas"], 1)
        self.assertFalse(probe["report"]["precision_fallback"])
        self.assertNotEqual(receipt["executable_sha256"], read_json("retained-native-v2-executable.json")["executable_sha256"])

    def test_historical_native_fuse_lane_covers_complete_cohort(self):
        manifest = self.manifest("fuse")
        executable_pins = {
            1: read_json("spreadsheetbench-completed-lanes.json")["retained_native"]["identity"]["executable_sha256"],
            2: read_json("retained-native-v2-executable.json")["executable_sha256"],
        }
        for version, executable in executable_pins.items():
            with self.subTest(version=version):
                prefix = f"fuse-native-v{version}"
                receipt = read_json(prefix + "-classification.json")
                summary = read_json(prefix + "-saved-cache-diagnostic.json")
                self.assertEqual(receipt["rows_sha256"], summary["rows_sha256"])
                rows = read_rows(prefix + "-rows.jsonl.gz", summary["rows_sha256"])
                self.complete(rows, manifest)
                self.classification(rows, receipt)
                self.diagnostic(rows, summary)
                self.assertEqual(summary["executable_sha256"], executable)
                self.assertEqual(summary["manifest_sha256"], read_json("provenance.json")["fuse"]["manifest_sha256"])

    def test_fuse_libreoffice_complete_lane_matches_pinned_cohort(self):
        manifest = self.manifest("fuse")
        receipt = read_json("fuse-libreoffice-classification.json")
        rows = read_rows("fuse-libreoffice-rows.jsonl.gz", receipt["rows_sha256"])
        self.complete(rows, manifest)
        self.classification(rows, receipt)
        self.assertEqual(receipt["workbooks"], len(manifest))
        self.assertEqual(receipt["identity"]["engine"], read_json("engine-comparison-pins.json")["libreoffice"])
        self.assertEqual(receipt["identity"]["manifest_sha256"], read_json("provenance.json")["fuse"]["manifest_sha256"])
        self.assertIs(receipt["fresh_excel_truth"], False)
        self.assertIs(receipt["native_default_eligible"], False)
        for row in rows:
            if row["recalc"]["ok"]:
                self.assertRegex(row["output_sha256"], r"^[0-9a-f]{64}$")

    def test_fuse_unchanged_complete_lane_matches_pinned_extraction(self):
        manifest = self.manifest("fuse")
        receipt = read_json("fuse-unchanged-classification.json")
        summary = read_json("fuse-unchanged-saved-cache-diagnostic.json")
        self.assertEqual(read_json("engine-comparison-pins.json")["formualizer_unchanged"], summary["executable_sha256"])
        self.assertEqual(receipt["rows_sha256"], summary["rows_sha256"])
        rows = read_rows("fuse-unchanged-rows.jsonl.gz", receipt["rows_sha256"])
        self.complete(rows, manifest)
        self.classification(rows, receipt)
        self.diagnostic(rows, summary)
        extraction = read_json("fuse-extraction-receipt.json")
        self.assertEqual(extraction["manifest_sha256"], summary["manifest_sha256"])
        self.assertEqual(receipt["identity"]["manifest_sha256"], summary["manifest_sha256"])
        self.assertEqual(receipt["identity"]["executable_sha256"], summary["executable_sha256"])
        self.assertEqual(extraction["classification"]["kept"], len(manifest))
        self.assertEqual(extraction["source"], read_json("fuse-download-receipt.json"))


if __name__ == "__main__":
    unittest.main()
