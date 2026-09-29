#!/usr/bin/env python3
"""Summarize complete real-workbook comparisons without changing runtime defaults."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

COHORTS = ("spreadsheetbench", "fuse")
ENGINES = ("libreoffice", "formualizer_unchanged", "native")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_comparison(directory, manifest):
    summary = json.loads((directory / "summary.json").read_text())
    raw = (directory / "rows.jsonl").read_bytes()
    if summary.get("fresh_excel_truth") is not True or digest(raw) != summary["comparison_rows_sha256"]:
        raise ValueError("not a hash-bound fresh Excel comparison")
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) != len(manifest) or {row["sha256"] for row in rows} != set(manifest):
        raise ValueError("incomplete or duplicate comparison cohort")
    if type(summary["workbooks"]) is not int or summary["workbooks"] != len(manifest):
        raise ValueError("workbook denominator changed")
    scored = []
    truth = {}
    for row in rows:
        key = row["sha256"]
        if row["status"] == "no-excel-truth":
            truth[key] = (row["status"], row["reason"])
        elif row["status"] == "scored":
            m = row["metrics"]
            for field in ("formula_cells", "mismatches", "missing"):
                if type(m[field]) is not int or m[field] < 0:
                    raise ValueError("invalid comparison count")
            if not m["missing"] <= m["mismatches"] <= m["formula_cells"]:
                raise ValueError("invalid mismatch bounds")
            if type(row["engine_recalculated"]) is not bool:
                raise ValueError("invalid recalculation outcome")
            truth[key] = (row["status"], m["formula_cells"])
            if m["formula_cells"]:
                scored.append(row)
        else:
            raise ValueError("unclassified comparison row")
    expected = dict(excel_completed=sum(row["status"] == "scored" for row in rows),
                    scored_workbooks=len(scored),
                    matching_workbooks=sum(row["engine_recalculated"] and row["metrics"]["mismatches"] == 0 for row in scored),
                    formula_cells=sum(row["metrics"]["formula_cells"] for row in scored),
                    mismatches=sum(row["metrics"]["mismatches"] for row in scored))
    if any(type(summary[k]) is not int or summary[k] != value for k, value in expected.items()):
        raise ValueError("summary arithmetic does not match comparison rows")
    if not expected["scored_workbooks"] or not expected["formula_cells"]:
        raise ValueError("empty scored universe cannot establish a threshold")
    return summary, truth


def summarize(config, provenance, engine_pins):
    if set(config) != set(COHORTS):
        raise ValueError("both real-workbook cohorts are required")
    if len({provenance[name]["manifest_sha256"] for name in COHORTS}) != len(COHORTS):
        raise ValueError("cohort pins must be distinct")
    if set(engine_pins) != set(ENGINES):
        raise ValueError("all engine identities must be pinned")
    results = {}
    identities = {}
    for name in COHORTS:
        cohort = config[name]
        manifest_path = Path(cohort["manifest"])
        raw = manifest_path.read_bytes()
        if manifest_path.suffix == ".gz":
            raw = gzip.decompress(raw)
        entries = [json.loads(line) for line in raw.splitlines()]
        manifest = {row["sha256"]: row["path"] for row in entries}
        if (len(manifest) != len(entries) or not manifest
                or digest(raw) != provenance[name]["manifest_sha256"]
                or len(manifest) != provenance[name]["unique"]):
            raise ValueError("invalid or substituted manifest cohort")
        if set(cohort["engines"]) != set(ENGINES):
            raise ValueError("all three measured engines are required")
        scores = {}
        common = None
        for engine in ENGINES:
            directory = Path(cohort["engines"][engine])
            summary, truth = load_comparison(directory, manifest)
            if summary["manifest_sha256"] != digest(raw):
                raise ValueError("manifest identity changed")
            current = (summary["excel_rows_sha256"], summary["excel_identity"],
                       summary["comparator_sha256"], truth)
            if common is not None and current != common:
                raise ValueError("engines did not use identical Excel truth and comparator")
            common = current
            identity = summary["engine_identity"]
            engine_id = identity.get("executable_sha256") if engine != "libreoffice" else identity.get("engine")
            if not engine_id or engine_id != engine_pins[engine]:
                raise ValueError("engine identity is absent or not the pinned candidate")
            if engine in identities and identities[engine] != engine_id:
                raise ValueError("engine changed between cohorts")
            identities[engine] = engine_id
            scores[engine] = dict(workbooks=summary["workbooks"], excel_completed=summary["excel_completed"],
                                  scored_workbooks=summary["scored_workbooks"], matching_workbooks=summary["matching_workbooks"],
                                  formula_cells=summary["formula_cells"], matching_cells=summary["formula_cells"] - summary["mismatches"],
                                  summary_sha256=digest((directory / "summary.json").read_bytes()),
                                  comparison_rows_sha256=summary["comparison_rows_sha256"],
                                  engine_rows_sha256=summary["engine_rows_sha256"])
        native, lo = scores["native"], scores["libreoffice"]
        meets = native["matching_workbooks"] >= lo["matching_workbooks"] and native["matching_cells"] >= lo["matching_cells"]
        results[name] = dict(manifest_sha256=digest(raw), excel_rows_sha256=common[0],
                             scores=scores, native_at_or_above_libreoffice=meets)
    return dict(fresh_excel_truth=True, cohorts=results, engines=identities,
                real_workbooks_at_or_above_libreoffice=all(r["native_at_or_above_libreoffice"] for r in results.values()),
                runtime_default_changed=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--engine-pins", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = summarize(json.loads(args.config.read_text()), json.loads(args.provenance.read_text()),
                       json.loads(args.engine_pins.read_text()))
    with args.output.open("x") as output:
        output.write(json.dumps(result, indent=2) + "\n")
