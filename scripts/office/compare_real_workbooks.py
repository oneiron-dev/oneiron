#!/usr/bin/env python3
"""Compare already measured outputs against hash-bound, freshly recalculated Excel files."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor/xlsx_corpus_bench"))
from cached_values import compare_to_truth, extract


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def index_rows(path, manifest):
    records = [json.loads(line) for line in path.read_text().splitlines()]
    indexed = {}
    for record in records:
        key = record["sha256"]
        if key in indexed or key not in manifest or record["path"] != manifest[key]:
            raise ValueError("duplicate, foreign or changed manifest row")
        indexed[key] = record
    if set(indexed) != set(manifest):
        raise ValueError("measurement is incomplete")
    return indexed


def compare(manifest_path, excel_dir, engine_dir):
    entries = [json.loads(line) for line in manifest_path.read_text().splitlines()]
    manifest = {row["sha256"]: row["path"] for row in entries}
    if len(manifest) != len(entries): raise ValueError("duplicate manifest identity")
    excel_identity = json.loads((excel_dir / "identity.json").read_text())
    engine_identity = json.loads((engine_dir / "identity.json").read_text())
    manifest_hash = digest(manifest_path)
    if any(pin["manifest_sha256"] != manifest_hash for pin in (excel_identity, engine_identity)):
        raise ValueError("different measurement corpora")
    custody = json.loads((excel_dir / "custody.json").read_text())
    if custody["lock_retained"]: raise ValueError("Excel has not restored custody")
    excel = index_rows(excel_dir / "rows.jsonl", manifest)
    engine = index_rows(engine_dir / "rows.jsonl", manifest)
    comparisons = []
    for key in manifest:
        truth_row, observed_row = excel[key], engine[key]
        if truth_row["status"] != "completed":
            comparisons.append(dict(sha256=key, status="no-excel-truth", reason=truth_row["status"]))
            continue
        if truth_row.get("calculation") != "calculate full rebuild" or truth_row.get("final_workbooks") != 0:
            raise ValueError("Excel row does not prove recalculation and cleanup")
        truth_file = excel_dir / (key + ".xlsx")
        if digest(truth_file) != truth_row["output_sha256"]: raise ValueError("Excel output hash changed")
        truth = extract(str(truth_file), with_formula=True)
        observed = {}
        if observed_row["recalc"]["ok"]:
            output = engine_dir / "workbooks" / (key + ".xlsx")
            if digest(output) != observed_row["output_sha256"]: raise ValueError("engine output hash changed")
            observed = extract(str(output))
        comparisons.append(dict(sha256=key, status="scored", metrics=compare_to_truth(truth, observed), engine_recalculated=observed_row["recalc"]["ok"]))
    scored = [row for row in comparisons if row.get("metrics", {}).get("formula_cells", 0) > 0]
    summary = dict(fresh_excel_truth=True, manifest_sha256=manifest_hash, workbooks=len(manifest),
                   excel_completed=sum(row["status"] == "completed" for row in excel.values()),
                   scored_workbooks=len(scored),
                   matching_workbooks=sum(row["engine_recalculated"] and row["metrics"]["mismatches"] == 0 for row in scored),
                   formula_cells=sum(row["metrics"]["formula_cells"] for row in scored),
                   mismatches=sum(row["metrics"]["mismatches"] for row in scored),
                   excel_identity=excel_identity, engine_identity=engine_identity,
                   excel_rows_sha256=digest(excel_dir / "rows.jsonl"), engine_rows_sha256=digest(engine_dir / "rows.jsonl"),
                   comparator_sha256=digest(Path(__file__).resolve().parent / "vendor/xlsx_corpus_bench/cached_values.py"))
    return summary, comparisons


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ["manifest", "excel", "engine", "output"]: parser.add_argument("--" + field, type=Path, required=True)
    args = parser.parse_args()
    summary, rows = compare(args.manifest, args.excel, args.engine)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "rows.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    summary["comparison_rows_sha256"] = digest(args.output / "rows.jsonl")
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
