#!/usr/bin/env python3
"""Combine hash-verified Office batches, retaining per-case native provenance."""
import argparse
import hashlib
import json
from pathlib import Path
from run_excel_oracle import cached_cells, result_value, validate_setup


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--receipt", action="append", type=Path, required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    cases = json.loads(args.cases.read_bytes())
    sources = [(path, json.loads(path.read_bytes())) for path in args.receipt]
    versions = {receipt["app_version"] for _, receipt in sources}
    if len(versions) != 1 or any(r["status"] != "completed" or r["lock_retained"] for _, r in sources):
        raise ValueError("cannot merge incomplete/different-app Office batches")
    args.output.mkdir(parents=True, exist_ok=False)
    receipts = [{"sha256": digest(p), "input_sha256": r["input_sha256"], "script_sha256": r["script_sha256"], "runner_sha256": r["runner_sha256"]} for p, r in sources]
    result = {"status": "completed", "lock_retained": False, "app_version": versions.pop(), "input_sha256": digest(args.cases), "sources": receipts,
              "script_sha256": [r["script_sha256"] for r in receipts], "cleanup_sha256": sources[-1][1]["cleanup_sha256"], "save_sha256": sources[-1][1]["save_sha256"], "cases": {}}
    for index, case in enumerate(cases):
        path, source = next((p, r) for p, r in reversed(sources) if case["id"] in r["cases"])
        row = source["cases"][case["id"]]
        input_file = path.parent / row["file"]
        if digest(input_file) != row["output_sha256"]:
            raise ValueError("native Office hash mismatch")
        cells = cached_cells(input_file)
        validate_setup(case, cells)
        if cells.get("Z1") != 3333 or result_value(case, cells) != row["value"]:
            raise ValueError("native cache mismatch")
        output_file = args.output / f"case-{index:04}.xlsx"
        output_file.write_bytes(input_file.read_bytes())
        result["cases"][case["id"]] = dict(row, file=output_file.name, source_receipt_sha256=digest(path))
    (args.output / "receipt.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
