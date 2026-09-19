#!/usr/bin/env python3
"""Measure unchanged file recalculation against saved caches, never claim Excel truth.

Run with the upstream recalc_unchanged binary. No Office, installs or network.
Each file runs in a separate process with a bound and a distinct output path.
The pinned Apache-2.0 Witan extractor/comparator remains unchanged.
"""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor/xlsx_corpus_bench"))
from cached_values import extract, compare_to_truth


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args):
    corpus, output = args.corpus.resolve(), args.output.resolve()
    executable = args.executable.resolve(strict=True)
    output.mkdir(parents=True, exist_ok=True)
    out_files = output / "workbooks"
    out_files.mkdir(exist_ok=True)
    identity = {"mode": "saved-cache-diagnostic", "fresh_excel_truth": False,
                "executable_sha256": sha(executable), "manifest_sha256": sha(args.manifest),
                "comparator_sha256": sha(Path(__file__).resolve().parent / "vendor/xlsx_corpus_bench/cached_values.py"),
                "timeout_seconds": args.timeout}
    identity_path = output / "identity.json"
    if identity_path.exists() and json.loads(identity_path.read_text()) != identity:
        raise ValueError("cannot resume a different benchmark identity")
    identity_path.write_text(json.dumps(identity, indent=2) + "\n")
    # A concurrent developer build may replace target/debug binaries. Execute
    # a hash-bound copy for the complete measurement, not a moving path.
    frozen = output / ("engine-" + identity["executable_sha256"])
    if not frozen.exists():
        shutil.copy2(executable, frozen)
    if sha(frozen) != identity["executable_sha256"]:
        raise ValueError("benchmark executable changed while freezing")
    executable = frozen
    rows_path = output / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_text().splitlines()] if rows_path.exists() else []
    done = {row["sha256"] for row in rows}
    manifest = [json.loads(line) for line in args.manifest.read_text().splitlines()]
    with rows_path.open("a") as stream:
        for item in manifest:
            if item["sha256"] in done:
                continue
            source = (corpus / item["path"]).resolve(strict=True)
            if not source.is_relative_to(corpus) or sha(source) != item["sha256"]:
                raise ValueError("manifest path/hash mismatch")
            row = {"sha256": item["sha256"], "path": item["path"]}
            destination = out_files / (item["sha256"] + ".xlsx")
            if destination.exists():
                destination.unlink()
            start = time.monotonic()
            observed = {}
            try:
                truth = extract(str(source), with_formula=True)
                result = subprocess.run([str(executable), str(source), str(destination)],
                                        capture_output=True, text=True, timeout=args.timeout)
                row["recalc"] = {"ok": result.returncode == 0, "exit": result.returncode,
                                 "detail": (result.stdout + result.stderr)[-4096:]}
                if result.returncode == 0:
                    observed = extract(str(destination))
                    row["output_sha256"] = sha(destination)
                row["comparison"] = compare_to_truth(truth, observed)
            except subprocess.TimeoutExpired:
                row["recalc"] = {"ok": False, "error": "timed-out"}
                row["comparison"] = compare_to_truth(truth, {})
            except (OSError, ValueError, KeyError, RuntimeError, ET.ParseError, zipfile.BadZipFile) as error:
                row["recalc"] = {"ok": False, "error": type(error).__name__, "detail": str(error)[:4096]}
            row["seconds"] = time.monotonic() - start
            stream.write(json.dumps(row) + "\n")
            stream.flush()
            rows.append(row)
            print(f"{len(rows)}/{len(manifest)} {row['sha256']}", flush=True)
    scored = [row for row in rows if row.get("comparison", {}).get("formula_cells", 0) > 0]
    summary = {**identity, "workbooks": len(rows), "scored_workbooks": len(scored),
               "matching_workbooks": sum(row["recalc"]["ok"] and row["comparison"]["mismatches"] == 0 for row in scored),
               "formula_cells": sum(row["comparison"]["formula_cells"] for row in scored),
               "mismatches": sum(row["comparison"]["mismatches"] for row in scored),
               "rows_sha256": sha(rows_path)}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120:
        parser.error("timeout must be between 1 and 120 seconds")
    print(json.dumps(run(args), indent=2))


if __name__ == "__main__":
    main()
