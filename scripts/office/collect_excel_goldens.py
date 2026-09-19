#!/usr/bin/env python3
"""Pin Excel cached values and privacy-normalized workbook fixtures for offline CI."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

from run_excel_oracle import cached_cells, result_value, validate_setup


def sha(data):
    return hashlib.sha256(data).hexdigest()


def normalize_metadata(data):
    """Only author/host-path metadata changes. Worksheet/value parts are byte-exact."""
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(output, "w") as target:
        for item in source.infolist():
            part = source.read(item.filename)
            if item.filename == "docProps/core.xml":
                for tag in (b"dc:creator", b"cp:lastModifiedBy"):
                    part = re.sub(rb'(<'+tag+rb'(?:\s[^>]*)?>).*?(</'+tag+rb'>)', rb'\g<1>Oneiron oracle\g<2>', part, flags=re.S)
            elif item.filename == "xl/workbook.xml":
                part = re.sub(rb'<x15ac:absPath\b[^>]*/>', b'', part)
            target.writestr(item, part)
    return output.getvalue()


def collect(args):
    raw = args.receipt.read_bytes()
    receipt = json.loads(raw)
    cases_raw = args.cases.read_bytes()
    cases = json.loads(cases_raw)
    if receipt["status"] != "completed" or receipt["lock_retained"]:
        raise ValueError("Excel corpus is not complete/cleaned")
    if receipt["input_sha256"] != sha(cases_raw) or set(receipt["cases"]) != {c["id"] for c in cases}:
        raise ValueError("Excel input corpus mismatch")
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": 1, "excel_version": receipt["app_version"],
                "input_sha256": sha(cases_raw), "native_receipt_sha256": sha(raw),
                "script_sha256": receipt["script_sha256"], "save_sha256": receipt["save_sha256"],
                "cleanup_sha256": receipt["cleanup_sha256"], "sources": receipt.get("sources", []),
                "normalization": "creator/lastModifiedBy replaced with Oneiron oracle; workbook x15ac:absPath removed; worksheet parts unchanged",
                "cases": {}}
    archive_path = args.output / "cached-workbooks.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, case in enumerate(cases):
            row = receipt["cases"][case["id"]]
            original = (args.receipt.parent / row["file"]).read_bytes()
            if sha(original) != row["output_sha256"]:
                raise ValueError("native Excel output hash mismatch")
            decoded = cached_cells(args.receipt.parent / row["file"])
            validate_setup(case, decoded)
            if decoded.get("Z1") != 3333 or result_value(case, decoded) != row["value"]:
                raise ValueError("native Excel cached value mismatch")
            fixture = normalize_metadata(original)
            with zipfile.ZipFile(io.BytesIO(original)) as before, zipfile.ZipFile(io.BytesIO(fixture)) as after:
                for part in before.namelist():
                    if part not in ("docProps/core.xml", "xl/workbook.xml") and before.read(part) != after.read(part):
                        raise ValueError("normalization modified an input/value part")
            name = f"case-{index:04}.xlsx"
            info = zipfile.ZipInfo(name, date_time=(2026, 9, 19, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, fixture)
            manifest["cases"][case["id"]] = {"function": case["function"], "status": row["status"],
                "value": row["value"], "file": name, "fixture_sha256": sha(fixture),
                "native_output_sha256": row["output_sha256"], "source_receipt_sha256": row.get("source_receipt_sha256", sha(raw)), "formula_rejection": row.get("formula_rejection")}
    manifest["archive_sha256"] = sha(archive_path.read_bytes())
    (args.output / "goldens.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    collect(parser.parse_args())
