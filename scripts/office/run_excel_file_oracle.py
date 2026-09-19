#!/usr/bin/env python3
"""Open a hashed native XLSX in Excel and round-trip it under Office custody."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preflight(path):
    if not path.is_file():
        raise ValueError("missing XLSX input")
    checksum = digest(path)
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() or not {"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml"}.issubset(archive.namelist()):
            raise ValueError("invalid XLSX package")
        for name in archive.namelist():
            if name.lower().endswith("vbaproject.bin"):
                raise ValueError("oracle refuses macros")
            if name.endswith((".xml", ".rels")):
                xml = ET.fromstring(archive.read(name))
                if name.endswith(".rels") and any(row.get("TargetMode") == "External" for row in xml):
                    raise ValueError("oracle refuses external relationships")
    return checksum


def run(args):
    if sys.platform != "darwin":
        raise RuntimeError("Excel oracle must run on the Mac")
    input_hash = preflight(args.input)
    args.output.mkdir(parents=True, exist_ok=False)
    receipt = dict(status="running", input_sha256=input_hash, script_sha256=digest(args.script), started_at=time.time())
    args.lock.mkdir()
    (args.lock / "owner").write_text(f"W7-C14 Excel native {args.output}\n")
    released = False
    try:
        output = args.output / "roundtrip.xlsx"
        command = ["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript", str(args.script), str(args.input), str(output), output.name, args.sheet, args.cell, args.input.name]
        result = subprocess.run(command, capture_output=True, text=True, timeout=130)
        (args.output / "driver.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            receipt["status"] = "timed-out" if result.returncode in (-14, 142) else "driver-error"
            raise RuntimeError(f"Excel driver refused: {result.returncode}")
        version, value, initial, final, startup_blank = result.stdout.strip().split("\t")
        if initial != final and not (initial == "1" and final == "0" and startup_blank == "1"):
            raise RuntimeError("Excel workbook custody changed")
        released = True
        receipt.update(app_version=version, observed=float(value), expected=args.expected, output_sha256=preflight(output), initial_workbooks=int(initial), final_workbooks=int(final), repair_requested=False)
        if receipt["observed"] != args.expected:
            raise ValueError("Excel value differs from the pinned expectation")
        receipt["status"] = "completed"
    except subprocess.TimeoutExpired:
        receipt["status"] = "timed-out"
        raise
    except Exception as error:
        if receipt["status"] == "running":
            receipt["status"] = "validation-error"
        receipt["error"] = str(error)
        raise
    finally:
        receipt.update(lock_retained=not released, finished_at=time.time())
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if released:
            (args.lock / "owner").unlink()
            args.lock.rmdir()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--sheet", default="Sheet1")
    parser.add_argument("--cell", default="F1")
    parser.add_argument("--expected", type=float, required=True)
    parser.add_argument("--lock", type=Path, default=Path("/Users/olety/w7-oracle/lock"))
    run(parser.parse_args())
