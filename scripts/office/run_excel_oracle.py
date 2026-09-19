#!/usr/bin/env python3
"""Mac-only Office runner: shared lock, bounded JXA batches, hashed cached-value receipts.

Uses the installed Excel and Python standard library. Never installs tools or kills Office.
A timeout or cleanup failure retains the lock for explicit recovery instead of exposing
another ticket to a possibly blocked app. Pre-existing workbooks are not closed or changed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from run_word_oracle import app_stage
import xml.etree.ElementTree as ET
import zipfile

NS = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def cached_cells(path):
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError("invalid output ZIP")
        strings = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            strings = ["".join(item.itertext()) for item in root.findall("s:si", NS)]
        root = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        cells = {}
        for cell in root.findall(".//s:sheetData/s:row/s:c", NS):
            kind = cell.get("t", "n")
            value = cell.find("s:v", NS)
            if kind == "inlineStr":
                value = cell.find("s:is", NS)
                decoded = "".join(value.itertext()) if value is not None else ""
            elif value is None:
                decoded = None
            elif kind == "s":
                decoded = strings[int(value.text)]
            elif kind == "b":
                decoded = value.text == "1"
            elif kind in ("e", "str"):
                decoded = value.text or ""
            else:
                decoded = float(value.text) if value.text else None
            cells[cell.attrib["r"]] = decoded
        return cells

def validate_setup(case, cells):
    for address, expected in case.get("setup_cells", {}).items():
        if isinstance(expected, str) and expected.startswith("="):
            continue
        actual = cells.get(address)
        if expected is None:
            if actual not in (None, ""):
                raise ValueError(f"setup blank changed at {address}")
        elif isinstance(expected, bool):
            if type(actual) is not bool or actual != expected:
                raise ValueError(f"setup boolean changed at {address}")
        elif isinstance(expected, str):
            if type(actual) is not str or actual != expected:
                raise ValueError(f"setup string changed at {address}")
        elif isinstance(actual, bool) or not isinstance(actual, (float, int)) or actual != expected:
            raise ValueError(f"setup number changed at {address}")


def coordinate(address):
    import re
    match = re.fullmatch(r"([A-Z]+)([1-9][0-9]*)", address)
    if not match:
        raise ValueError("bad cell address")
    col = 0
    for ch in match[1]:
        col = col * 26 + ord(ch) - ord("A") + 1
    return int(match[2]), col

def address(row, col):
    letters = ""
    while col:
        col, rem = divmod(col - 1, 26)
        letters = chr(65 + rem) + letters
    return f"{letters}{row}"

def result_value(case, cells):
    check = case.get("check_range", "F1")
    first, _, last = check.partition(":")
    if not last:
        return cells.get(first)
    sr, sc = coordinate(first)
    er, ec = coordinate(last)
    grid = [[cells.get(address(r, c)) for c in range(sc, ec + 1)] for r in range(sr, er + 1)]
    expected = case.get("expected")
    if isinstance(expected, list) and expected and not isinstance(expected[0], list):
        return [v for row in grid for v in row]
    return grid

def workbook_identities(script):
    process = subprocess.run(["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript", str(script.with_name("excel_inventory.applescript"))], capture_output=True, text=True, timeout=130)
    if process.returncode: raise RuntimeError("Excel inventory refused")
    rows = [tuple(line.split("\t")) for line in process.stdout.splitlines() if line]
    if any(len(row) != 3 for row in rows): raise RuntimeError("Invalid workbook inventory")
    return sorted(rows)


def run(args):
    if sys.platform != "darwin":
        raise RuntimeError("Excel oracle must run on the Office Mac")
    args.output.mkdir(parents=True, exist_ok=False)
    cases = json.loads(args.cases.read_text())
    if args.limit is not None:
        cases = cases[:args.limit]
    receipt = {"status": "running", "input_sha256": digest(args.cases),
               "script_sha256": digest(args.script), "cleanup_sha256": digest(args.script.with_name("close_excel.applescript")), "save_sha256": digest(args.script.with_name("save_excel.applescript")), "runner_sha256": digest(Path(__file__)), "cases": {}, "batches": [], "started_at": time.time()}
    previous = None
    if args.reuse is not None:
        previous = json.loads(args.reuse.read_bytes())
        for field in ("input_sha256", "script_sha256", "cleanup_sha256", "save_sha256"):
            if previous.get(field) != receipt[field]:
                raise ValueError(f"oracle reuse {field} mismatch")
        if previous.get("lock_retained"):
            raise ValueError("recover the previous Office session before reuse")
        receipt["reused_receipt_sha256"] = digest(args.reuse)
        receipt["app_version"] = previous["app_version"]
        indexed = {case["id"]: (index, case) for index, case in enumerate(cases)}
        for case_id, row in previous["cases"].items():
            if case_id not in indexed or row["status"] not in ("ok", "formula-rejected", "missing-cache"):
                raise ValueError("unrecognized reusable case")
            index, case = indexed[case_id]
            source = args.reuse.parent / row["file"]
            if digest(source) != row["output_sha256"]:
                raise ValueError("reused Excel output hash mismatch")
            cells = cached_cells(source)
            if cells.get("Z1") != 3333 or result_value(case, cells) != row["value"]:
                raise ValueError("reused cached value mismatch")
            path = args.output / f"case-{index:04}.xlsx"
            path.write_bytes(source.read_bytes())
            receipt["cases"][case_id] = dict(row, file=path.name)
    receipt_path = args.output / "receipt.json"
    def save():
        temporary = receipt_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
        temporary.replace(receipt_path)
    save()
    try:
        args.lock.mkdir()  # Atomic cross-ticket ownership; never reuse another process's lock.
    except FileExistsError:
        receipt["status"] = "busy"
        save()
        return
    (args.lock / "owner").write_text(f"W7-C14 {args.output}\n")
    release = True
    stage = app_stage("excel")
    try:
        for offset in range(len(cases)):
            if cases[offset]["id"] in receipt["cases"]:
                continue
            batch = []
            for index, case in enumerate(cases[offset:offset + 1], offset):
                row = dict(case, file=str(args.output / f"case-{index:04}.xlsx"))
                batch.append(row)
            payload = args.output / f"batch-{offset:04}.json"
            payload.write_text(json.dumps({"cases": batch}, ensure_ascii=False))
            shutil.copyfile(payload, stage / payload.name)
            if digest(payload) != digest(stage / payload.name): raise RuntimeError("staged payload hash mismatch")
            command = ["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript", "-l", "JavaScript", str(args.script), str(stage / payload.name)]
            try:
                before_workbooks = workbook_identities(args.script)
                # Creating a new workbook must not discard existing unsaved/recovered work.
                # Refuse it rather than treating a raw count or saved-only roster as custody.
                if any(not identity[1] for identity in before_workbooks):
                    raise RuntimeError("Foreign unsaved or recovered workbook is open")
                release = False
                process = subprocess.run(command, capture_output=True, text=True, timeout=130)
            except subprocess.TimeoutExpired:
                receipt["status"] = "timed-out"
                release = False
                raise
            log = args.output / f"batch-{offset:04}.log"
            log.write_text(process.stdout + process.stderr)
            if process.returncode != 0:
                receipt["status"] = "timed-out" if process.returncode in (-14, 142) else "driver-error"
                release = False
                raise RuntimeError(f"osascript exited {process.returncode}; inspect {log}")
            report = json.loads(process.stdout)
            receipt["batches"].append(dict(input_sha256=digest(payload), report=report))
            receipt["app_version"] = report["version"]
            # JXA's workbook specifier becomes stale after save-as. Use the
            # proven native AppleScript close door with both name AND path bound.
            result = report["cases"][0]
            remaining = report["finalWorkbooks"]
            saved = None
            if result.get("workbookName") is not None:
                if result["status"] in ("ok", "formula-rejected"):
                    saved = stage / Path(batch[0]["file"]).name
                    cleanup = ["/usr/bin/perl", "-e", "alarm 120; exec @ARGV",
                               "/usr/bin/osascript", str(args.script.with_name("save_excel.applescript")),
                               result["workbookName"], str(saved), Path(batch[0]["file"]).name]
                else:
                    cleanup = ["/usr/bin/perl", "-e", "alarm 120; exec @ARGV",
                               "/usr/bin/osascript", str(args.script.with_name("close_excel.applescript")),
                               result["workbookName"], ""]
                try:
                    closed = subprocess.run(cleanup, capture_output=True, text=True, timeout=130)
                    (args.output / f"close-{offset:04}.log").write_text(closed.stdout + closed.stderr)
                    if closed.returncode != 0:
                        raise RuntimeError("native Excel close refused")
                    remaining = int(closed.stdout.strip())
                    if saved is not None:
                        shutil.move(saved, batch[0]["file"])
                except Exception:
                    release = False
                    raise
            report["afterCleanupWorkbooks"] = remaining
            after_workbooks = workbook_identities(args.script)
            report["workbooksBefore"] = before_workbooks
            report["workbooksAfter"] = after_workbooks
            if before_workbooks != after_workbooks:
                release = False
                raise RuntimeError("Office workbook identities changed")
            release = True
            if report.get("error"):
                raise RuntimeError("Excel case failed; owned workbook cleaned")
            if previous is not None and report["version"] != previous["app_version"]:
                raise RuntimeError("Excel version changed during reused corpus run")
            for case, result in zip(batch, report["cases"], strict=True):
                path = Path(case["file"])
                values = cached_cells(path)
                if result["canary"] != 3333 or values.get("Z1") != 3333 or result["date1904"]:
                    raise RuntimeError("untrusted recalc or unexpected calendar mode")
                validate_setup(case, values)
                value = result_value(case, values)
                status = result["status"]
                if status == "ok" and value is None:
                    status = "missing-cache"
                receipt["cases"][case["id"]] = {
                    "status": status, "value": value,
                    "output_sha256": digest(path), "file": path.name,
                    "formula_rejection": result.get("formulaError"), "canary": 3333,
                }
            save()
        receipt["status"] = "completed"
    except Exception as error:
        if receipt["status"] == "running":
            receipt["status"] = "failed"
        receipt["error"] = str(error)
        raise
    finally:
        receipt["finished_at"] = time.time()
        receipt["lock_retained"] = not release
        save()
        receipt["stage"] = str(stage)
        save()
        if release: shutil.rmtree(stage)
        # Excel stays open between cases (a quit-and-relaunch races LaunchServices and fails with -600);
        # leave the owner's Mac clean once the corpus is done and Excel holds nothing.
        if release: subprocess.run(["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript", "-e", 'if application "Microsoft Excel" is running then tell application "Microsoft Excel" to if (count of workbooks) is 0 then quit'],
                       capture_output=True, timeout=130)
        if release:
            (args.lock / "owner").unlink()
            args.lock.rmdir()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reuse", type=Path)
    parser.add_argument("--lock", type=Path, default=Path("/Users/olety/w7-oracle/lock"))
    parser.add_argument("--limit", type=int)
    run(parser.parse_args())
