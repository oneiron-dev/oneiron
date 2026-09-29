#!/usr/bin/env python3
"""Recalculate the same native Excel inputs in an isolated LibreOffice profile.

Cached formula/output cells are removed first; a stored recalc canary must return.
No Office app is opened. Inputs are copied only after the Excel receipt hashes them.
"""
import argparse
import hashlib
import io
import json
import re
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET
import zipfile

from run_excel_oracle import NS, address, cached_cells, coordinate, result_value


def without_cached_results(data, case):
    start, _, end = case.get("check_range", "F1").partition(":")
    sr, sc = coordinate(start)
    er, ec = coordinate(end or start)
    output_cells = {address(r, c) for r in range(sr, er + 1) for c in range(sc, ec + 1)}
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(output, "w") as target:
        for info in source.infolist():
            part = source.read(info.filename)
            if info.filename == "xl/worksheets/sheet1.xml":
                tree = ET.fromstring(part)
                clear = {cell.get("r") for cell in tree.findall(".//s:sheetData/s:row/s:c", NS)
                         if cell.find("s:f", NS) is not None or cell.get("r") in output_cells}
                found = set()
                def scrub(match):
                    tag, header, body = match.group("tag", "header", "body")
                    cell_ref = re.search(rb'\br="([A-Z]+[1-9][0-9]*)"', header)
                    if cell_ref is None or cell_ref[1].decode() not in clear:
                        return match[0]
                    found.add(cell_ref[1].decode())
                    prefix = tag[:-1]  # c / s:c -> empty / s:
                    value_tag = re.escape(prefix) + rb'(?:v|is)'
                    body = re.sub(rb'<' + value_tag + rb'(?:\s[^>]*)?/>|<' + value_tag + rb'(?:\s[^>]*)?>.*?</' + value_tag + rb'>', b'', body, flags=re.S)
                    header = re.sub(rb'\s+t="[^"]*"', b'', header)
                    return b'<' + tag + header + b'>' + body + b'</' + tag + b'>'
                # Excel-owned XML uses double-quoted attributes. Only cache-cell
                # bytes change; namespace declarations and unknown XML stay put.
                part = re.sub(rb'<(?P<tag>(?:[A-Za-z_][\w.-]*:)?c)(?P<header>\s[^>]*?)(?<!/)>(?P<body>.*?)</(?P=tag)>', scrub, part, flags=re.S)
                if not clear.issubset(found):
                    # Empty cells have no cache to remove.
                    nonempty = {cell.get("r") for cell in tree.findall(".//s:sheetData/s:row/s:c", NS)
                                if cell.find("s:v", NS) is not None or cell.find("s:is", NS) is not None or cell.find("s:f", NS) is not None}
                    if (clear & nonempty) - found:
                        raise ValueError("unrecognized Excel cache cell serialization")
            target.writestr(info, part)
    return output.getvalue()


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    sources = args.output / "input"
    results = args.output / "output"
    sources.mkdir()
    results.mkdir()
    cases = {c["id"]: c for c in json.loads(args.cases.read_bytes())}
    raw = args.excel_receipt.read_bytes()
    excel = json.loads(raw)
    version = subprocess.run([str(args.soffice), "--version"], capture_output=True, text=True, check=True).stdout.strip()
    report = {"status": "running", "engine": version, "started_at": time.time(),
              "excel_receipt_sha256": hashlib.sha256(raw).hexdigest(),
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": {}}
    def save():
        temporary = args.output / "receipt.tmp"
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        temporary.replace(args.output / "receipt.json")
    previous = None
    if args.reuse is not None:
        previous = json.loads(args.reuse.read_bytes())
        if previous["status"] != "completed" or previous["engine"] != version or previous["runner_sha256"] != report["runner_sha256"]:
            raise ValueError("baseline reuse version mismatch")
        report["reused_receipt_sha256"] = hashlib.sha256(args.reuse.read_bytes()).hexdigest()
    save()
    try:
        eligible = []
        for case_id, golden in excel["cases"].items():
            if golden["status"] != "ok":
                report["cases"][case_id] = {"status": "no-excel-golden"}
                continue
            data = (args.excel_receipt.parent / golden["file"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != golden["output_sha256"]:
                raise ValueError("Excel output hash mismatch")
            path = sources / golden["file"]
            scrubbed = without_cached_results(data, cases[case_id])
            input_hash = hashlib.sha256(scrubbed).hexdigest()
            old = previous["cases"].get(case_id) if previous is not None else None
            if old is not None and old.get("input_sha256") == input_hash and old.get("output_sha256"):
                cached = (args.reuse.parent / "output" / old["file"]).read_bytes()
                if hashlib.sha256(cached).hexdigest() != old["output_sha256"]:
                    raise ValueError("baseline reused output hash mismatch")
                (results / old["file"]).write_bytes(cached)
                report["cases"][case_id] = old
                continue
            path.write_bytes(scrubbed)
            eligible.append((case_id, path, input_hash))
        profile = (args.output / "profile").resolve().as_uri()
        for offset in range(0, len(eligible), 16):
            batch = eligible[offset:offset + 16]
            command = [str(args.soffice), f"-env:UserInstallation={profile}", "--headless", "--convert-to",
                       "xlsx:Calc MS Excel 2007 XML", "--outdir", str(results)] + [str(path) for _, path, _ in batch]
            process = subprocess.run(command, capture_output=True, text=True, timeout=240)
            (args.output / f"batch-{offset:04}.log").write_text(process.stdout + process.stderr)
            for case_id, source, input_hash in batch:
                path = results / source.name
                if process.returncode != 0 or not path.is_file():
                    report["cases"][case_id] = {"status": "conversion-failed", "input_sha256": input_hash}
                    continue
                cells = cached_cells(path)
                value = result_value(cases[case_id], cells)
                status = "ok" if cells.get("Z1") == 3333 else "no-recalc"
                if status == "ok" and value is None:
                    status = "missing-cache"
                report["cases"][case_id] = {"status": status, "value": value,
                    "input_sha256": input_hash, "output_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "canary": cells.get("Z1"), "file": path.name}
            save()
        report["status"] = "completed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        report["finished_at"] = time.time()
        save()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--excel-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reuse", type=Path)
    parser.add_argument("--soffice", type=Path, default=Path("/Applications/LibreOffice.app/Contents/MacOS/soffice"))
    run(parser.parse_args())
