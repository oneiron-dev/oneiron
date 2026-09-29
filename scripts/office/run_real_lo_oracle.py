#!/usr/bin/env python3
"""Recalculate real XLSX corpus inputs in an isolated LibreOffice profile."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import signal
import subprocess
import time
import zipfile
import xml.etree.ElementTree as ET

from run_real_excel_oracle import preflight


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clear_formula_caches(source, destination):
    """Remove formula-cell caches only; leave formula/input/unknown XML bytes intact."""
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(destination, "w") as out:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename.startswith("xl/worksheets/") and item.filename.endswith(".xml"):
                tree = ET.fromstring(data)
                cells = {c.get("r") for c in tree.iter("{" + main + "}c") if c.find("{" + main + "}f") is not None}
                found = set()
                def scrub(match):
                    tag, header, body = match.group("tag", "header", "body")
                    address = re.search(rb"\br=[\"']([^\"']+)[\"']", header)
                    if address is None or address[1].decode() not in cells:
                        return match[0]
                    found.add(address[1].decode())
                    prefix = re.escape(tag[:-1])
                    body = re.sub(rb"<" + prefix + rb"(?:v|is)(?:\s[^>]*)?/>|<" + prefix + rb"(?:v|is)(?:\s[^>]*)?>.*?</" + prefix + rb"(?:v|is)>", b"", body, flags=re.S)
                    header = re.sub(rb"\s+t=([\"']).*?\1", b"", header)
                    return b"<" + tag + header + b">" + body + b"</" + tag + b">"
                data = re.sub(rb"<(?P<tag>(?:[A-Za-z_][\w.-]*:)?c)(?P<header>\s[^>]*?)(?<!/)>(?P<body>.*?)</(?P=tag)>", scrub, data, flags=re.S)
                if not cells.issubset(found):
                    raise ValueError("unrecognized formula cell XML")
            out.writestr(item, data)


def run(args):
    args.output.mkdir(parents=True, exist_ok=True)
    version = subprocess.run([str(args.soffice), "--version"], capture_output=True, text=True, check=True).stdout.strip()
    identity = dict(manifest_sha256=digest(args.manifest), runner_sha256=digest(Path(__file__)),
                    preflight_sha256=digest(Path(__file__).with_name("run_real_excel_oracle.py")), engine=version)
    pin = args.output / "identity.json"
    if pin.exists() and json.loads(pin.read_text()) != identity:
        raise ValueError("LibreOffice measurement identity changed")
    pin.write_text(json.dumps(identity, indent=2) + "\n")
    entries = [json.loads(line) for line in args.manifest.read_text().splitlines()]
    rows_path = args.output / "rows.jsonl"
    rows = [json.loads(line) for line in rows_path.read_text().splitlines()] if rows_path.exists() else []
    done = {row["sha256"] for row in rows}
    sources, outputs = args.output / "input", args.output / "workbooks"
    sources.mkdir(exist_ok=True); outputs.mkdir(exist_ok=True)
    profile = (args.output / "profile").resolve().as_uri()
    for entry in entries:
        if entry["sha256"] in done: continue
        source = (args.corpus / entry["path"]).resolve()
        if not source.is_relative_to(args.corpus.resolve()): raise ValueError("manifest escapes corpus")
        row = dict(sha256=entry["sha256"], path=entry["path"], recalc=dict(ok=False))
        try:
            if preflight(source) != entry["sha256"]: raise RuntimeError("source hash mismatch")
            staged = sources / (entry["sha256"] + ".xlsx")
            clear_formula_caches(source, staged)
            output = outputs / staged.name
            if output.exists(): output.unlink()
            command = [str(args.soffice), "-env:UserInstallation=" + profile, "--headless", "--convert-to", "xlsx:Calc MS Excel 2007 XML", "--outdir", str(outputs), str(staged)]
            start = time.monotonic()
            with (args.output / (entry["sha256"] + ".driver.log")).open("w") as log:
                child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = child.wait(timeout=120)
                    row["recalc"] = dict(ok=code == 0 and output.is_file(), exit_code=code)
                except subprocess.TimeoutExpired:
                    # Only this invocation's isolated profile/process group, never a GUI instance.
                    import os
                    os.killpg(child.pid, signal.SIGTERM)
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL); child.wait()
                    row["recalc"] = dict(ok=False, error="timed-out")
            row["seconds"] = time.monotonic() - start
            if row["recalc"]["ok"]: row["output_sha256"] = preflight(output)
            staged.unlink()
        except (ValueError, KeyError, zipfile.BadZipFile, ET.ParseError) as error:
            row["recalc"] = dict(ok=False, error=type(error).__name__, detail=str(error))
        with rows_path.open("a") as stream: stream.write(json.dumps(row) + "\n")
        done.add(entry["sha256"])
        print(len(done), len(entries), row["recalc"]["ok"], entry["sha256"], flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ["corpus", "manifest", "output"]: parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--soffice", type=Path, default=Path("/Applications/LibreOffice.app/Contents/MacOS/soffice"))
    run(parser.parse_args())
