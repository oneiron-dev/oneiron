#!/usr/bin/env python3
"""Word zero-repair oracle; only validated ZIP inputs under an exclusive Office lock."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import zipfile
import xml.etree.ElementTree as ET


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preflight(path, kind="word"):
    if not path.is_file():
        raise ValueError("missing oracle input")
    checksum = digest(path)
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError("broken oracle ZIP")
        required = {"[Content_Types].xml", "_rels/.rels", "word/document.xml" if kind == "word" else "ppt/presentation.xml"}
        if not required.issubset(archive.namelist()):
            raise ValueError("incomplete DOCX package")
        for name in archive.namelist():
            if name.endswith((".xml", ".rels")):
                root = ET.fromstring(archive.read(name))
                if name.endswith(".rels"):
                    for relation in root:
                        if relation.get("TargetMode") == "External":
                            raise ValueError("oracle input has an external link")
            if name.lower().endswith("vbaproject.bin"):
                raise ValueError("oracle input has macros")
    return checksum


def run(args):
    if sys.platform != "darwin":
        raise RuntimeError("Word oracle must run on the Mac")
    input_hash = preflight(args.input)
    args.output.mkdir(parents=True, exist_ok=False)
    receipt = {"status": "running", "input_sha256": input_hash, "script_sha256": digest(args.script), "started_at": time.time()}
    def save():
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    save()
    args.lock.mkdir()
    (args.lock / "owner").write_text(f"W7-C14 Word {args.output}\n")
    release = False
    try:
        output = args.output / "roundtrip.docx"
        pdf = args.output / "roundtrip.pdf"
        command = ["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript", str(args.script), str(args.input), str(output), str(pdf)]
        process = subprocess.run(command, capture_output=True, text=True, timeout=130)
        (args.output / "driver.log").write_text(process.stdout + process.stderr)
        if process.returncode != 0:
            receipt["status"] = "timed-out" if process.returncode in (-14, 142) else "driver-error"
            raise RuntimeError(f"Word driver refused: {process.returncode}")
        version, revisions, comments, paragraphs, initial, final = process.stdout.strip().split("\t")
        if initial != final:
            raise RuntimeError("Word document count changed")
        release = True
        receipt.update({"app_version": version, "revisions": int(revisions), "comments": int(comments), "paragraphs": int(paragraphs), "initial_documents": int(initial), "final_documents": int(final), "repair_requested": False,
                        "output_sha256": preflight(output), "pdf_sha256": digest(pdf), "status": "completed"})
    except subprocess.TimeoutExpired:
        receipt["status"] = "timed-out"
        raise
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        receipt["lock_retained"] = not release
        receipt["finished_at"] = time.time()
        save()
        if release:
            (args.lock / "owner").unlink()
            args.lock.rmdir()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--script", required=True, type=Path)
    parser.add_argument("--lock", type=Path, default=Path("/Users/olety/w7-oracle/lock"))
    run(parser.parse_args())
