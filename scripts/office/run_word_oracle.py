#!/usr/bin/env python3
"""Word zero-repair oracle; only validated ZIP inputs under an exclusive Office lock."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile
import xml.etree.ElementTree as ET

CONTAINERS = {"word": "com.microsoft.Word", "excel": "com.microsoft.Excel", "ppt": "com.microsoft.Powerpoint"}


def app_stage(app="word"):
    """A fresh folder inside that Office app's sandbox container.

    Word, Excel and PowerPoint are sandboxed apart from Full Disk Access: a path that AppleScript opens or saves
    outside the app's own container raises the Grant File Access prompt every time. Paths inside the container are
    silent, so each oracle copies its input here, points the app at the copy and moves any app-written result back."""
    stage = Path.home() / "Library/Containers" / CONTAINERS[app] / "Data/tmp/w7-oracle" / f"{time.time_ns()}-{os.getpid()}"
    stage.mkdir(parents=True)
    return stage


def word_stage():
    return app_stage("word")


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
    stage = None
    try:
        output = args.output / "roundtrip.docx"
        pdf = args.output / "roundtrip.pdf"
        stage = word_stage()
        staged = stage / args.input.name
        shutil.copyfile(args.input, staged)
        if preflight(staged) != input_hash: raise RuntimeError("staged input hash mismatch")
        command = ["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript", str(args.script), str(staged), str(stage / output.name), str(stage / pdf.name)]
        process = subprocess.run(command, capture_output=True, text=True, timeout=130)
        (args.output / "driver.log").write_text(process.stdout + process.stderr)
        if process.returncode != 0:
            receipt["status"] = "timed-out" if process.returncode in (-14, 142) else "driver-error"
            raise RuntimeError(f"Word driver refused: {process.returncode}")
        version, revisions, comments, paragraphs, initial, final = process.stdout.strip().split("\t")
        if initial != final:
            raise RuntimeError("Word document count changed")
        shutil.move(stage / output.name, output)
        shutil.move(stage / pdf.name, pdf)
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
        receipt["stage"] = str(stage) if stage is not None else None
        receipt["finished_at"] = time.time()
        save()
        if stage is not None and release:
            shutil.rmtree(stage)
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
