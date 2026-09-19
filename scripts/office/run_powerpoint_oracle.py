#!/usr/bin/env python3
"""One pinned PowerPoint package, under the shared Office lock."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from run_word_oracle import preflight, digest, app_stage


def run(args):
    if sys.platform != "darwin":
        raise RuntimeError("PowerPoint oracle needs the Office Mac")
    checksum = preflight(args.input, "ppt")
    args.output.mkdir(parents=True, exist_ok=False)
    receipt = {"status": "running", "input_sha256": checksum, "script_sha256": digest(args.script), "started_at": time.time()}
    def save():
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    save()
    args.lock.mkdir()
    (args.lock / "owner").write_text(f"W7-C14 PowerPoint {args.output}\n")
    release = False
    stage = None
    try:
        pptx = args.output / "roundtrip.pptx"
        pdf = args.output / "roundtrip.pdf"
        stage = app_stage("ppt")
        staged = stage / args.input.name
        shutil.copyfile(args.input, staged)
        if preflight(staged, "ppt") != checksum: raise RuntimeError("staged input hash mismatch")
        command = ["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript", str(args.script), str(staged), str(stage / pptx.name), str(stage / pdf.name)]
        process = subprocess.run(command, capture_output=True, text=True, timeout=130)
        (args.output / "driver.log").write_text(process.stdout + process.stderr)
        if process.returncode != 0:
            receipt["status"] = "timed-out" if process.returncode in (-14, 142) else "driver-error"
            raise RuntimeError(f"PowerPoint driver refused: {process.returncode}")
        version, slides, initial, final = process.stdout.strip().split("\t")
        if initial != final:
            raise RuntimeError("PowerPoint presentation count changed")
        shutil.move(stage / pptx.name, pptx)
        shutil.move(stage / pdf.name, pdf)
        release = True
        receipt.update({"status": "completed", "app_version": version, "slides": int(slides), "initial_presentations": int(initial), "final_presentations": int(final), "output_sha256": preflight(pptx, "ppt"), "pdf_sha256": digest(pdf)})
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
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=Path("/Users/olety/w7-oracle/lock"))
    run(parser.parse_args())
