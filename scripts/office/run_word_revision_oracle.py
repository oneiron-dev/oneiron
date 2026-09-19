#!/usr/bin/env python3
"""Observe native Word revision semantics without saving over the input."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from run_word_oracle import preflight, digest


def run(args):
    if sys.platform != "darwin":
        raise RuntimeError("Word revision oracle needs the Office Mac")
    input_hash = preflight(args.input)
    args.output.mkdir(parents=True, exist_ok=False)
    receipt = {"status": "running", "input_sha256": input_hash, "script_sha256": digest(args.script),
               "action": args.action, "started_at": time.time()}
    def save():
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    save()
    args.lock.mkdir()
    (args.lock / "owner").write_text(f"W7-C14 Word revisions {args.output}\n")
    release = False
    try:
        text = args.output / "resolved.txt"
        process = subprocess.run(["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript",
                                  str(args.script), str(args.input), args.action, str(text)],
                                 capture_output=True, text=True, timeout=130)
        (args.output / "driver.log").write_text(process.stdout + process.stderr)
        if process.returncode:
            receipt["status"] = "timed-out" if process.returncode in (-14, 142) else "driver-error"
            raise RuntimeError(f"Word revision driver refused: {process.returncode}")
        version, before, after, paragraphs, initial, final = process.stdout.strip().split("\t")
        if initial != final:
            raise RuntimeError("Word document count changed")
        release = True
        if int(after) != 0 or preflight(args.input) != input_hash:
            raise RuntimeError("Word did not resolve all revisions or changed the input")
        receipt.update(status="completed", app_version=version, before_revisions=int(before),
                       after_revisions=int(after), paragraphs=int(paragraphs),
                       initial_documents=int(initial), final_documents=int(final), repair_requested=False,
                       resolved_text=text.read_text(), resolved_text_sha256=digest(text))
        if args.expected is not None:
            expected = args.expected.read_text()
            receipt.update(expected_sha256=digest(args.expected), matches_expected=receipt["resolved_text"] == expected)
            if not receipt["matches_expected"]:
                receipt["status"] = "mismatch"
                raise RuntimeError("Word revision result differs from the authored expectation")
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
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--action", choices=("accept", "reject"), required=True)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--lock", type=Path, default=Path("/Users/olety/w7-oracle/lock"))
    run(parser.parse_args())
