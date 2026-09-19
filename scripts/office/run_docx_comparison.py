#!/usr/bin/env python3
"""Compare retained DOCX proposals with LibreOffice on the same edited inputs.

This measures preservation of the supported edit set, not broad DOCX coverage.
The native corpus report retains every refusal separately. Word owns the truth:
resolved text, paragraph boundaries and pending revision counts. No Office file
is opened before ZIP/XML/hash preflight; unsafe external-link inputs are unscored.
"""
import argparse
import json
from argparse import Namespace
from pathlib import Path
import shutil
import subprocess
import time
from run_word_oracle import preflight, digest
from run_word_revision_oracle import run as word


def run(args):
    native = json.loads(args.report.read_bytes())
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"status": "running", "measurement": "same-edit-preservation-not-total-docx-coverage",
              "native_report_sha256": digest(args.report), "native_counts": native["counts"],
              "runner_sha256": digest(Path(__file__)), "started_at": time.time(), "cases": {}}
    report["libreoffice_version"] = subprocess.run([str(args.soffice), "--version"], capture_output=True, text=True, check=True).stdout.strip()
    def save():
        (args.output / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")
    save()
    try:
        for index, entry in enumerate(native["entries"]):
            case = {"native_status": entry["status"], "scored": False}
            report["cases"][entry["input"]] = case
            if entry["status"] != "proposed_native_only":
                case["status"] = "native-refusal"
                save()
                continue
            source = args.report.parent / entry["output"]
            try:
                case["input_sha256"] = preflight(source)
            except ValueError as error:
                case.update(status="preflight-refused", reason=str(error))
                save()
                continue
            directory = args.output / f"case-{index:03}"
            directory.mkdir()
            native_input = directory / "input.docx"
            shutil.copyfile(source, native_input)
            output = directory / "libreoffice"
            output.mkdir()
            profile = (directory / "profile").resolve().as_uri()
            process = subprocess.run([str(args.soffice), f"-env:UserInstallation={profile}", "--headless",
                                      "--convert-to", "docx:Office Open XML Text", "--outdir", str(output),
                                      str(native_input)], capture_output=True, text=True, timeout=120)
            (directory / "libreoffice.log").write_text(process.stdout + process.stderr)
            receipts = {}
            for engine, path in (("native", native_input), ("libreoffice", output / "input.docx")):
                if not path.is_file():
                    receipts[engine] = {"status": "missing-output"}
                    continue
                try:
                    preflight(path)
                except ValueError as error:
                    receipts[engine] = {"status": "preflight-refused", "reason": str(error)}
                    continue
                oracle = directory / f"word-{engine}"
                word(Namespace(input=path, output=oracle, script=args.script, action="accept", expected=None, lock=args.lock))
                receipts[engine] = json.loads((oracle / "receipt.json").read_bytes())
            case["word"] = receipts
            case["scored"] = receipts.get("native", {}).get("status") == "completed"
            native_result = receipts.get("native", {})
            lo = receipts.get("libreoffice", {})
            case["native_pass"] = case["scored"]
            case["libreoffice_pass"] = bool(case["scored"] and lo.get("status") == "completed" and all(
                lo.get(key) == native_result.get(key) for key in ("resolved_text", "paragraphs", "before_revisions")))
            case["status"] = "completed"
            save()
        scored = [case for case in report["cases"].values() if case["scored"]]
        report["counts"] = {"scored": len(scored), "native_pass": sum(case["native_pass"] for case in scored),
                            "libreoffice_pass": sum(case["libreoffice_pass"] for case in scored)}
        report["status"] = "completed"
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        report["finished_at"] = time.time()
        save()
        # Word stays open between oracle calls (a quit-and-relaunch races LaunchServices and fails with -600);
        # leave the owner's Mac clean when the run is over and Word holds nothing.
        if report["status"] == "completed":
            try:
                args.lock.mkdir()
            except FileExistsError:
                pass  # Another Office caller owns custody; do not quit under it.
            else:
                owner = f"W7-C14 Word corpus shutdown {args.output}"
                (args.lock / "owner").write_text(owner + "\n")
                shutdown = subprocess.run(["/usr/bin/perl", "-e", "alarm 120; exec @ARGV", "/usr/bin/osascript", "-e", 'if application "Microsoft Word" is running then tell application "Microsoft Word" to if (count of documents) is 0 then quit'], capture_output=True, text=True, timeout=130)
                if shutdown.returncode:
                    raise RuntimeError("Word shutdown failed; custody lock retained")
                if (args.lock / "owner").read_text().strip() != owner:
                    raise RuntimeError("Office lock ownership changed")
                (args.lock / "owner").unlink()
                args.lock.rmdir()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=Path("/Users/olety/w7-oracle/lock"))
    parser.add_argument("--soffice", type=Path, default=Path("/Applications/LibreOffice.app/Contents/MacOS/soffice"))
    run(parser.parse_args())
