#!/usr/bin/env python3
"""Fail-closed Word/LibreOffice fixture measurement. No golden data is inferred."""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
CASES = {
    "poi-tracking-on": ("apache/poi", "942d95d85b15d0dfdb3bc9ba1b4f273f277757c8", "test-data/document/bug56075-changeTracking_on.docx"),
    "poi-tracking-off": ("apache/poi", "942d95d85b15d0dfdb3bc9ba1b4f273f277757c8", "test-data/document/bug56075-changeTracking_off.docx"),
    "poi-protected-tracked": ("apache/poi", "942d95d85b15d0dfdb3bc9ba1b4f273f277757c8", "test-data/document/documentProtection_trackedChanges_no_password.docx"),
    "docx4j-compare-left": ("plutext/docx4j", "882f2d2cc72cae794f9e4be4a8712afa948ef309", "docx4j-samples-docx-diffx/sample-docs/test.docx"),
    "docx4j-compare-right": ("plutext/docx4j", "882f2d2cc72cae794f9e4be4a8712afa948ef309", "docx4j-samples-docx-diffx/sample-docs/test2.docx"),
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def summarize(path):
    """Parse the document and settings, never equating archive hashes to repairs."""
    with zipfile.ZipFile(path) as z:
        names = sorted(z.namelist())
        if len(names) != len(set(names)) or "word/document.xml" not in names or "[Content_Types].xml" not in names:
            raise ValueError("invalid DOCX package spine or duplicate part")
        root = ET.fromstring(z.read("word/document.xml"))
        # Word can split or merge runs on save without changing any visible
        # characters. Compare logical text per paragraph, not text-node cuts.
        text_tags = {f"{{{WORD}}}t", f"{{{WORD}}}delText"}
        paragraph_text = [
            "".join(e.text or "" for e in paragraph.iter() if e.tag in text_tags)
            for paragraph in root.iter(f"{{{WORD}}}p")
        ]
        revisions = {tag: sum(e.tag == f"{{{WORD}}}{tag}" for e in root.iter()) for tag in ("ins", "del")}
        comments = {tag: sum(e.tag == f"{{{WORD}}}{tag}" for e in root.iter()) for tag in ("commentRangeStart", "commentRangeEnd")}
        protection = None
        if "word/settings.xml" in names:
            settings = ET.fromstring(z.read("word/settings.xml"))
            for e in settings.iter(f"{{{WORD}}}documentProtection"):
                protection = e.get(f"{{{WORD}}}edit")
        return {"parts": len(names), "text_sha256": digest("\n".join(paragraph_text).encode()),
                "paragraphs": sum(e.tag == f"{{{WORD}}}p" for e in root.iter()),
                "revisions": revisions, "comments": comments, "protection": protection,
                "document_xml_sha256": digest(z.read("word/document.xml"))}

def acquire(directory):
    directory.mkdir(parents=True, exist_ok=True)
    import urllib.request
    receipts = []
    for name, (repo, commit, rel) in CASES.items():
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/{rel}"
        with urllib.request.urlopen(url, timeout=30) as stream:
            data = stream.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise ValueError(f"fixture too large: {name}")
        dst = directory / f"{name}.docx"
        dst.write_bytes(data)
        receipts.append({"name": name, "url": url, "sha256": digest(data), "summary": summarize(dst)})
    (directory / "sources.json").write_text(json.dumps(receipts, indent=2) + "\n")
    return receipts

def lo_roundtrip(inputs, output):
    soffice = shutil.which("libreoffice") or shutil.which("soffice")
    if not soffice:
        raise RuntimeError("LibreOffice not installed: no baseline measured")
    output.mkdir(parents=True, exist_ok=True)
    records = []
    for src in sorted(inputs.glob("*.docx")):
        with tempfile.TemporaryDirectory(prefix="oneiron-lo-") as temp:
            work = Path(temp) / "input"
            work.mkdir()
            staged = work / src.name
            shutil.copyfile(src, staged)
            dest = Path(temp) / "output"
            dest.mkdir()
            profile = (Path(temp) / "profile").as_uri()
            command = [soffice, f"-env:UserInstallation={profile}", "--headless", "--convert-to", "docx", "--outdir", str(dest), str(staged)]
            run = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
            result = dest / staged.name
            if run.returncode or not result.exists():
                records.append({"name": src.name, "status": "failed", "returncode": run.returncode,
                                "stderr": run.stderr[-1000:]})
                continue
            final = output / src.name
            shutil.copyfile(result, final)
            records.append({"name": src.name, "status": "output_unscored_without_word_oracle",
                            "input_sha256": digest(src.read_bytes()), "output_sha256": digest(final.read_bytes()),
                            "input": summarize(src), "output": summarize(final)})
    (output / "lo-receipt.json").write_text(json.dumps({"tool": soffice, "cases": records,
        "rate": None, "reason": "Word for Mac golden outcomes not supplied"}, indent=2) + "\n")
    return records

def word_receipt(src, saved, output, repair_observed):
    if platform.system() != "Darwin":
        raise RuntimeError("Word oracle must run on the owner's Word-for-Mac host")
    if repair_observed not in ("yes", "no"):
        raise ValueError("operator must explicitly report the observed Word repair dialog")
    if not saved.exists() or src.resolve() == saved.resolve():
        raise ValueError("Word must save a separate staged copy of the input")
    before, after = summarize(src), summarize(saved)
    result = {"input_sha256": digest(src.read_bytes()), "saved_sha256": digest(saved.read_bytes()),
              "before": before, "after": after, "repair_observed": repair_observed,
              "status": "repair_observed" if repair_observed == "yes" else "operator_no_repair_observed_semantics_need_review"}
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("acquire", "lo", "word"):
        cmd = sub.add_parser(action)
        if action == "acquire": cmd.add_argument("directory", type=Path)
        elif action == "lo":
            cmd.add_argument("inputs", type=Path); cmd.add_argument("output", type=Path)
        else:
            cmd.add_argument("input", type=Path); cmd.add_argument("saved_copy", type=Path)
            cmd.add_argument("receipt", type=Path)
            cmd.add_argument("--repair-observed", choices=("yes", "no"), required=True)
    args = parser.parse_args()
    try:
        if args.action == "acquire": result = acquire(args.directory)
        elif args.action == "lo": result = lo_roundtrip(args.inputs, args.output)
        else: result = word_receipt(args.input, args.saved_copy, args.receipt, args.repair_observed)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, ET.ParseError, subprocess.TimeoutExpired) as error:
        parser.exit(2, f"oracle not verified: {error}\n")
    print(json.dumps(result, indent=2))
if __name__ == "__main__": main()
