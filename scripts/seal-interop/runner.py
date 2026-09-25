#!/usr/bin/env python3
"""Run pinned PDF reader wrappers and normalize each result to a stable TSV row."""
import json, os, platform, shutil, subprocess, sys
from pathlib import Path

DEFAULT_HOME = Path("/mnt/wd16/w8-build/seal-interop")
HOME = Path(os.environ.get("SEAL_INTEROP_HOME", DEFAULT_HOME))
REPO = Path(__file__).resolve().parents[2]
BIN = HOME / "bin"
ALL = ["poppler-22.02", "poppler-24.02", "poppler-25.02", "poppler-26.05", "dss", "pdfbox", "pyhanko", "pdfium", "pdfjs", "qpdf"]
WRAPPERS = {
    "dss": ("SEAL_DSS_BIN", BIN / "seal-dss"),
    "pdfbox": ("SEAL_PDFBOX_BIN", BIN / "seal-pdfbox"),
    "pyhanko": ("SEAL_PYHANKO_BIN", BIN / "seal-pyhanko"),
    "pdfium": ("SEAL_PDFIUM_BIN", BIN / "seal-pdfium"),
    "pdfjs": ("SEAL_PDFJS_BIN", BIN / "seal-pdfjs"),
    "qpdf": ("SEAL_QPDF_BIN", BIN / "seal-qpdf"),
    "poppler-22.02": ("", BIN / "seal-poppler-22.02"),
    "poppler-24.02": ("", BIN / "seal-poppler-24.02"),
    "poppler-25.02": ("", BIN / "seal-poppler-25.02"),
    "poppler-26.05": ("", BIN / "seal-poppler-26.05"),
}

def os_proxy():
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return "linux-x86_64/" + line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return f"linux-x86_64/{platform.system()}-{platform.release()}"

def emit(reader, pdf):
    envvar, default = WRAPPERS[reader]
    path = Path(os.environ.get(envvar, default)) if envvar else default
    if not path.exists() or not os.access(path, os.X_OK):
        obj = {"reader": reader, "version": "unavailable", "os_proxy": os_proxy(),
               "mode": "verify" if reader in ("dss", "pdfbox", "pyhanko") or reader.startswith("poppler-") else ("check" if reader == "qpdf" else "parse"),
               "status": "unavailable", "detail": f"wrapper missing: {path}"}
        print("\t".join(str(obj[k]) for k in ("reader", "version", "os_proxy", "mode", "status", "detail")))
        return 77
    p = subprocess.run([str(path), str(pdf)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.stderr:
        print(p.stderr, file=sys.stderr, end="" if p.stderr.endswith("\n") else "\n")
    try:
        result = json.loads(p.stdout)
    except Exception:
        print(f"{reader}: wrapper output is not JSON: {p.stdout!r}", file=sys.stderr)
        result = {"reader": reader, "version": "unknown", "mode": "unknown", "status": "fail", "detail": "invalid wrapper output"}
        p.returncode = p.returncode or 1
    result.setdefault("reader", reader)
    result.setdefault("version", "unknown")
    result.setdefault("os_proxy", os_proxy())
    result.setdefault("mode", "unknown")
    result.setdefault("status", "fail")
    result.setdefault("detail", "")
    print("\t".join(str(result[k]).replace("\t", " ").replace("\n", " ") for k in ("reader", "version", "os_proxy", "mode", "status", "detail")))
    return p.returncode

def main(argv):
    if len(argv) == 4 and argv[1] == "--reader":
        chosen, pdf = [argv[2]], argv[3]
    elif len(argv) == 2:
        chosen, pdf = ALL, argv[1]
        print("reader\tversion\tos_proxy\tmode\tstatus\tdetail")
    else:
        print("usage: runner.py [--reader NAME] PDF", file=sys.stderr); return 2
    if not Path(pdf).is_file():
        print(f"PDF not found: {pdf}", file=sys.stderr); return 2
    bad = 0
    skipped = 0
    for name in chosen:
        if name not in WRAPPERS:
            print(f"unknown reader {name}; choose from {', '.join(ALL)}", file=sys.stderr); return 2
        code = emit(name, pdf)
        if code == 77: skipped += 1
        elif code != 0: bad += 1
    if bad: return 1
    return 77 if len(chosen) == 1 and skipped else 0

if __name__ == "__main__": raise SystemExit(main(sys.argv))
