#!/usr/bin/env python3
"""The deck-create-v1 template: fixtures/clean.pptx without its one slide.

PowerPoint itself measures, per text unit, whether the laid-out text fits the
frame of six decks the docedit emitter writes; the receipts are committed and
a test keeps them bound to the emitter. Every one of those decks is emitted
against the same template, so the runner (deck-create-cases), the pin test
(deck_create_oracle_receipt) and a later engine test read the same bytes:
fixtures/deck-create-template.pptx, which this script makes from
fixtures/clean.pptx the way oracle_template() in
crates/oneiron-docedit/src/emit/tests.rs makes it in memory (same entry
order, stored, fixed date and mode, the slide entries dropped and the three
references to slide1 cut). --check keeps the committed file honest.

Usage: python3 -I scripts/office/make_deck_create_template.py [--check]
"""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CLEAN = ROOT / "fixtures" / "clean.pptx"
TEMPLATE = ROOT / "fixtures" / "deck-create-template.pptx"

STORED_DATE = (1980, 1, 1, 0, 0, 0)
STORED_ATTR = 0o644 << 16


def _cut_once(text: str, start: str, end: str, what: str) -> str:
    """Cut from `start` through `end`, each found exactly once."""
    at = text.find(start)
    if at < 0 or text.find(start, at + 1) >= 0:
        raise ValueError(f"{what}: {start!r} is not in the part exactly once")
    to = text.find(end, at + len(start))
    if to < 0:
        raise ValueError(f"{what}: nothing ends {start!r}")
    return text[:at] + text[to + len(end):]


def _cut_slide_rel(text: str) -> str:
    """Cut the one slide <Relationship> element, found by its Type suffix."""
    marker = 'relationships/slide"'
    at = text.find(marker)
    if at < 0 or text.find(marker, at + 1) >= 0:
        raise ValueError(f"ppt/_rels/presentation.xml.rels: {marker!r} is not in the part exactly once")
    rel = text.rfind("<Relationship ", 0, at)
    if rel < 0:
        raise ValueError("ppt/_rels/presentation.xml.rels: no <Relationship element opens the slide ref")
    end = text.find("/>", at)
    if end < 0:
        raise ValueError("ppt/_rels/presentation.xml.rels: the slide <Relationship element never ends")
    return text[:rel] + text[end + 2:]


def template_bytes(clean: bytes) -> bytes:
    """The template `oracle_template()` builds in memory, from clean.pptx's bytes."""
    with zipfile.ZipFile(io.BytesIO(clean)) as source:
        entries = [(info.filename, source.read(info.filename)) for info in source.infolist()]
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as target:
        for name, body in entries:
            if name.startswith("ppt/slides/"):
                continue
            if name == "ppt/presentation.xml":
                body = _cut_once(body.decode("utf-8"), "<p:sldIdLst>", "</p:sldIdLst>",
                                 "ppt/presentation.xml").encode("utf-8")
            elif name == "ppt/_rels/presentation.xml.rels":
                body = _cut_slide_rel(body.decode("utf-8")).encode("utf-8")
            elif name == "[Content_Types].xml":
                body = _cut_once(body.decode("utf-8"), '<Override PartName="/ppt/slides/slide1.xml"',
                                 "/>", "[Content_Types].xml").encode("utf-8")
            info = zipfile.ZipInfo(filename=name, date_time=STORED_DATE)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = STORED_ATTR
            target.writestr(info, body)
    return out.getvalue()


def main(argv: list[str]) -> int:
    if len(argv) > 1 or (argv and argv[0] != "--check"):
        print(f"usage: {Path(sys.argv[0]).name} [--check]", file=sys.stderr)
        return 2
    try:
        made = template_bytes(CLEAN.read_bytes())
    except (OSError, ValueError, zipfile.BadZipFile, UnicodeDecodeError) as exc:
        print(f"cannot build the template: {exc}", file=sys.stderr)
        return 1
    if argv:
        try:
            committed = TEMPLATE.read_bytes()
        except OSError as exc:
            print(f"--check: {TEMPLATE} does not read: {exc}", file=sys.stderr)
            return 1
        if committed != made:
            print(f"--check: {TEMPLATE} differs from what the script writes; run it without --check",
                  file=sys.stderr)
            return 1
        return 0
    TEMPLATE.write_bytes(made)
    print(f"wrote {TEMPLATE} ({len(made)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
