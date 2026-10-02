#!/usr/bin/env python3
"""Formula cells that depend on a volatile cell (NOW/TODAY/RAND/RANDBETWEEN/RANDARRAY), directly or through other
formula cells. The bench skips the volatile cell itself (vendor/xlsx_corpus_bench/cached_values.py); a cell that reads
such a cell differs between two Excel runs just the same, so no engine can match it. This module names those cells
from the truth workbook's own formulas: A1 references and ranges, sheet-qualified or not, whole columns and rows.
Dynamic references (INDIRECT/OFFSET), defined names and structured references are not followed."""
import bisect
import re
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0] + "/vendor/xlsx_corpus_bench")
from cached_values import VOLATILE  # noqa: E402

_SHEET = r"(?:(?:'((?:[^']|'')+)'|([A-Za-z0-9_.]+))!)?"
_CELL = re.compile(_SHEET + r"(?<![A-Za-z0-9_.])\$?([A-Z]{1,3})\$?([0-9]{1,7})(?::\$?([A-Z]{1,3})\$?([0-9]{1,7}))?(?![A-Za-z0-9_(])")
_COLS = re.compile(_SHEET + r"(?<![A-Za-z0-9_.])\$?([A-Z]{1,3}):\$?([A-Z]{1,3})(?![A-Za-z0-9_(])")
_ROWS = re.compile(_SHEET + r"(?<![A-Za-z0-9_.])\$?([0-9]{1,7}):\$?([0-9]{1,7})(?![A-Za-z0-9_(:])")
_STRING = re.compile(r'"(?:[^"]|"")*"')
MAX_COL, MAX_ROW = 16384, 1048576


def _col(letters):
    n = 0
    for ch in letters:
        n = n * 26 + ord(ch) - 64
    return n


def _coord(ref):
    m = re.fullmatch(r"\$?([A-Z]{1,3})\$?([0-9]+)", ref)
    return (_col(m[1]), int(m[2])) if m else None


def references(formula, own_sheet):
    """Rectangles (sheet, c1, r1, c2, r2) a formula reads."""
    text = _STRING.sub('""', formula)
    rects = []
    for m in _CELL.finditer(text):
        sheet = (m[1] or m[2] or own_sheet).replace("''", "'")
        c1, r1 = _col(m[3]), int(m[4])
        c2, r2 = (_col(m[5]), int(m[6])) if m[5] else (c1, r1)
        rects.append((sheet, min(c1, c2), min(r1, r2), max(c1, c2), max(r1, r2)))
    for m in _COLS.finditer(text):
        sheet = (m[1] or m[2] or own_sheet).replace("''", "'")
        c1, c2 = sorted((_col(m[3]), _col(m[4])))
        rects.append((sheet, c1, 1, c2, MAX_ROW))
    for m in _ROWS.finditer(text):
        sheet = (m[1] or m[2] or own_sheet).replace("''", "'")
        r1, r2 = sorted((int(m[3]), int(m[4])))
        rects.append((sheet, 1, r1, MAX_COL, r2))
    return rects


def volatile_dependents(truth):
    """Addresses ("Sheet!A1") of formula cells that read a volatile cell, directly or through other formula cells.
    The volatile cells themselves are not returned."""
    volatile, reads = set(), {}
    for addr, t in truth.items():
        formula = t[2] if len(t) > 2 else ""
        if not formula:
            continue
        sheet, _, cell = addr.rpartition("!")
        if VOLATILE.search(formula):
            volatile.add(addr)
        else:
            rects = references(formula, sheet)
            if rects:
                reads[addr] = rects
    if not volatile or not reads:
        return set()
    marked = set(volatile)
    for _ in range(10000):
        index = {}  # sheet -> {col -> sorted rows} of marked cells
        for addr in marked:
            sheet, _, cell = addr.rpartition("!")
            co = _coord(cell)
            if co:
                index.setdefault(sheet, {}).setdefault(co[0], []).append(co[1])
        for cols in index.values():
            for rows in cols.values():
                rows.sort()
        added = False
        for addr, rects in reads.items():
            if addr in marked:
                continue
            for sheet, c1, r1, c2, r2 in rects:
                cols = index.get(sheet)
                if not cols:
                    continue
                candidates = cols.items() if c2 - c1 > len(cols) else ((c, cols.get(c)) for c in range(c1, c2 + 1))
                hit = False
                for c, rows in candidates:
                    if rows is None or c < c1 or c > c2:
                        continue
                    i = bisect.bisect_left(rows, r1)
                    if i < len(rows) and rows[i] <= r2:
                        hit = True
                        break
                if hit:
                    marked.add(addr)
                    added = True
                    break
        if not added:
            break
    return marked - volatile
