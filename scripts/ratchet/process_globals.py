#!/usr/bin/env python3
"""Ratchet metric: process-global mutable statics under crates/*/src.

Counts `static` items (including `static mut`) in non-test Rust files whose
DECLARED TYPE names one of the shared-mutability or write-once wrappers:

    Mutex  RwLock  Atomic  OnceLock  OnceCell  LazyLock  Lazy<  Cell<  RefCell

A `static` inside a `thread_local! { … }` block is NOT counted: that storage is
per-thread by definition and is the fix this metric wants people to reach for.
Test-gated (`#[cfg(test)]`) statics DO count — under `cargo test --lib` sibling
tests share one process, so a test-only global is exactly the seam that flakes
(#922 bm25 diagnostics counter, #923 delete rendezvous slot).

Non-test file: the same definition scripts/ratchet/check.sh uses — no `tests/`
path component, filename is not `tests.rs`, does not end `_tests.rs` and does
not start `tests_`. `vendor/` and `target/` are excluded.

Output: ONE integer on stdout, exit 0. With --list: one `path:line NAME: type`
line per hit, sorted by path then line, for humans reading the number.

Fails CLOSED like check.sh: an unreadable file or a scan that finds no source
files at all prints `RATCHET-ERROR: …` on stderr and exits 1, never a silent 0.

Stdlib only, no third-party parser: the file is lexed just enough to be honest
about comments, strings and char literals, so a `static` inside a doc comment or
a string is not counted and a `'static` lifetime is never mistaken for an item.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# A static counts when its declared type names one of these. Order is fixed so
# --list output is stable; a type matching several is still ONE hit.
TYPE_TOKENS = (
    "Mutex",
    "RwLock",
    "Atomic",
    "OnceLock",
    "OnceCell",
    "LazyLock",
    "Lazy<",
    "Cell<",
    "RefCell",
)

# `static` opening an item: start of line, optional visibility, optional `mut`.
# Anchoring at line start is what keeps `&'static str` out of the count.
STATIC_RE = re.compile(
    r"(?m)^[ \t]*(?:pub[ \t]*(?:\([^)]*\)[ \t]*)?)?static[ \t]+(?:mut[ \t]+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)[ \t]*:"
)

THREAD_LOCAL_RE = re.compile(r"\bthread_local\s*!")

OPENERS = {"{": "}", "(": ")", "[": "]"}
CLOSERS = {"}", ")", "]"}


class ScanError(Exception):
    """A read or decode failure; the caller turns it into RATCHET-ERROR."""


def blank(text: str) -> str:
    """Return `text` with every character replaced by a space, newlines kept.

    Offsets and line numbers survive, so a match position in the blanked source
    still points at the right line of the real file.
    """
    return "".join("\n" if ch == "\n" else " " for ch in text)


def strip_noise(src: str) -> str:
    """Blank out comments, string literals and char literals, in place.

    Rust block comments nest, raw strings carry a hash fence, and a `'` starts a
    lifetime far more often than a char literal — all three are handled, because
    each of them can otherwise hide or invent a `static` or an unbalanced brace.
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        # Line comment.
        if ch == "/" and nxt == "/":
            end = src.find("\n", i)
            end = n if end == -1 else end
            out.append(blank(src[i:end]))
            i = end
            continue

        # Block comment, nesting.
        if ch == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src[j] == "/" and j + 1 < n and src[j + 1] == "*":
                    depth += 1
                    j += 2
                elif src[j] == "*" and j + 1 < n and src[j + 1] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(blank(src[i:j]))
            i = j
            continue

        # Raw string: r"…", r#"…"#, br##"…"##.
        raw = re.compile(r'(?:b?r)(#*)"').match(src, i)
        if raw and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            fence = '"' + raw.group(1)
            end = src.find(fence, raw.end())
            j = n if end == -1 else end + len(fence)
            out.append(blank(src[i:j]))
            i = j
            continue

        # Ordinary or byte string.
        if ch == '"' or (ch == "b" and nxt == '"'):
            j = i + (2 if ch == "b" else 1)
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(blank(src[i:j]))
            i = j
            continue

        # Char literal vs lifetime: only a closing quote makes it a literal.
        if ch == "'":
            lit = re.compile(r"'(?:\\.|[^\\'])'").match(src, i)
            if lit:
                out.append(blank(lit.group(0)))
                i = lit.end()
                continue

        out.append(ch)
        i += 1
    return "".join(out)


def thread_local_spans(src: str) -> list[tuple[int, int]]:
    """Half-open [start, end) offsets of every `thread_local! { … }` body.

    Depth is counted over all three delimiter kinds so a nested block, tuple or
    index inside the macro cannot close it early.
    """
    spans: list[tuple[int, int]] = []
    for m in THREAD_LOCAL_RE.finditer(src):
        i = m.end()
        while i < len(src) and src[i].isspace():
            i += 1
        if i >= len(src) or src[i] not in OPENERS:
            continue
        depth, j = 0, i
        while j < len(src):
            if src[j] in OPENERS:
                depth += 1
            elif src[j] in CLOSERS:
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        spans.append((i, j))
    return spans


def declared_type(src: str, start: int) -> str | None:
    """Read the type between a static's `:` and its `=` (or `;`).

    Depth-aware, so an associated-type binding (`Iterator<Item = u8>`) does not
    end the type early; `->` is stepped over whole so a function type's arrow is
    not read as a closing angle bracket.
    """
    depth, j, n = 0, start, len(src)
    while j < n:
        ch = src[j]
        if ch == "-" and j + 1 < n and src[j + 1] == ">":
            j += 2
            continue
        if ch in OPENERS or ch == "<":
            depth += 1
        elif ch in CLOSERS or ch == ">":
            depth -= 1
        elif depth == 0 and ch in "=;":
            return src[start:j]
        j += 1
    return None


def source_files() -> list[Path]:
    """Non-test .rs files under crates/*/src, deterministically ordered."""
    files: list[Path] = []
    for path in sorted((REPO_ROOT / "crates").glob("*/src/**/*.rs")):
        parts = path.relative_to(REPO_ROOT).parts
        if "tests" in parts or "vendor" in parts or "target" in parts:
            continue
        name = path.name
        if name == "tests.rs" or name.endswith("_tests.rs") or name.startswith("tests_"):
            continue
        files.append(path)
    return files


def scan(path: Path) -> list[tuple[int, str, str]]:
    """Hits in one file as (line, name, type)."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ScanError(f"cannot read {path.relative_to(REPO_ROOT)}: {exc}") from exc

    src = strip_noise(raw)
    skip = thread_local_spans(src)
    hits: list[tuple[int, str, str]] = []
    for m in STATIC_RE.finditer(src):
        if any(lo <= m.start() < hi for lo, hi in skip):
            continue
        ty = declared_type(src, m.end())
        if ty is None:
            continue
        # Collapse whitespace so `Lazy <T>` and a type wrapped over two lines
        # still meet the `Lazy<` / `Cell<` tokens.
        ty = re.sub(r"\s+", " ", ty).strip()
        ty = re.sub(r"\s+<", "<", ty)
        if any(tok in ty for tok in TYPE_TOKENS):
            hits.append((src.count("\n", 0, m.start()) + 1, m.group(1), ty))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list",
        action="store_true",
        help="print `path:line NAME: type` per hit instead of the count",
    )
    args = parser.parse_args()

    files = source_files()
    if not files:
        print("RATCHET-ERROR: no .rs files found under crates/*/src", file=sys.stderr)
        return 1

    rows: list[tuple[str, int, str, str]] = []
    try:
        for path in files:
            rel = path.relative_to(REPO_ROOT).as_posix()
            for line, name, ty in scan(path):
                rows.append((rel, line, name, ty))
    except ScanError as exc:
        print(f"RATCHET-ERROR: {exc}", file=sys.stderr)
        return 1

    rows.sort(key=lambda r: (r[0], r[1]))
    if args.list:
        for rel, line, name, ty in rows:
            print(f"{rel}:{line} {name}: {ty}")
    else:
        print(len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
