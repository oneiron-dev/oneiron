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

A type ALIAS or a named wrapper STRUCT hides none of this: `type Slot =
LazyLock<Mutex<..>>` and `struct Registry { entries: LazyLock<Mutex<..>> }` are
resolved when they are declared in the SAME file as the static, so a global
cannot duck the metric by being given a name. Resolution is same-file only and
purely textual — a real type resolver is out of scope. Stated gaps, none live in
this tree: a name declared in ANOTHER file; a generic struct header
(`struct Foo<T> { inner: Mutex<T> }`, whose body is not scanned); an `enum`
wrapper; and an alias chain longer than MAX_RESOLVE_DEPTH. Stating them beats
guessing.

Output: ONE integer on stdout, exit 0. With --list: one `path:line NAME: type`
line per hit, sorted by path then line, for humans reading the number; a hit
resolved through a local name carries ` [via NAME]` naming it.

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

# `type Name<..> = ..;` — a same-file alias the static's declared type may name.
TYPE_ALIAS_RE = re.compile(
    r"(?m)^[ \t]*(?:pub[ \t]*(?:\([^)]*\)[ \t]*)?)?type[ \t]+([A-Za-z_][A-Za-z0-9_]*)"
)

# `struct Name` — a same-file wrapper whose fields may hold the mutability.
STRUCT_RE = re.compile(
    r"(?m)^[ \t]*(?:pub[ \t]*(?:\([^)]*\)[ \t]*)?)?struct[ \t]+([A-Za-z_][A-Za-z0-9_]*)"
)

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Depth cap for local-name resolution: deep enough for any real wrapper chain,
# and a hard stop so a cyclic alias cannot hang the scan.
MAX_RESOLVE_DEPTH = 8

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


def declared_type(src: str, start: int, terminators: str = "=;") -> str | None:
    """Read a type from `start` up to the first top-level terminator.

    `terminators` is `"=;"` for a static's declared type (between its `:` and
    its initializer) and `";"` for a type alias's right-hand side, which may
    itself contain a top-level `=` in an associated-type binding.

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
        elif depth == 0 and ch in terminators:
            return src[start:j]
        j += 1
    return None


def balanced_body(src: str, start: int) -> tuple[str, int]:
    """Text of the `{…}`/`(…)`/`[…]` group opening at `start`, and its end offset.

    Depth is counted over all three delimiter kinds, so a nested group cannot
    close the outer one early.
    """
    depth, j, n = 0, start, len(src)
    while j < n:
        if src[j] in OPENERS:
            depth += 1
        elif src[j] in CLOSERS:
            depth -= 1
            if depth == 0:
                return src[start : j + 1], j + 1
        j += 1
    return src[start:], n


def local_names(src: str) -> tuple[dict[str, str], dict[str, str]]:
    """Same-file `type` aliases and `struct` bodies, each as name -> type text.

    Both maps are keyed by the declared name and valued by the text a hit is
    then searched for: an alias's right-hand side, a struct's field list. A
    later declaration of the same name overwrites an earlier one; duplicate
    top-level names do not occur in a compiling crate.
    """
    aliases: dict[str, str] = {}
    for m in TYPE_ALIAS_RE.finditer(src):
        eq = src.find("=", m.end())
        if eq == -1:
            continue
        rhs = declared_type(src, eq + 1, terminators=";")
        if rhs is not None:
            aliases[m.group(1)] = rhs

    structs: dict[str, str] = {}
    for m in STRUCT_RE.finditer(src):
        i, n = m.end(), len(src)
        while i < n and (src[i].isspace() or src[i] in "<>,'&:+="):
            # Step over generics and bounds without parsing them; a delimiter
            # below ends the header either way.
            if src[i] in OPENERS:
                break
            i += 1
        if i < n and src[i] in ("{", "("):
            structs[m.group(1)] = balanced_body(src, i)[0]
        else:
            structs[m.group(1)] = ""
    return aliases, structs


def holds_shared_mutability(
    ty: str,
    aliases: dict[str, str],
    structs: dict[str, str],
    seen: set[str],
    depth: int = 0,
) -> str | None:
    """The local name a type reaches shared mutability through, or `None`.

    Returns "" when the declared type names a wrapper directly, so a caller can
    tell a direct hit from one resolved through a local alias or struct.
    """
    if any(tok in ty for tok in TYPE_TOKENS):
        return ""
    if depth >= MAX_RESOLVE_DEPTH:
        return None
    for ident in IDENT_RE.findall(ty):
        if ident in seen:
            continue
        body = aliases.get(ident, structs.get(ident))
        if body is None:
            continue
        seen.add(ident)
        if holds_shared_mutability(body, aliases, structs, seen, depth + 1) is not None:
            return ident
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
    aliases, structs = local_names(src)
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
        via = holds_shared_mutability(ty, aliases, structs, set())
        if via is None:
            continue
        shown = ty if via == "" else f"{ty} [via {via}]"
        hits.append((src.count("\n", 0, m.start()) + 1, m.group(1), shown))
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
