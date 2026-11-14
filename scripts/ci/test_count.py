#!/usr/bin/env python3
"""Print the suite's total test count and gate its growth (L8-01).

Canon, implementation-baseline-v1 #tests-findings: "The gate prints the suite's
total test count. Growth in that count needs a stated reason."

The count is a static scan of git objects: no cargo, no checkout, the same
answer on any host. It counts what the test census counted:
  rust  fns under a test attribute whose last path segment is test, rstest,
        test_case, wasm_bindgen_test, quickcheck, test_matrix or parameterized
        (`*.rs` under crates/ and apps/; comments and strings are masked; a fn
        with several such attributes counts once)
  e2e   cases registered through the E2E runner (`suite.test(test, ...)`,
        `.skip`, `.todo`, `.pendingDoor`) in tests/e2e/*.test.ts
  js    test()/it() calls with a literal name in other *.test.* / *.spec.* files
  py    `def test*` functions in test_*.py / *_test.py files (strings and
        comments are skipped: Python's own tokenizer reads the file)
Paths with a vendor, node_modules, target, dist or third_party component are
not counted. A macro that emits several tests counts once; the growth is a
delta of the same counter, so that does not bias it.

The baseline is the count at --base (the PR's merge base): growth is head
minus base over the files the diff changes. Growth above zero needs a line
`Test growth: <reason>` in --body-file (the PR body).

Usage: test_count.py [--repo DIR] [--base REV] [--head REV] [--body-file FILE] [--report-only]
Exit: 0 pass; 1 growth with no reason line; 2 scan error (fails closed).
"""
import argparse
import io
import re
import subprocess
import sys
import tokenize
from pathlib import Path

KINDS = ("rust", "e2e", "js", "py")
TEST_ATTRS = {"test", "rstest", "test_case", "wasm_bindgen_test", "quickcheck", "test_matrix", "parameterized"}
SKIP_DIRS = {"vendor", "node_modules", "target", "dist", "third_party"}
REASON_RE = re.compile(r"(?im)^\s*(?:[-*]\s+)?test growth:[ \t]*(\S[^\r\n]*)$")

# Rust: one alternation, scanned left to right. Comments, strings and char
# literals are skipped; an outer attribute `#[` and the `fn` keyword are kept.
_RUST_TOKEN = re.compile(
    r"(?P<line>//[^\n]*)"
    r"|(?P<block>/\*)"
    r"|(?P<raw>(?<![A-Za-z0-9_])[bc]?r(?P<hashes>#*)\")"
    r"|(?P<str>\"(?:\\.|[^\"\\])*\")"
    r"|(?P<char>(?<![A-Za-z0-9_])b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'\n])')"
    r"|(?P<attr>\#\s*\[)"
    r"|(?P<fn>(?<![A-Za-z0-9_])fn(?![A-Za-z0-9_]))",
    re.S,
)
_RUST_BLOCK = re.compile(r"/\*|\*/")
_RUST_PATH = re.compile(r"\s*((?:r#)?[A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*(?:r#)?[A-Za-z_][A-Za-z0-9_]*)*)")

# JS/TS: comments and string literals are skipped; regex literals are not parsed.
_JS_TOKEN = re.compile(
    r"(?P<e2e>\.\s*(?:test|skip|todo|pendingDoor)\s*\(\s*test\s*,)"
    r"|(?P<call>(?<![A-Za-z0-9_$.])(?:test|it)(?:\s*\.\s*(?:skip|todo|only|failing))?\s*\(\s*(?=[\"'`]))"
    r"|(?P<line>//[^\n]*)"
    r"|(?P<block>/\*.*?(?:\*/|\Z))"
    r"|(?P<str>\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)",
    re.S,
)
_PY_TEST = re.compile(r"(?m)^[ \t]*(?:async[ \t]+)?def[ \t]+test\w*[ \t]*\(")  # fallback: a file tokenize refuses


class ScanError(Exception):
    pass


def kind_of(path):
    """The kind a repo path is counted under, or None."""
    parts = path.split("/")
    if SKIP_DIRS.intersection(parts[:-1]):
        return None
    name = parts[-1]
    if name.endswith(".rs"):
        return "rust" if parts[0] in ("crates", "apps") else None
    if re.fullmatch(r"[^/]+\.test\.ts", name) and parts[:2] == ["tests", "e2e"] and len(parts) == 3:
        return "e2e"
    if re.fullmatch(r"[^/]+\.(?:test|spec)\.(?:ts|tsx|js|jsx|mjs|cjs|mts|cts)", name):
        return "js"
    if name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py")):
        return "py"
    return None


def rust_test_fns(text):
    """Yield the offset of the `fn` keyword of each test in a Rust source text.

    scripts/ci/suite_census.py reads the same offsets, so the census and this
    gate count one set of tests."""
    if "test" not in text and "quickcheck" not in text and "parameterized" not in text:
        return  # every name in TEST_ATTRS contains one of these
    pending, pos = False, 0
    while True:
        m = _RUST_TOKEN.search(text, pos)
        if not m:
            return
        pos = m.end()
        kind = m.lastgroup
        if kind == "block":
            depth = 1
            for b in _RUST_BLOCK.finditer(text, pos):
                depth += 1 if b.group() == "/*" else -1
                if depth == 0:
                    pos = b.end()
                    break
            else:
                return
        elif kind == "raw":
            close = text.find('"' + m.group("hashes"), pos)
            if close < 0:
                return
            pos = close + 1 + len(m.group("hashes"))
        elif kind == "attr":
            p = _RUST_PATH.match(text, pos)
            if p:
                last = re.split(r"\s*::\s*", p.group(1))[-1].removeprefix("r#")
                pending = pending or last in TEST_ATTRS
                pos = p.end()
        elif kind == "fn" and pending:
            yield m.start()
            pending = False


def count_rust(text):
    return sum(1 for _ in rust_test_fns(text))


def count_js(text, e2e):
    group = "e2e" if e2e else "call"
    return sum(1 for m in _JS_TOKEN.finditer(text) if m.lastgroup == group)


def count_py(text):
    try:
        names = [t.string for t in tokenize.generate_tokens(io.StringIO(text).readline) if t.type == tokenize.NAME]
    except (tokenize.TokenError, SyntaxError):
        return len(_PY_TEST.findall(text))
    return sum(1 for a, b in zip(names, names[1:]) if a == "def" and b.startswith("test"))


def count_blob(kind, data):
    text = data.decode("utf-8", errors="replace")
    if kind == "rust":
        return count_rust(text)
    if kind in ("e2e", "js"):
        return count_js(text, kind == "e2e")
    return count_py(text)


def git(repo, *args, data=None):
    out = subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True)
    if out.returncode != 0:
        raise ScanError(f"git {' '.join(args[:3])} failed: {out.stderr.decode(errors='replace').strip()}")
    return out.stdout


def tree_files(repo, rev, keep=kind_of):
    """{path: blob sha} of every file in rev's tree that keep(path) accepts (default: the counted files)."""
    files = {}
    for entry in git(repo, "ls-tree", "-r", "-z", "--full-tree", rev).split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, typ, sha = meta.split()
        path = path.decode("utf-8", errors="replace")
        if typ == b"blob" and mode != b"120000" and keep(path):
            files[path] = sha.decode()
    return files


def read_blobs(repo, files):
    """Yield (path, bytes) for {path: sha} in path order, read through one cat-file --batch."""
    if not files:
        return
    paths = sorted(files)
    raw = git(repo, "cat-file", "--batch", data="".join(files[p] + "\n" for p in paths).encode())
    pos = 0
    for path in paths:
        nl = raw.index(b"\n", pos)
        header = raw[pos:nl].split()
        if len(header) != 3 or header[1] != b"blob":
            raise ScanError(f"unreadable blob for {path}: {raw[pos:nl].decode(errors='replace')}")
        size = int(header[2])
        yield path, raw[nl + 1 : nl + 1 + size]
        pos = nl + 1 + size + 1


def count_blobs(repo, files):
    """{path: (kind, count)} for {path: sha}."""
    out = {}
    for path, data in read_blobs(repo, files):
        kind = kind_of(path)
        out[path] = (kind, count_blob(kind, data))
    return out


def totals(counted):
    t = dict.fromkeys(KINDS, 0)
    for kind, n in counted.values():
        t[kind] += n
    return t


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--base", help="baseline revision (the PR's merge base); omit to print the total only")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--body-file", help="PR body; a 'Test growth: <reason>' line states the reason for growth")
    ap.add_argument("--report-only", action="store_true", help="print the counts, never fail on growth")
    a = ap.parse_args(argv)
    try:
        head_files = tree_files(a.repo, a.head)
        if not head_files:
            raise ScanError(f"no test file found in {a.head}: empty scan")
        head = count_blobs(a.repo, head_files)
        head_totals = totals(head)
        total = sum(head_totals.values())
        print(f"tests_total={total}")
        for kind in KINDS:
            print(f"tests_{kind}={head_totals[kind]}")
        if not a.base:
            return 0
        changed = [p for p in git(a.repo, "diff", "--name-only", "--no-renames", "-z", a.base, a.head).decode().split("\0") if p and kind_of(p)]
        base_files = tree_files(a.repo, a.base)
        base = count_blobs(a.repo, {p: base_files[p] for p in changed if p in base_files})
        growth = sum(head[p][1] for p in changed if p in head) - sum(n for _, n in base.values())
        body = Path(a.body_file).read_text(errors="replace") if a.body_file else ""
    except (ScanError, OSError, ValueError) as err:
        print(f"test_count=error {err}", file=sys.stderr)
        return 2
    print(f"tests_base={total - growth}")
    print(f"tests_growth={growth}")
    m = REASON_RE.search(body)
    reason = m.group(1).strip() if m else None
    print(f"growth_reason={reason or 'none'}")
    if growth > 0 and not reason and not a.report_only:
        print(f'test_count=fail: the suite grows by {growth} test(s) and the PR body has no "Test growth: <reason>" line', file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
