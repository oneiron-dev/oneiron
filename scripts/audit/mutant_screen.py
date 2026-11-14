#!/usr/bin/env python3
"""Mutant screen: does the pruned test suite miss a mutant the old suite caught? (L8-02)

Canon, implementation-baseline-v1 #tests-mutant-screen: "C: a mutant screen checks that the
prune loses nothing. A mutant is a small deliberate change to the code. The screen makes about
50 mutants across 5 crates. It runs the old suite and the pruned suite on each mutant. It
compares what each suite catches."

The two suites (Rust tests only; a test is a fn under a test attribute, as scripts/ci/test_count.py
counts it, in a file test_count.py counts):
  old suite     the tests at --old, the prune plan's census base (65a9a904107f).
  pruned suite  the tests at --pruned (default origin/main).
An old test (file, fn name) is kept when the pruned file of the same path defines the name. It is a
followed move when exactly one pruned file has the same path below its crate directory and defines
the name, or when a pruned test has the same name and the same whitespace-normalized text. Any
other old test is deleted, whatever deleted it.

No commit holds the old suite in a runnable state, so the old suite is built as the pruned tree
plus every deleted test put back ("restored") at the end of its module in the same file. A module
the prune removed is re-created around its tests. In test code (a cfg(test) module, a *tests.rs
file, an integration test) the old module's other items that the pruned module lacks (a swept
helper, a use line) come back too. A deleted test-only file comes back whole, with its `mod` line.
A test whose file has no pruned counterpart is `subject_removed`. Production code is the same bytes
in both trees: deleting every restored span from the old tree gives the pruned tree back.

Per crate (ranked by deleted tests; --crates overrides), until --crate-count crates are screened:
  1. the pruned suite runs unmutated (`cargo nextest run`); a failing crate is skipped and named;
  2. the old tree compiles; a restored item an error points at is taken out (up to 3 rounds,
     `restored_did_not_compile`); a restored test that fails unmutated is taken out
     (`restored_failed_unmutated`);
  3. `cargo mutants --list` in both trees; mutants are paired by (file, function, genre,
     replacement, ordinal in the function), not by line; --per-crate pairs are drawn with the
     seed int(pruned sha[:16], 16), from the files that held deleted tests first;
  4. pinned cargo-mutants runs the same mutants in each tree (whole crate suite, nextest);
     a pair with a Timeout on either side runs once more with twice the timeout.
Lost = caught by the old suite and missed by the pruned suite. Undecided = still a Timeout, or
no outcome on one side. Verdict `loses_nothing` only when both lists are empty.

Usage:
  mutant_screen.py --plan-only [--old REV] [--pruned REV] [--crates a,b]   (git only, no cargo)
  mutant_screen.py [--old REV] [--pruned REV] [--crates a,b] [--crate-count 5] [--per-crate 10]
  mutant_screen.py --report report.json                            (re-judge a saved report)
  mutant_screen.py --old-outcomes A.json [A2.json] --pruned-outcomes B.json [B2.json]
                    (judge two cargo-mutants outcomes.json sets; a later file overrides an earlier)
A full run writes target/mutant-screen/<pruned sha12>/report.json and report.md.
Exit: 0 loses nothing (or a plan); 1 lost or undecided mutants; 2 the screen could not run.
"""
import argparse
import collections
import json
import math
import os
import random
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import test_count as tc  # noqa: E402  the census's own test rule (TEST_ATTRS, kind_of)

OLD_SUITE_REF = "65a9a904107f"  # TEST-PASS-PLAN census base, rewritten 14 Nov (was 391509654610)
RUNNER = "cargo-mutants " + json.loads((ROOT / "scripts/audit/tools.json").read_text())["cargo-mutants"]
DEFAULT_RUSTFLAGS = "--cfg oneiron_test_support"
SCHEMA = 1


class ScreenError(Exception):
    pass


# ---------------------------------------------------------------- Rust source structure

_LEX = re.compile(
    r"(?P<line>//[^\n]*)"
    r"|(?P<block>/\*)"
    r"|(?P<raw>(?<![A-Za-z0-9_])[bc]?r(?P<hashes>#*)\")"
    r"|(?P<str>(?<![A-Za-z0-9_])[bc]?\"(?:\\.|[^\"\\])*\")"
    r"|(?P<char>(?<![A-Za-z0-9_])b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'\n])')",
    re.S,
)
_BLOCK = re.compile(r"/\*|\*/")
_NOT_NL = re.compile(r"[^\n]")
_DELIMS = re.compile(r"[{}()\[\]]")
_ITEM_STOP = re.compile(r"[{(\[;]")
_NON_SPACE = re.compile(r"\S")
_ATTR_OPEN = re.compile(r"#(!?)\s*\[")
_ATTR_PATH = re.compile(r"#!?\s*\[\s*((?:r#)?\w+(?:\s*::\s*(?:r#)?\w+)*)")
_CFG_TEST = re.compile(r"\bcfg\s*\(\s*test\s*\)")
_PATH_ATTR = re.compile(r"^\s*#\s*\[\s*path\s*=")
_HEAD = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?:const|async|unsafe|extern|default|safe)\s+)*"
    r"(?P<kw>fn|mod|use|struct|enum|impl|trait|const|static|type|union|macro_rules\s*!|extern\s+crate)"
    r"(?![A-Za-z0-9_])\s*(?P<name>(?:r#)?[A-Za-z_][A-Za-z0-9_]*)?"
)
_SEMI_KINDS = {"use", "const", "static", "type", "extern crate"}  # a `}` does not end these
_NAMED_KINDS = {"fn", "mod", "struct", "enum", "trait", "const", "static", "type", "union", "macro_rules"}


def mask(text):
    """The text with comments, strings and char literals blanked; newlines and offsets kept."""
    out, pos, n = [], 0, len(text)
    while True:
        m = _LEX.search(text, pos)
        if not m:
            out.append(text[pos:])
            return "".join(out)
        out.append(text[pos:m.start()])
        end, kind = m.end(), m.lastgroup
        if kind == "block":
            depth = 1
            for b in _BLOCK.finditer(text, end):
                depth += 1 if b.group() == "/*" else -1
                if depth == 0:
                    end = b.end()
                    break
            else:
                end = n
        elif kind == "raw":
            close = text.find('"' + m.group("hashes"), end)
            end = n if close < 0 else close + 1 + len(m.group("hashes"))
        out.append(_NOT_NL.sub(" ", text[m.start():end]))
        pos = end


def _pairs(masked):
    """Each open delimiter's offset -> its close's offset."""
    pairs, stack = {}, []
    for m in _DELIMS.finditer(masked):
        c = m.group()
        if c in "{([":
            stack.append((c, m.start()))
            continue
        want = {"}": "{", ")": "(", "]": "["}[c]
        while stack:
            o, at = stack.pop()
            if o == want:
                pairs[at] = m.start()
                break
    return pairs


class Item:
    """One item of a module level: its kind, name and extents (offsets into the file text).

    first..code_end is the code with its attributes; start..end adds attached comment lines and
    the rest of the last line, so text[start:end] can be cut out or copied whole.
    """

    __slots__ = ("chain", "kind", "name", "attrs", "first", "head", "code_end", "start", "end",
                 "children", "body")

    def __init__(self, chain, kind, name, attrs, first, head):
        self.chain, self.kind, self.name, self.attrs = chain, kind, name, attrs
        self.first, self.head = first, head
        self.code_end = self.start = self.end = first
        self.children, self.body = None, None

    @property
    def is_test(self):
        if self.kind != "fn":
            return False
        for attr in self.attrs:
            p = _ATTR_PATH.match(attr)
            if p and re.split(r"\s*::\s*", p.group(1))[-1].removeprefix("r#") in tc.TEST_ATTRS:
                return True
        return False

    @property
    def test_gated(self):
        return any(_CFG_TEST.search(a) for a in self.attrs)


class Source:
    """A Rust file parsed into module levels (inline `mod x { }` blocks are levels)."""

    def __init__(self, text):
        self.text, self.masked = text, mask(text)
        self._pairs = _pairs(self.masked)
        self.items = self._level(0, len(text), ())

    def _skip(self, pos, limit):
        m = _NON_SPACE.search(self.masked, pos, limit)
        return m.start() if m else limit

    def _level(self, pos, limit, chain):
        items = []
        while True:
            p = self._skip(pos, limit)
            if p >= limit:
                return items
            item = self._item(p, limit, chain)
            items.append(item)
            pos = max(item.code_end, p + 1)

    def _item(self, p, limit, chain):
        t, m, first, attrs = self.text, self.masked, p, []
        while p < limit:
            a = _ATTR_OPEN.match(m, p)
            close = self._pairs.get(a.end() - 1) if a else None
            if close is None:
                break
            if a.group(1):  # an inner attribute is an item of its own
                if not attrs:
                    item = Item(chain, "inner", None, [t[p:close + 1]], p, p)
                    return self._extents(item, close + 1, limit)
                break
            attrs.append(t[p:close + 1])
            p = self._skip(close + 1, limit)
        head = _HEAD.match(m, p, limit)
        kind = re.sub(r"\s+", " ", head.group("kw")).replace(" !", "").rstrip("!") if head else "other"
        name = head.group("name") if head and kind in _NAMED_KINDS else None  # `use super::x` names nothing
        item = Item(chain, kind, name, attrs, first, p)
        q = head.end() if head else p
        code_end = limit
        while q < limit:
            s = _ITEM_STOP.search(m, q, limit)
            if not s:
                break
            c, at = s.group(), s.start()
            if c == ";":
                code_end = at + 1
                break
            close = self._pairs.get(at)
            if close is None or close >= limit:
                break
            if c in "([":
                q = close + 1
                continue
            if kind == "mod" and item.children is None:
                item.children = self._level(at + 1, close, chain + (item.name,))
                item.body = (at, close)
            if kind in _SEMI_KINDS:
                q = close + 1
                continue
            code_end = close + 1
            nxt = self._skip(code_end, limit)
            if nxt < limit and m[nxt] == ";":
                code_end = nxt + 1
            break
        return self._extents(item, code_end, limit)

    def _extents(self, item, code_end, limit):
        t, m = self.text, self.masked
        item.code_end = code_end
        start = item.first
        ls = t.rfind("\n", 0, start) + 1
        if not m[ls:start].strip():
            start = ls
            while start > 0:  # attached comment lines (doc comments) above
                prev = t.rfind("\n", 0, start - 1) + 1
                if t[prev:start].strip() and not m[prev:start].strip():
                    start = prev
                else:
                    break
        item.start = start
        le = t.find("\n", code_end, limit)
        item.end = (le + 1) if le >= 0 and not m[code_end:le].strip() else code_end
        return item

    def levels(self):
        """chain -> (items, the mod item or None); the first of two same-named modules wins."""
        out = {(): (self.items, None)}
        todo = list(self.items)
        while todo:
            item = todo.pop(0)
            if item.children is not None:
                out.setdefault(item.chain + (item.name,), (item.children, item))
                todo.extend(item.children)
        return out

    def tests(self):
        """(chain, name, normalized text) of every test fn."""
        found = []
        for items, _ in self.levels().values():
            for item in items:
                if item.is_test:
                    found.append((item.chain, item.name, norm(self.text[item.head:item.code_end])))
        return found

    def code(self, item):
        return self.text[item.first:item.code_end]


def norm(code):
    return re.sub(r"\s+", " ", code).strip()


def test_id(path, chain, name):
    return "::".join([path, *chain, name])


def _piece_text(text):
    return text if text.endswith("\n") else text + "\n"


def restore_file(old_text, pruned_text, wanted, *, test_file=False, label="", skip=frozenset()):
    """Put the old file's wanted tests back into the pruned file.

    wanted: {(chain, name): unit id}. In test code (test_file, or a chain under a cfg(test)
    module) the old module's other items that the pruned module lacks come back as helper units.
    skip: unit ids to leave out. Returns (text, pieces): a piece is (start, end, unit ids) in the
    returned text, and deleting every piece gives pruned_text back byte for byte.
    """
    wanted = {k: v for k, v in wanted.items() if v not in skip}
    old, new = Source(old_text), Source(pruned_text)
    old_levels, new_levels = old.levels(), new.levels()
    needed = set()
    for chain, _ in wanted:
        for i in range(len(chain) + 1):
            needed.add(chain[:i])
    direct = {chain for chain, _ in wanted}

    def test_code(chain):
        if test_file:
            return True
        return any(old_levels.get(chain[:i], (None, None))[1] is not None
                   and old_levels[chain[:i]][1].test_gated for i in range(1, len(chain) + 1))

    def entries(chain):
        """The restore entries of one old level, in old order: ("item", item, unit) or ("block", chain)."""
        items, _ = old_levels.get(chain, ((), None))
        here = new_levels.get(chain)
        have_names = {(i.kind, i.name) for i in here[0]} if here else set()
        have_code = {norm(new.code(i)) for i in here[0]} if here else set()
        out = []
        for n, item in enumerate(items):
            if item.is_test:
                unit = wanted.get((chain, item.name))
                if unit:
                    out.append(("item", item, unit))
            elif item.kind == "mod" and item.children is not None and chain + (item.name,) in needed:
                out.append(("block", chain + (item.name,)))
            elif chain in direct and test_code(chain) and item.kind not in ("inner",):
                if item.kind == "mod" and item.children is None:
                    continue  # a `mod x;` line names a file; whole-file restores carry their own
                if item.name and item.kind in _NAMED_KINDS:
                    if (item.kind, item.name) in have_names:
                        continue
                elif norm(old.code(item)) in have_code:
                    continue
                unit = f"{label}::{'::'.join(chain) or '<root>'}::{item.kind} {item.name or '#%d' % n}"
                if unit not in skip:
                    out.append(("item", item, unit))
        return out

    def block(chain):
        """Text pieces of a module the pruned file lacks, or [] when nothing in it is restored."""
        _, mod = old_levels[chain]
        inner = []
        for e in entries(chain):
            if e[0] == "item":
                inner.append((_piece_text(old_text[e[1].start:e[1].end]), {e[2]}))
            else:
                inner.extend(block(e[1]))
        if not inner:
            return []
        members = set().union(*(u for _, u in inner))
        open_end = mod.body[0] + 1
        nl = old_text.find("\n", open_end)
        if nl >= 0 and not old.masked[open_end:nl].strip():
            open_end = nl + 1
        header = _piece_text(old_text[mod.start:open_end])
        ls = old_text.rfind("\n", 0, mod.body[1]) + 1
        indent = old_text[ls:mod.body[1]] if not old_text[ls:mod.body[1]].strip() else ""
        return [(header, members), *inner, (indent + "}\n", members)]

    inserts = collections.defaultdict(list)  # offset -> [(text, units)]
    for chain in sorted(needed, key=len):
        if chain not in new_levels or chain not in old_levels:
            continue
        items, mod = new_levels[chain]
        if mod is None:
            at, glue = len(pruned_text), bool(pruned_text) and not pruned_text.endswith("\n")
        else:
            close = mod.body[1]
            ls = pruned_text.rfind("\n", 0, close) + 1
            at, glue = (ls, False) if not new.masked[ls:close].strip() else (close, True)
        pieces = []
        for e in entries(chain):
            if e[0] == "item":
                pieces.append((_piece_text(old_text[e[1].start:e[1].end]), {e[2]}))
            elif e[1] not in new_levels:
                pieces.extend(block(e[1]))
        if pieces and glue:
            pieces[0] = ("\n" + pieces[0][0], pieces[0][1])
        inserts[at].extend(pieces)
    return splice(pruned_text, inserts)


def splice(text, inserts):
    """Insert {offset: [(piece text, units)]} into text; returns (new text, pieces)."""
    out, pieces, pos, size = [], [], 0, 0
    for at in sorted(inserts):
        out.append(text[pos:at])
        size += at - pos
        pos = at
        for piece, units in inserts[at]:
            out.append(piece)
            pieces.append((size, size + len(piece), frozenset(units)))
            size += len(piece)
    out.append(text[pos:])
    return "".join(out), pieces


def blank(text, pieces):
    """The text with every restored piece deleted."""
    out, pos = [], 0
    for start, end, _ in sorted(pieces):
        out.append(text[pos:start])
        pos = end
    out.append(text[pos:])
    return "".join(out)


# ---------------------------------------------------------------- git trees

def git(repo, *args, data=None):
    p = subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True)
    if p.returncode:
        raise ScreenError(f"git {' '.join(args)}: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout


class Tree:
    """A commit's files, read from git objects (no checkout)."""

    def __init__(self, repo, rev):
        self.repo = repo
        self.sha = git(repo, "rev-parse", "--verify", rev + "^{commit}").decode().strip()
        self.blobs = {}
        for rec in git(repo, "ls-tree", "-r", "-z", self.sha).decode(errors="surrogateescape").split("\0"):
            if rec:
                meta, path = rec.split("\t", 1)
                if meta.split()[1] == "blob":
                    self.blobs[path] = meta.split()[2]
        self._text, self._parsed, self._names = {}, {}, {}

    def rust_files(self):
        return sorted(p for p in self.blobs if tc.kind_of(p) == "rust")

    def load(self, paths):
        want = [p for p in paths if p in self.blobs and p not in self._text]
        for i in range(0, len(want), 2000):
            chunk = want[i:i + 2000]
            out = git(self.repo, "cat-file", "--batch", data="".join(self.blobs[p] + "\n" for p in chunk).encode())
            pos = 0
            for p in chunk:
                nl = out.index(b"\n", pos)
                size = int(out[pos:nl].split()[2])
                self._text[p] = out[nl + 1:nl + 1 + size].decode(errors="surrogateescape")
                pos = nl + 1 + size + 1

    def text(self, path):
        if path not in self._text:
            self.load([path])
        return self._text[path]

    def source(self, path):
        if path not in self._parsed:
            self._parsed[path] = Source(self.text(path))
        return self._parsed[path]

    def test_names(self, path):
        """A consumable count of the test fn names a file defines."""
        if path not in self._names:
            text = self.text(path) if path in self.blobs else ""
            self._names[path] = collections.Counter(
                n for _, n, _ in (self.source(path).tests() if "test" in text else ()))
        return self._names[path]

    def crate_dir(self, path):
        parts = path.split("/")[:-1]
        while parts:
            if "/".join(parts + ["Cargo.toml"]) in self.blobs:
                return "/".join(parts)
            parts.pop()
        return "" if "Cargo.toml" in self.blobs else None

    def crate_name(self, crate_dir):
        if crate_dir is None:
            return None
        manifest = self.text(f"{crate_dir}/Cargo.toml" if crate_dir else "Cargo.toml")
        section = re.search(r"(?ms)^\[package\][^\[]*?^\s*name\s*=\s*\"([^\"]+)\"", manifest)
        return section.group(1) if section else None

    def rel(self, path):
        d = self.crate_dir(path)
        return path[len(d) + 1:] if d else path


# ---------------------------------------------------------------- D1: what the prune deleted

_FN_NAME = re.compile(r"\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)")


def module_dir(path):
    """The directory a file's `mod x;` lines resolve in (no #[path])."""
    base = path.rsplit("/", 1)
    name = base[-1]
    if name in ("mod.rs", "lib.rs", "main.rs"):
        return base[0] if len(base) > 1 else ""
    return path[:-3]


def test_only_file(rel):
    """True for a crate-relative path whose whole file is test code by layout."""
    parts = rel.split("/")
    stem = parts[-1][:-3]
    return (parts[0] == "tests" or "tests" in parts[1:-1] or stem == "tests"
            or stem.endswith("_tests") or stem.endswith("_test"))


def subject_file(tree, path):
    """The production file a test file tests (D4), or None for an integration test."""
    d = tree.crate_dir(path)
    rel = path[len(d) + 1:] if d else path
    if not rel.startswith("src/"):
        return None
    prefix = (d + "/") if d else ""
    parts = rel.split("/")

    def module_file(dir_parts):
        if dir_parts == ["src"]:
            cands = ["src/lib.rs", "src/main.rs"]
        else:
            cands = ["/".join(dir_parts) + "/mod.rs", "/".join(dir_parts) + ".rs"]
        return next((prefix + c for c in cands if prefix + c in tree.blobs), None)

    if "tests" in parts[1:-1]:
        return module_file(parts[:parts.index("tests", 1)])
    stem = parts[-1][:-3]
    if stem == "tests":
        return module_file(parts[:-1])
    for suffix in ("_tests", "_test"):
        if stem.endswith(suffix):
            base = "/".join(parts[:-1] + [stem[:-len(suffix)]])
            for c in (base + ".rs", base + "/mod.rs"):
                if prefix + c in tree.blobs:
                    return prefix + c
            return module_file(parts[:-1])
    return path


def find_deletions(old, pruned):
    """D1 + D2's targets: every old test without a pruned counterpart, and where it goes back.

    Returns (deleted, followed): deleted rows {id, old_path, chain, name, target, kind, crate,
    parent, decl}; kind "fn" (into an existing file), "file" (a whole test-only file) or
    "subject_removed". followed: {(old path, pruned path): tests}.
    """
    changed = [p for p in old.rust_files() if old.blobs[p] != pruned.blobs.get(p)]
    old.load(changed)
    pruned.load([p for p in changed if p in pruned.blobs])
    by_rel = collections.defaultdict(list)
    for p in pruned.rust_files():
        by_rel[pruned.rel(p)].append(p)

    def counterpart(path):
        """The pruned file an old file became: same path, else the one same crate-relative path."""
        if path in pruned.blobs:
            return path
        cands = by_rel.get(old.rel(path), [])
        return cands[0] if len(cands) == 1 else None

    followed, unmatched = collections.Counter(), []
    for path in changed:
        text = old.text(path)
        if "test" not in text:
            continue
        tests = old.source(path).tests()
        here = pruned.test_names(path)
        moved = [q for q in by_rel.get(old.rel(path), []) if q != path]
        for chain, name, code in tests:
            if here[name] > 0:
                here[name] -= 1
            elif len(moved) == 1 and pruned.test_names(moved[0])[name] > 0:
                pruned.test_names(moved[0])[name] -= 1
                followed[(path, moved[0])] += 1
            else:
                unmatched.append((path, chain, name, code))
    if unmatched:
        names = {u[2] for u in unmatched}
        files = pruned.rust_files()
        pruned.load(files)
        index = collections.defaultdict(list)
        for q in files:
            text = pruned.text(q)
            if "test" in text and names.intersection(_FN_NAME.findall(text)):
                for _, name, code in pruned.source(q).tests():
                    if name in names:
                        index[(name, code)].append(q)
        rest = []
        for u in unmatched:
            hits = index.get((u[2], u[3]))
            if hits:
                followed[(u[0], hits.pop())] += 1
            else:
                rest.append(u)
        unmatched = rest

    deleted, used = [], {}
    by_file = collections.defaultdict(list)
    for u in unmatched:
        by_file[u[0]].append(u)
    for path, rows in sorted(by_file.items()):
        target, kind, parent, decl = counterpart(path), "fn", None, None
        if target is None:
            target, parent, decl = whole_file_target(old, pruned, path, counterpart)
            kind = "file" if target else "subject_removed"
        if target and used.setdefault(target, path) != path:
            target, kind, parent, decl = None, "subject_removed", None, None  # one old file per target
        crate_tree, crate_path = (pruned, target) if target else (old, path)
        crate = crate_tree.crate_name(crate_tree.crate_dir(crate_path))
        for _, chain, name, _ in rows:
            deleted.append({"id": test_id(path, chain, name), "old_path": path, "chain": list(chain),
                            "name": name, "target": target, "kind": kind, "crate": crate,
                            "parent": parent, "decl": decl})
    return deleted, followed


def whole_file_target(old, pruned, path, counterpart):
    """Where a deleted test-only file goes back: (target, parent file, `mod` line) or Nones."""
    d = old.crate_dir(path)
    rel = path[len(d) + 1:] if d else path
    if d is None or not test_only_file(rel):
        return None, None, None
    if rel.startswith("tests/"):
        if rel.count("/") == 1 and f"{d}/Cargo.toml" in pruned.blobs:
            return path, None, None  # an integration test target: Cargo finds it by its place
        return None, None, None
    stem = path.rsplit("/", 1)[-1][:-3]
    if stem == "mod":
        return None, None, None
    folder = path.rsplit("/", 1)[0]
    cands = [folder + ".rs", folder + "/mod.rs"]
    if folder == (f"{d}/src" if d else "src"):
        cands = [folder + "/lib.rs", folder + "/main.rs"]
    for parent in cands:
        if parent not in old.blobs:
            continue
        decls = [i for i in old.source(parent).items
                 if i.kind == "mod" and i.children is None and i.name == stem
                 and not any(_PATH_ATTR.match(a) for a in i.attrs)]
        new_parent = counterpart(parent)
        if not decls or new_parent is None:
            continue
        target = module_dir(new_parent) + path[len(module_dir(parent)):]
        if target in pruned.blobs:
            return None, None, None
        item = decls[0]
        return target, new_parent, _piece_text(old.text(parent)[item.start:item.end])
    return None, None, None


# ---------------------------------------------------------------- D3/D4: the plan

def plan_crates(old, pruned, deleted, followed, only=None):
    crates = collections.OrderedDict()
    for row in deleted:
        if not row["crate"]:
            continue
        c = crates.setdefault(row["crate"], {"crate": row["crate"], "deleted": [], "subject_removed": [],
                                             "candidate_files": set(), "followed_moves": 0})
        if row["kind"] == "subject_removed":
            c["subject_removed"].append(row["id"])
            continue
        c["deleted"].append(row["id"])
        subject = subject_file(pruned, row["target"])
        if subject and subject in pruned.blobs:
            c["candidate_files"].add(subject)
    for (src, dst), n in followed.items():
        name = pruned.crate_name(pruned.crate_dir(dst))
        if name in crates:
            crates[name]["followed_moves"] += n
    ranked = sorted(crates.values(), key=lambda c: (-len(c["deleted"]), c["crate"]))
    ranked = [c for c in ranked if c["deleted"]]
    if only:
        ranked = [c for c in ranked if c["crate"] in only] + [
            {"crate": n, "deleted": [], "subject_removed": [], "candidate_files": set(), "followed_moves": 0}
            for n in only if n not in crates]
        ranked.sort(key=lambda c: only.index(c["crate"]))
    for c in ranked:
        c["candidate_files"] = sorted(c["candidate_files"])
    return ranked


# ---------------------------------------------------------------- mutants, outcomes and the verdict

def mutant_key(m):
    fn = (m.get("function") or {}).get("function_name", "")
    return (m["file"], fn, str(m.get("genre")), m.get("replacement", ""))


def keyed(mutants):
    """{(file, function, genre, replacement, ordinal): mutant} for one tree's mutants."""
    groups = collections.defaultdict(list)
    for m in mutants:
        groups[mutant_key(m)].append(m)
    out = {}
    for key, ms in groups.items():
        ms.sort(key=lambda m: (m["span"]["start"]["line"], m["span"]["start"]["column"]))
        for n, m in enumerate(ms):
            out[key + (n,)] = m
    return out


def read_outcomes(path):
    """{mutant name: {summary, mutant, duration, log}} from one cargo-mutants outcomes.json."""
    path = Path(path)
    data = json.loads(path.read_text())
    if not isinstance(data.get("outcomes"), list):
        raise ScreenError(f"{path}: no outcomes list")
    out, baseline = {}, None
    for o in data["outcomes"]:
        scenario = o.get("scenario")
        if scenario == "Baseline":
            baseline = o.get("summary")
            continue
        if not isinstance(scenario, dict) or "Mutant" not in scenario:
            continue
        m = scenario["Mutant"]
        phases = o.get("phase_results") or []
        log = path.parent / o["log_path"] if o.get("log_path") else None
        out[m["name"]] = {"summary": o.get("summary"), "mutant": m,
                          "duration": phases[-1].get("duration", 0.0) if phases else 0.0,
                          "log": str(log) if log and log.is_file() else None}
    return out, baseline


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_NEXTEST_FAIL = re.compile(
    r"^\s*(?:TRY \d+ )?(?:FAIL|SIGSEGV|SIGABRT|SIGKILL|SIGBUS|ABORT|TIMEOUT|LEAK-FAIL)\s+\[[^\]]*\]\s+"
    r"(?:\(\s*\d+/\s*\d+\)\s+)?(\S+)\s+(\S+)\s*$", re.M)
_LIBTEST_FAIL = re.compile(r"^test (\S+) \.\.\. FAILED\s*$", re.M)


def failed_tests(log_text):
    """[(binary id, test path)] named by nextest FAIL lines (or libtest FAILED lines), deduplicated."""
    text = _ANSI.sub("", log_text)
    seen = []
    for m in _NEXTEST_FAIL.finditer(text):
        if (m.group(1), m.group(2)) not in seen:
            seen.append((m.group(1), m.group(2)))
    for m in _LIBTEST_FAIL.finditer(text):
        if ("", m.group(1)) not in seen:
            seen.append(("", m.group(1)))
    return seen


def judge(pairs):
    lost = [p for p in pairs if p["old"] == "CaughtMutant" and p["pruned"] == "MissedMutant"]
    undecided = [p for p in pairs if "Timeout" in (p["old"], p["pruned"]) or None in (p["old"], p["pruned"])]
    return lost, undecided


def compare_outcomes(old_paths, pruned_paths):
    """Pair two outcomes sets by mutant key; a later file of a set overrides an earlier one."""
    sides = []
    for paths in (old_paths, pruned_paths):
        merged = {}
        for p in paths:
            merged.update(read_outcomes(p)[0])
        sides.append(merged)
    old_k = keyed([v["mutant"] for v in sides[0].values()])
    new_k = keyed([v["mutant"] for v in sides[1].values()])
    pairs = []
    for key in sorted(set(old_k) | set(new_k)):
        o, n = old_k.get(key), new_k.get(key)
        oo = sides[0][o["name"]] if o else None
        no = sides[1][n["name"]] if n else None
        pairs.append({"name_old": o["name"] if o else None, "name_pruned": n["name"] if n else None,
                      "old": oo["summary"] if oo else None, "pruned": no["summary"] if no else None,
                      "old_failed_tests": [" ".join(filter(None, t)) for t in failed_tests(
                          Path(oo["log"]).read_text(errors="replace"))] if oo and oo["log"] else []})
    return pairs


def verdict_doc(doc, pairs):
    lost, undecided = judge(pairs)
    doc["lost"] = lost
    doc["undecided"] = undecided
    doc["verdict"] = "loses_nothing" if not lost and not undecided else "lost"
    return doc


# ---------------------------------------------------------------- the full screen (cargo)

def rx_escape(text):
    """The regex crate's own escape set (regex::escape): `<` and `>` must stay bare."""
    return re.sub(r"([\\.+*?()|\[\]{}^$#&\-~])", r"\\\1", text)


class Screen:
    def __init__(self, args, old, pruned):
        self.args, self.old, self.pruned = args, old, pruned
        self.work = Path(args.work or Path(args.repo) / "target/mutant-screen" / pruned.sha[:12]).resolve()
        self.target_root = Path(args.target_root).resolve() if args.target_root else self.work
        self.seed = int(pruned.sha[:16], 16)
        self.trees = {"pruned": self.work / "pruned", "old": self.work / "old"}
        env = dict(os.environ)
        env["RUSTFLAGS"] = " ".join(x for x in (env.get("RUSTFLAGS", ""), args.rustflags) if x)
        env["CARGO_TERM_COLOR"] = "never"
        env.pop("CARGO_MUTANTS_JOBS", None)  # conflicts with --in-place
        self.env = env

    def log(self, line):
        print(line, file=sys.stderr, flush=True)  # stdout carries only the final JSON

    def cargo(self, side, argv, log_name):
        env = dict(self.env, CARGO_TARGET_DIR=str(self.target_root / f"target-{side}"))
        p = subprocess.run(["cargo", *argv], cwd=self.trees[side], env=env, capture_output=True,
                           text=True, errors="replace")
        log = self.work / "logs" / log_name
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(f"$ cargo {' '.join(argv)}\n## rc={p.returncode}\n{p.stdout}\n{p.stderr}")
        return p.returncode, p.stdout, p.stderr

    def checkouts(self):
        self.work.mkdir(parents=True, exist_ok=True)
        for tree in self.trees.values():
            if tree.exists():
                subprocess.run(["git", "-C", self.args.repo, "worktree", "remove", "--force", str(tree)],
                               capture_output=True)
                shutil.rmtree(tree, ignore_errors=True)
            git(self.args.repo, "worktree", "add", "--detach", str(tree), self.pruned.sha)

    def reset_old(self):
        git(self.trees["old"], "checkout", "--", ".")
        git(self.trees["old"], "clean", "-fdq")

    def render(self, rows, skip):
        """Write the old tree for these deleted rows; returns {path: pieces} and the units."""
        self.reset_old()
        files, units = {}, {}
        by_target = collections.defaultdict(list)
        for row in rows:
            by_target[(row["target"], row["old_path"])].append(row)
        for (target, old_path), group in sorted(by_target.items()):
            if group[0]["kind"] == "file":
                unit = "file:" + old_path
                units[unit] = [(target, tuple(r["chain"]), r["name"], r["id"]) for r in group]
                if unit in skip:
                    continue
                text = self.old.text(old_path)
                files[target] = (text, [(0, len(text), frozenset({unit}))])
                parent = group[0]["parent"]
                if parent:  # a src test file comes back with its `mod` line, at the end of its parent
                    ptext, ppieces = files.get(parent) or (self.pruned.text(parent), [])
                    glue = "" if ptext.endswith("\n") or not ptext else "\n"
                    files[parent] = (ptext + glue + group[0]["decl"], ppieces + [
                        (len(ptext), len(ptext) + len(glue) + len(group[0]["decl"]), frozenset({unit}))])
                continue
            wanted = {}
            for r in group:
                wanted[(tuple(r["chain"]), r["name"])] = r["id"]
                units[r["id"]] = [(target, tuple(r["chain"]), r["name"], r["id"])]
            rel = self.old.rel(old_path)
            text, pieces = restore_file(self.old.text(old_path), self.pruned.text(target), wanted,
                                        test_file=test_only_file(rel), label=old_path, skip=skip)
            prev = files.get(target)
            if prev:  # a whole file's `mod` line went in first: append it again after the restore
                base = len(self.pruned.text(target))
                pieces = pieces + [(p[0] - base + len(text), p[1] - base + len(text), p[2]) for p in prev[1]]
                text += prev[0][base:]
            files[target] = (text, pieces)
        for path, (text, pieces) in files.items():
            base = self.pruned.text(path) if path in self.pruned.blobs else None
            if base is not None and blank(text, pieces) != base:
                raise ScreenError(f"restore changed production code in {path}")
            if base is None and not all(p[0] == 0 and p[1] == len(text) for p in pieces):
                raise ScreenError(f"restore made a new file that is not a whole restored file: {path}")
            out = self.trees["old"] / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(text.encode(errors="surrogateescape"))
        return files, units

    def units_at(self, files, path, line):
        if path not in files:
            return None
        text, pieces = files[path]
        offset = 0
        for _ in range(line - 1):
            nl = text.find("\n", offset)
            if nl < 0:
                break
            offset = nl + 1
        hit = set()
        for start, end, units in pieces:
            if start <= offset < end:
                hit |= units
        return hit or None

    def compile_errors(self, crate):
        rc, out, _ = self.cargo("old", ["test", "-p", crate, "--all-features", "--no-run",
                                        "--message-format=json"], f"{crate}/old-compile.log")
        errors = []
        for line in out.splitlines():
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("reason") != "compiler-message" or msg["message"].get("level") != "error":
                continue
            spans = [s for s in msg["message"].get("spans", []) if s.get("is_primary")] or msg["message"].get("spans", [])
            if not spans:
                continue  # "aborting due to N previous errors"
            places = []
            for s in spans:
                name = s.get("file_name", "")
                if os.path.isabs(name):
                    try:
                        name = str(Path(name).resolve().relative_to(self.trees["old"].resolve()))
                    except ValueError:
                        pass
                places.append((name, s.get("line_start", 0)))
            errors.append(places)
        return rc, errors

    def nextest(self, side, crate, name):
        rc, out, err = self.cargo(side, ["nextest", "run", "-p", crate, "--all-features", "--no-fail-fast"],
                                  f"{crate}/{name}.log")
        return rc, failed_tests(out + "\n" + err)

    def map_failures(self, crate, units, fails):
        """Unit ids whose restored tests are among the failing (binary, test path) pairs."""
        hit, unmapped = set(), []
        for binary, path in fails:
            found = None
            for unit, tests in units.items():
                for target, chain, name, _ in tests:
                    tail = "::".join([*chain, name])
                    if path == tail or path.endswith("::" + tail):
                        if test_binary_ok(self.pruned, target, binary):
                            found = unit
            if found:
                hit.add(found)
            else:
                unmapped.append(f"{binary} {path}".strip())
        return hit, unmapped

    def mutants_list(self, side, crate):
        rc, out, err = self.cargo(side, ["mutants", "--list", "--json", "--package", crate],
                                  f"{crate}/{side}-list.log")
        if rc:
            raise ScreenError(f"cargo mutants --list in {side} exited {rc}: {err.strip()[-400:]}")
        return json.loads(out)

    def mutants_run(self, side, crate, names, tag, timeout=None):
        out = self.work / crate / f"{side}-{tag}"
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        # --in-place: one mutant at a time in this throwaway checkout (cargo-mutants refuses --jobs with it)
        argv = ["mutants", "--package", crate, "--all-features", "--test-tool", "nextest",
                "--in-place", "--no-shuffle", "--output", str(out)]
        for name in names:
            argv += ["--re", "^" + rx_escape(name) + "$"]
        if timeout:
            argv += ["--timeout", str(timeout)]
        rc, _, err = self.cargo(side, argv, f"{crate}/{side}-{tag}.log")
        report = out / "mutants.out" / "outcomes.json"
        if not report.is_file():
            raise ScreenError(f"cargo mutants in {side} exited {rc} without outcomes: {err.strip()[-400:]}")
        return report

    def screen_crate(self, plan, rows):
        crate = plan["crate"]
        rec = {"crate": crate, "deleted": len(plan["deleted"]), "followed_moves": plan["followed_moves"],
               "restored_compiled": 0, "restored_did_not_compile": [], "restored_failed_unmutated": [],
               "subject_removed": plan["subject_removed"], "baseline": None, "skipped": None, "mutants": []}
        self.log(f"## CRATE {crate}: {rec['deleted']} deleted tests to restore")
        rc, fails = self.nextest("pruned", crate, "pruned-unmutated")
        if rc not in (0, 4):
            rec["baseline"] = "Failure"
            rec["skipped"] = ("pruned suite fails unmutated: " + ", ".join(" ".join(filter(None, f)) for f in fails[:5])
                              if fails else f"pruned suite exits {rc} unmutated")
            return rec
        rec["baseline"] = "Success"
        skip, test_units = set(), {}
        for attempt in range(1, 4):
            files, units = self.render(rows, skip)
            test_units = units
            rc, errors = self.compile_errors(crate)
            if rc == 0:
                break
            hit, unmapped = set(), []
            for places in errors:
                found = set()
                for path, line in places:
                    found |= self.units_at(files, path, line) or set()
                if found:
                    hit |= found
                else:
                    unmapped.append(places)
            if unmapped or not hit:
                rec["skipped"] = f"old suite does not compile (round {attempt}): " + json.dumps(unmapped[:3] or errors[:3])
                return rec
            skip |= hit
            self.log(f"## OLD-COMPILE {crate} round {attempt}: {len(hit)} restored items taken out")
        else:
            rec["skipped"] = "old suite does not compile after 3 rounds"
            return rec
        dropped_compile = {u for u in skip if u in test_units}
        for attempt in range(1, 3):
            rc, fails = self.nextest("old", crate, f"old-unmutated-{attempt}")
            if rc in (0, 4):
                break
            hit, unmapped = self.map_failures(crate, {u: t for u, t in test_units.items() if u not in skip}, fails)
            if unmapped or not hit:
                rec["skipped"] = "old suite fails unmutated outside the restored tests: " + ", ".join(unmapped[:5])
                return rec
            skip |= hit
            rec["restored_failed_unmutated"] += sorted(t[3] for u in hit for t in test_units[u])
            files, _ = self.render(rows, skip)
        else:
            rec["skipped"] = "restored tests still fail unmutated after 2 rounds"
            return rec
        rec["restored_did_not_compile"] = sorted(t[3] for u in dropped_compile for t in test_units[u])
        live = [u for u in test_units if u not in skip]
        rec["restored_compiled"] = sum(len(test_units[u]) for u in live)
        self.old_units = {u: test_units[u] for u in live}

        old_k = keyed(self.mutants_list("old", crate))
        new_k = keyed(self.mutants_list("pruned", crate))
        paired = sorted(set(old_k) & set(new_k))
        rng = random.Random(self.seed)
        cands = [k for k in paired if new_k[k]["file"] in plan["candidate_files"]]
        chosen = rng.sample(cands, min(self.args.per_crate, len(cands)))
        if len(chosen) < self.args.per_crate:
            taken = set(cands)
            rest = [k for k in paired if k not in taken]
            chosen += rng.sample(rest, min(self.args.per_crate - len(chosen), len(rest)))
        chosen.sort()
        if not chosen:
            rec["skipped"] = "no mutants in the crate"
            return rec
        names = {"old": [old_k[k]["name"] for k in chosen], "pruned": [new_k[k]["name"] for k in chosen]}
        self.log(f"## MUTANTS {crate}: {len(chosen)} pairs; running the pruned suite")
        runs = {"pruned": [self.mutants_run("pruned", crate, names["pruned"], "run")]}
        res_p, base_p = read_outcomes(runs["pruned"][0])
        if base_p != "Success":
            rec["baseline"], rec["skipped"] = base_p or "missing", "cargo-mutants baseline failed in the pruned suite"
            return rec
        self.log(f"## MUTANTS {crate}: running the old suite")
        runs["old"] = [self.mutants_run("old", crate, names["old"], "run")]
        res_o, base_o = read_outcomes(runs["old"][0])
        if base_o != "Success":
            rec["skipped"] = "cargo-mutants baseline failed in the old suite"
            return rec
        timed = [i for i, k in enumerate(chosen)
                 if "Timeout" in ((res_o.get(names["old"][i]) or {}).get("summary"),
                                  (res_p.get(names["pruned"][i]) or {}).get("summary"))]
        if timed:
            longest = max([(res_o.get(names["old"][i]) or {}).get("duration", 0.0) for i in timed]
                          + [(res_p.get(names["pruned"][i]) or {}).get("duration", 0.0) for i in timed])
            seconds = max(60, math.ceil(2 * longest))
            self.log(f"## TIMEOUT-RERUN {crate}: {len(timed)} pairs at --timeout {seconds}")
            for side, res in (("pruned", res_p), ("old", res_o)):
                again = self.mutants_run(side, crate, [names[side][i] for i in timed], "rerun", seconds)
                res.update(read_outcomes(again)[0])
        for i, k in enumerate(chosen):
            o, p = res_o.get(names["old"][i]), res_p.get(names["pruned"][i])
            entry = {"name_pruned": names["pruned"][i], "name_old": names["old"][i],
                     "old": o["summary"] if o else None, "pruned": p["summary"] if p else None,
                     "caught_by_restored": [], "old_failed_tests": []}
            if o and o["log"]:
                fails = failed_tests(Path(o["log"]).read_text(errors="replace"))
                entry["old_failed_tests"] = [" ".join(filter(None, f)) for f in fails]
                hit, _ = self.map_failures(crate, self.old_units, fails)
                entry["caught_by_restored"] = sorted(t[3] for u in hit for t in self.old_units[u])
            rec["mutants"].append(entry)
        return rec

    def run(self, ranked, deleted):
        self.checkouts()
        crates = []
        for plan in ranked:
            if sum(1 for c in crates if not c["skipped"]) >= self.args.crate_count:
                break
            rows = [r for r in deleted if r["crate"] == plan["crate"] and r["kind"] in ("fn", "file")]
            rec = self.screen_crate(plan, rows)
            if rec["skipped"]:
                self.log(f"## SKIPPED {plan['crate']}: {rec['skipped']}")
            crates.append(rec)
        return crates


def test_binary_ok(tree, target, binary):
    """Does a nextest binary id fit a restored test's file (lib vs integration target)?"""
    if not binary:
        return True
    rel = tree.rel(target)
    if rel.startswith("tests/"):
        stem = rel.split("/")[1].removesuffix(".rs")
        return binary.endswith("::" + stem)
    return "::" not in binary or binary.endswith("::lib")


def markdown(doc):
    lines = [f"# Mutant screen {doc['pruned_ref'][:12]} vs old suite {doc['old_ref'][:12]}", "",
             f"Runner {doc['runner']}, seed {doc['seed']}. Verdict: **{doc['verdict']}** "
             f"({len(doc['lost'])} lost, {len(doc['undecided'])} undecided).", "",
             "| crate | deleted | restored | did not compile | failed unmutated | subject removed | mutants | lost | skipped |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for c in doc["crates"]:
        lost = sum(1 for m in c["mutants"] if m["old"] == "CaughtMutant" and m["pruned"] == "MissedMutant")
        lines.append(f"| {c['crate']} | {c['deleted']} | {c['restored_compiled']} | {len(c['restored_did_not_compile'])} "
                     f"| {len(c['restored_failed_unmutated'])} | {len(c['subject_removed'])} | {len(c['mutants'])} "
                     f"| {lost} | {c['skipped'] or ''} |")
    lines += ["", "| mutant (pruned tree) | old suite | pruned suite | restored tests that caught it |", "|---|---|---|---|"]
    for c in doc["crates"]:
        for m in c["mutants"]:
            lines.append(f"| `{m['name_pruned']}` | {m['old']} | {m['pruned']} | {', '.join(m['caught_by_restored'])} |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--repo", default=str(ROOT))
    ap.add_argument("--old", default=OLD_SUITE_REF, help="the old suite's commit")
    ap.add_argument("--pruned", default="origin/main", help="the pruned suite's commit")
    ap.add_argument("--crates", help="comma-separated crates to screen, in order (default: ranked by deleted tests)")
    ap.add_argument("--crate-count", type=int, default=5)
    ap.add_argument("--per-crate", type=int, default=10)
    ap.add_argument("--work", help="work directory (default <repo>/target/mutant-screen/<pruned sha12>)")
    ap.add_argument("--target-root", help="parent of the two cargo target dirs (default: the work directory)")
    ap.add_argument("--rustflags", default=DEFAULT_RUSTFLAGS, help="added to RUSTFLAGS in both trees")
    ap.add_argument("--plan-only", action="store_true", help="git only: the deleted tests, ranked crates and files")
    ap.add_argument("--report", type=Path, help="re-judge a saved report.json (no cargo)")
    ap.add_argument("--old-outcomes", nargs="+", type=Path, help="old-suite outcomes.json files (no cargo)")
    ap.add_argument("--pruned-outcomes", nargs="+", type=Path, help="pruned-suite outcomes.json files (no cargo)")
    args = ap.parse_args(argv)

    if args.report:
        doc = json.loads(args.report.read_text())
        if doc.get("schema") != SCHEMA:
            raise ScreenError(f"{args.report}: schema {doc.get('schema')} is not {SCHEMA}")
        pairs = [m for c in doc.get("crates", []) for m in c.get("mutants", [])]
        doc = verdict_doc(doc, pairs)
        print(json.dumps({"verdict": doc["verdict"], "lost": doc["lost"], "undecided": doc["undecided"]}, indent=1))
        return 0 if doc["verdict"] == "loses_nothing" else 1
    if args.old_outcomes or args.pruned_outcomes:
        if not (args.old_outcomes and args.pruned_outcomes):
            raise ScreenError("--old-outcomes and --pruned-outcomes go together")
        pairs = compare_outcomes(args.old_outcomes, args.pruned_outcomes)
        doc = verdict_doc({"schema": SCHEMA, "mutants": pairs}, pairs)
        print(json.dumps(doc, indent=1))
        return 0 if doc["verdict"] == "loses_nothing" else 1

    old, pruned = Tree(args.repo, args.old), Tree(args.repo, args.pruned)
    deleted, followed = find_deletions(old, pruned)
    only = [c.strip() for c in args.crates.split(",") if c.strip()] if args.crates else None
    ranked = plan_crates(old, pruned, deleted, followed, only)
    doc = {"schema": SCHEMA, "runner": RUNNER, "old_ref": old.sha, "pruned_ref": pruned.sha,
           "seed": int(pruned.sha[:16], 16)}
    if args.plan_only:
        first = ranked[:args.crate_count]
        doc.update({
            "deleted_total": sum(1 for r in deleted if r["kind"] != "subject_removed"),
            "subject_removed_total": sum(1 for r in deleted if r["kind"] == "subject_removed"),
            "followed_moves": [{"old": a, "pruned": b, "tests": n} for (a, b), n in sorted(followed.items())],
            "crates": ranked,
            "screened_first": [c["crate"] for c in first],
            "mutant_runs": 2 * args.per_crate * len(first),
        })
        print(json.dumps(doc, indent=1))
        return 0
    version = subprocess.run(["cargo", "mutants", "--version"], capture_output=True, text=True).stdout.strip()
    if version != RUNNER:
        raise ScreenError(f"required runner {RUNNER}, found {version or 'none'}")
    screen = Screen(args, old, pruned)
    doc["crates"] = screen.run(ranked, deleted)
    screened = [c for c in doc["crates"] if not c["skipped"]]
    if not screened:
        raise ScreenError("no crate could be screened: " + "; ".join(f"{c['crate']}: {c['skipped']}" for c in doc["crates"]))
    doc = verdict_doc(doc, [m for c in screened for m in c["mutants"]])
    (screen.work / "report.json").write_text(json.dumps(doc, indent=1) + "\n")
    (screen.work / "report.md").write_text(markdown(doc))
    print(json.dumps({"report": str(screen.work / "report.json"), "verdict": doc["verdict"],
                      "lost": doc["lost"], "undecided": doc["undecided"]}, indent=1))
    return 0 if doc["verdict"] == "loses_nothing" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ScreenError, OSError, ValueError, KeyError) as error:
        print("MUTANT-SCREEN-FAILED: " + str(error), file=sys.stderr)
        sys.exit(2)
