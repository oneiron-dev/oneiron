#!/usr/bin/env python3
"""Manifest-free move-only split checker.

    split_check.py <base-rev> <old-file>[,<old-file>...] <new-dir | new-file>

Checks that `<old-file>` (as it was at `<base-rev>`) was split into the
directory module `<new-dir>/` (`mod.rs` + children, read from the working tree)
as a pure MOVE: every item of the old file lands in exactly one child,
byte-equivalent after rustfmt, and the children add nothing but module
plumbing. The manifest-driven sibling is `../conformance.sh`; this tool covers
the common case with no manifest. Several old files may be given (comma
separated) when one directory absorbs more than one base file; a child module
the old file mounted at `<base-rev>` (`mod x;` / `#[path = ".."] mod y;`)
whose file is gone from the working tree is absorbed as a source
automatically (INFO). When the last argument is a `.rs` FILE the old file is
compared against that one file (single-file mode: no mod.rs / sibling checks).

Rules (see README.md for the full list):
  - Items are matched by (scope, kind, name-or-impl-header canon, cfgs).
    scope is a `::`-joined module path: `top` for the file body, `tests` for
    an inline `mod tests {..}` body, `seam` for a bodied `mod seam {..}`,
    `seam::tests` / `seam::inner` for mods nested inside it, and so on.
  - Base side: a bodied `mod X {..}` (X != tests) is not one opaque item; its
    body is walked recursively with scope `X` and the mod itself becomes a
    "mod record" (name, cfgs, vis, doc/attribute lead).
  - New side: the directory is walked recursively. A subdirectory `D/` that
    holds a `mod.rs` is the nested module `D` (it must be declared by the
    parent level); `D/mod.rs` + `D/*.rs` are collected with scope
    `<parent>::D`. A subdirectory without `mod.rs` but with a sibling `D.rs`
    (Rust-2018 layout) holds children of `D.rs`'s module in `D.rs`'s scope,
    declared from `D.rs`; one with neither is an orphan (FAIL). A flat child
    `D.rs` whose stem matches a base mod record at that level is the module
    `D` flattened into one file. A bodied `mod Y {..}` inside any new-side
    file is collected with scope `<file scope>::Y`. `tests.rs` / `*_tests.rs`
    at any level are `<level>::tests` and are skipped (INFO) when the base mod
    at that level had no inline `mod tests`.
  - Pre-existing children: a new-side file that already exists at
    `<base-rev>` at the same path is skipped when byte-identical (INFO, and it
    needs no declaration); when modified it is compared against its OWN base
    version with the same machinery (INFO `re-plumbed` when only plumbing
    changed, FAIL body/missing otherwise); new content it gained is matched
    against the split's base like any other child.
  - Declarations: a child is declared when any file of its directory level
    (mod.rs or a child) carries a `mod x;` or `#[path = "x.rs"] mod y;` that
    resolves to it.
  - Mod records are compared 1:1: a base `mod X` at scope S needs a bodied
    `mod X` at S or a `mod X;` decl in a file of scope S (FAIL missing /
    duplicate); its cfg tuple must match (FAIL); a visibility change is INFO;
    its `///` doc + non-cfg attributes must be on the decl verbatim or as
    `//!` / `#![..]` at the top of `X/mod.rs` / `X.rs`, otherwise INFO. A
    new-side bodied mod or a decl that mounts a directory the base never had
    is FAIL extra; tests mounts and decls for child files are plumbing.
  - Bodies are compared with the leading visibility keyword stripped; a
    visibility change is reported as INFO, not a failure.
  - String literals (normal, byte, C, raw with any number of `#`) are
    compared byte-for-byte: every whitespace normalisation the checker runs
    (the mod-body / impl-method dedent, the visibility strip, the standalone
    rustfmt pass, the canon tokenisation of residue) sees each literal as a
    one-line placeholder and the literal is put back byte-exact afterwards.
    Whitespace inside a multi-line literal (YAML / JSON fixtures, expected
    output) is semantic; re-indenting it along with the code is FAIL body.
    The one run the compiler itself discards, the whitespace after a
    `\\`-newline continuation in a non-raw string, is compared as skipped.
  - An impl block whose header lands in more than one child (or that the base
    file already carried more than once) is compared per associated item
    instead; the header/attribute residue of every part must match the base.
    Impl headers pair with lifetimes elided: `impl<'a> S<'a>` == `impl S<'_>`
    (a part that uses `'a` nowhere else must be written elided under the
    `single_use_lifetimes` lint); the respelled part is INFO, never FAIL.
  - Allowed new-side extras: `use` items (any vis, cfg'd or not), `mod` decls
    for children, `#![..]` inner attributes, `//!` docs, `extern crate`, free
    comments.
  - Anything the item enumerator does not recognise (e.g. a top-level macro
    invocation) is compared as an opaque residue chunk, 1:1 as well.
Fails CLOSED: any exception prints `SPLIT-CHECK-ERROR` and exits 1.
"""
import difflib
import os
import re
import subprocess
import sys
import textwrap
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rustlex import Doc, canon, enumerate_items, item_text, normalized_fragment, rustfmt, strip_item_vis  # noqa: E402
from rustlex import _CHAR, _RAW_OPEN, _STR_OPEN, _is_ident  # noqa: E402  (string-literal lexing rules, shared with mask())

DIFF_CAP = 60
PLUMBING_KINDS = ("use",)
TOP = "top"


# ---------------------------------------------------------------------------
# git / fs helpers
# ---------------------------------------------------------------------------

def _git(root, *args):
    p = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (" ".join(args), p.stderr.strip()))
    return p.stdout


def _git_show_or_none(root, rev, rel):
    """Content of rev:rel, or None when the path does not exist at rev."""
    p = subprocess.run(["git", "-C", root, "cat-file", "-e", "%s:%s" % (rev, rel)], capture_output=True)
    if p.returncode != 0:
        return None
    return _git(root, "show", "%s:%s" % (rev, rel))


def _repo_root(*candidates):
    """Toplevel of the git repo containing the first existing candidate dir."""
    for c in candidates:
        d = c if os.path.isdir(c) else os.path.dirname(c)
        if d and os.path.isdir(d):
            return _git(d, "rev-parse", "--show-toplevel").strip()
    return _git(os.getcwd(), "rev-parse", "--show-toplevel").strip()


def _rel(root, path):
    rel = os.path.relpath(os.path.abspath(path), root)
    if rel.startswith(".."):
        raise RuntimeError("%s is outside the repository %s" % (path, root))
    return rel.replace(os.sep, "/")


def _is_tests_file(name):
    return name == "tests.rs" or name.endswith("_tests.rs")


def _is_tests_mod(name):
    return name == "tests" or name.endswith("_tests")


def _sub_scope(scope, name):
    """Scope path of module `name` nested in `scope` (`top::D` is written `D`)."""
    return name if scope == TOP else "%s::%s" % (scope, name)


def _has_rs_files(dir_abs):
    for _d, _sub, files in os.walk(dir_abs):
        if any(f.endswith(".rs") for f in files):
            return True
    return False


# ---------------------------------------------------------------------------
# item collection
# ---------------------------------------------------------------------------

class Item:
    """One comparable unit: a top-level item, an impl block, or (for the
    impl-split fallback) an associated item inside an impl block."""

    __slots__ = ("scope", "kind", "name", "cfgs", "vis", "text", "where", "methods", "residue", "header")

    def __init__(self, scope, kind, name, cfgs, vis, text, where):
        self.scope = scope
        self.kind = kind
        self.name = name        # impl: lifetime-elided header canon (the matching key)
        self.cfgs = tuple(cfgs)
        self.vis = vis
        self.text = text
        self.where = where
        self.methods = None
        self.residue = None
        self.header = None      # impl: header canon as written

    @property
    def key(self):
        return (self.scope, self.kind, self.name, self.cfgs)

    def label(self):
        s = (self.header or self.name) if self.kind == "impl" else "%s %s" % (self.kind, self.name)
        if self.cfgs:
            s += " " + _cfg_str(self.cfgs)
        if self.scope != TOP:
            s += " (in %s)" % self.scope
        return s


def _cfg_str(cfgs):
    return " ".join("#[cfg(%s)]" % c for c in cfgs) if cfgs else "none"


class ModRec:
    """A module boundary: a bodied `mod X {..}` (base or new side) or a
    `mod X;` declaration in a new-side file. `scope` is the scope the mod
    sits in; the mod's own scope is `_sub_scope(scope, name)`. `target` on a
    decl: "file" (a child `.rs`), "dir" (a `mod.rs`) or None (dangling).
    `lead` = (doc lines, non-cfg attribute canons); `file_lead` = the same
    read from the top of the target file (`//!` / `#![..]`)."""

    __slots__ = ("scope", "name", "cfgs", "vis", "lead", "where", "bodied", "target", "file_lead")

    def __init__(self, scope, name, cfgs, vis, lead, where, bodied, target=None, file_lead=None):
        self.scope = scope
        self.name = name
        self.cfgs = tuple(cfgs)
        self.vis = vis
        self.lead = lead
        self.where = where
        self.bodied = bodied
        self.target = target
        self.file_lead = file_lead

    @property
    def key(self):
        return (self.scope, self.name)

    def label(self):
        s = "mod %s" % self.name
        if self.scope != TOP:
            s += " (in %s)" % self.scope
        return s


class Side:
    """Everything collected from one side of the comparison."""

    def __init__(self):
        self.items = []
        self.chunks = []
        self.mods = []          # ModRec: bodied mods (both sides) + decls (new side)
        self.tests_scopes = set()  # scopes whose inline `mod tests` was seen, e.g. {"tests", "seam::tests"}

    def mods_in(self, scope):
        return {m.name for m in self.mods if m.scope == scope and m.bodied}


# ---------------------------------------------------------------------------
# string literals: compared byte-for-byte
# ---------------------------------------------------------------------------
#
# Whitespace inside a string literal is semantic (YAML / JSON fixtures,
# expected output). Every normalisation the checker applies to compared text
# -- textwrap.dedent of a mod body or impl method, the visibility strip, the
# standalone rustfmt pass with its 4-space de-wrap, the canon tokenisation of
# residue chunks -- would otherwise touch the leading whitespace of a
# literal's continuation lines, and symmetric damage on both sides hides a
# real difference (a raw YAML fixture re-indented by four spaces when its
# test moved out of an inline `mod tests` parsed differently and failed while
# the checker said OK). So each literal is swapped for a one-line placeholder
# string before any such transform and spliced back byte-exact after it.

_PLACEHOLDER = '"@@SPLIT-CHECK-LITERAL-%d@@"'
_PLACEHOLDER_RE = re.compile(r'"@@SPLIT-CHECK-LITERAL-(\d+)@@"')
_PLACEHOLDER_MARK = "@@SPLIT-CHECK-LITERAL-"


def string_spans(text):
    """[(start, end)] of every string literal in `text` (end exclusive,
    prefix included): normal / byte / C strings with escapes, raw strings
    with any number of `#`. Comments and char literals (`'"'`) are skipped
    with the rules rustlex.mask() uses, so the two never disagree about
    where a literal is. An unterminated literal runs to the end of text."""
    spans = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            i = j
            continue
        boundary = i == 0 or not _is_ident(text[i - 1])
        m = None
        if boundary:
            m = _RAW_OPEN.match(text, i)
            if m:
                close = '"' + m.group(1)
                end = text.find(close, m.end())
                end = n if end < 0 else end + len(close)
                spans.append((i, end))
                i = end
                continue
            m = _STR_OPEN.match(text, i)
        elif c == '"':
            m = _STR_OPEN.match(text, i)
        if m:
            j = m.end()
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                j += 1
                if text[j - 1] == '"':
                    break
            spans.append((i, min(j, n)))
            i = j
            continue
        if c == "'":
            m = _CHAR.match(text, i)
            i = m.end() if m else i + 1
            continue
        i += 1
    return spans


def protect_literals(text):
    """(text with every string literal replaced by a one-line placeholder
    string, [the literals in order]). The placeholder is itself a string
    literal, so every transform in the pipeline (dedent, vis strip, rustfmt,
    canon) carries it through untouched; restore_literals() undoes it."""
    if _PLACEHOLDER_MARK in text:
        raise RuntimeError("source already contains the literal placeholder marker %r" % _PLACEHOLDER_MARK)
    lits, out, pos = [], [], 0
    for s, e in string_spans(text):
        out.append(text[pos:s])
        out.append(_PLACEHOLDER % len(lits))
        lits.append(text[s:e])
        pos = e
    out.append(text[pos:])
    return "".join(out), lits


def restore_literals(text, lits):
    """Splice the literals from protect_literals() back, byte-exact. Every
    placeholder must come back exactly once; anything else means a transform
    ate one, and the checker fails closed rather than compare a lie."""
    seen = []

    def sub(m):
        k = int(m.group(1))
        seen.append(k)
        return lits[k]

    out = _PLACEHOLDER_RE.sub(sub, text)
    if sorted(seen) != list(range(len(lits))):
        raise RuntimeError("string-literal placeholders lost in normalisation (%d of %d restored)" % (len(seen), len(lits)))
    return out


def literal_compare_form(lit):
    """A literal as the compiler reads its whitespace. In a non-raw string
    the newline after a trailing `\\` and every whitespace byte at the start
    of the next line are skipped (string continuation escape), so that run
    is compared as the bare `\\` + newline and a mover re-indenting the
    continuation line with the code is not a change. Every other byte is
    kept; raw strings are returned unchanged. Return `lit` here to compare
    continuation whitespace strictly."""
    if _RAW_OPEN.match(lit):
        return lit
    out, i, n = [], 0, len(lit)
    while i < n:
        c = lit[i]
        if c == "\\" and i + 1 < n:
            if lit[i + 1] == "\n" or lit.startswith("\r\n", i + 1):
                out.append("\\\n")
                i += 2 if lit[i + 1] == "\n" else 3
                while i < n and lit[i] in " \t\r\n":
                    i += 1
                continue
            out.append(lit[i:i + 2])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _dedent(text):
    """textwrap.dedent over the code lines only: the margin is computed
    from, and stripped from, lines outside string literals; a literal's
    continuation lines (the ones whose start lies inside it, closing-quote
    line included) come back byte-exact."""
    protected, lits = protect_literals(text)
    return restore_literals(textwrap.dedent(protected), lits)


def _canon(text):
    """rustlex.canon with string literals carried through byte-exact (canon
    keeps a plain `"…"` as one token but re-lexes the interior of a raw
    string holding quotes)."""
    protected, lits = protect_literals(text)
    return restore_literals(canon(protected), lits)


def _mod_body(doc, it):
    """Body text of a bodied `mod x { .. }` item (lines strictly between the
    opening and closing brace lines), code lines dedented."""
    return _dedent("\n".join(doc.lines[it["body_open_line"] + 1:it["end_line"]]))


_CFG_ATTR = re.compile(r"^#\s*\[\s*cfg\s*\(")
_PATH_ATTR = re.compile(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]')


def _mod_lead(doc, it):
    """(doc lines, attribute canons) of the `///` docs and attributes leading
    a mod item, cfg and `#[path]` attributes excluded (compared / mounting
    plumbing respectively). Doc lines are compared with the marker and
    surrounding whitespace stripped."""
    docs, attrs = [], []
    i = it["lead_start"]
    while i < it["sig_line"]:
        s = doc.lines[i].strip()
        ms = doc.mlines[i].strip()
        if s.startswith("///"):
            docs.append(s[3:].strip())
            i += 1
            continue
        if ms.startswith("#["):
            j, depth = i, 0
            while j < it["sig_line"]:
                depth += doc.mlines[j].count("[") - doc.mlines[j].count("]")
                j += 1
                if depth <= 0:
                    break
            text = "\n".join(doc.lines[i:j])
            if not _CFG_ATTR.match(ms) and not _PATH_ATTR.match(text.strip()):
                attrs.append(canon(text))
            i = j
            continue
        i += 1
    return (tuple(docs), tuple(attrs))


def _file_lead(path):
    """(doc lines, attribute canons) from the leading `//!` / `#![..]` lines
    of a file, in the same shape as _mod_lead (inner attrs read as outer)."""
    docs, attrs = [], []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if not s:
                continue
            if s.startswith("//!"):
                docs.append(s[3:].strip())
                continue
            if s.startswith("#!["):
                attrs.append(canon("#[" + s[3:]))
                continue
            break
    return (tuple(docs), tuple(attrs))


def _resolve_decl(doc, it, dir_abs, fname):
    """(kind, absolute path) of the file a `mod name;` in <dir_abs>/<fname>
    mounts: an explicit `#[path = ".."]` (relative to the file's directory),
    else `name.rs` / `name/mod.rs` under the file's own module directory
    (<dir_abs> for mod.rs, <dir_abs>/<stem>/ for a child), else, leniently,
    a sibling `name.rs` / `name/mod.rs` of the declaring child. kind is
    "file" or "dir" (a mod.rs). (None, None) when nothing exists: rustc
    rejects dangling declarations, the checker treats them as plumbing."""
    lead = "\n".join(doc.lines[it["lead_start"]:it["sig_line"]])
    m = _PATH_ATTR.search(lead)
    if m:
        cands = [os.path.normpath(os.path.join(dir_abs, m.group(1)))]
    else:
        own = dir_abs if fname == "mod.rs" else os.path.join(dir_abs, fname[:-3])
        name = it["name"]
        cands = [os.path.join(own, name + ".rs"), os.path.join(own, name, "mod.rs")]
        if own != dir_abs:
            cands += [os.path.join(dir_abs, name + ".rs"), os.path.join(dir_abs, name, "mod.rs")]
    for c in cands:
        if os.path.isfile(c):
            return ("dir" if os.path.basename(c) == "mod.rs" else "file"), c
    return None, None


def _vanished_children(root, base_rev, old_rel, base_doc):
    """Repo-relative paths of child modules the old file mounted at base_rev
    (top-level `mod x;` / `#[path = ".."] mod y;`) whose file existed at
    base_rev and is gone from the working tree: the split moved them into
    the new directory, so they are part of its source (scope `top`)."""
    out = []
    old_dir = os.path.dirname(old_rel)
    stem = os.path.basename(old_rel)[:-3]
    for it in enumerate_items(base_doc):
        if it["kind"] != "mod" or it["body_open_line"] is not None:
            continue
        lead = "\n".join(base_doc.lines[it["lead_start"]:it["sig_line"]])
        m = _PATH_ATTR.search(lead)
        if m:
            cands = [os.path.normpath(os.path.join(old_dir, m.group(1)))]
        else:
            cands = [os.path.join(old_dir, stem, it["name"] + ".rs"), os.path.join(old_dir, stem, it["name"], "mod.rs")]
        for c in cands:
            c = c.replace(os.sep, "/")
            if os.path.exists(os.path.join(root, c)) or _git_show_or_none(root, base_rev, c) is None:
                continue
            out.append(c)
            break
    return out


def _elide_lifetimes(text):
    """canon-form impl header (or impl residue) with every lifetime parameter
    declared on the impl and used exactly once after the parameter list
    replaced by `'_` and dropped from the list: `impl<'a> S<'a>` and
    `impl S<'_>` are the same header. The workspace `single_use_lifetimes`
    lint forces the elided spelling on a split part that uses the lifetime
    nowhere else, so the two spellings must pair. Anything else (bounded
    lifetimes, `'static`, a lifetime used twice) is left as written."""
    toks = text.split(" ")
    if "impl" not in toks:
        return text
    i = toks.index("impl")
    if i + 1 >= len(toks) or toks[i + 1] != "<":
        return text
    depth, j = 0, i + 1
    while j < len(toks):
        if toks[j] == "<":
            depth += 1
        elif toks[j] == ">":
            depth -= 1
            if depth == 0:
                break
        j += 1
    else:
        return text
    groups, cur, d = [], [], 0
    for t in toks[i + 2:j]:
        if t == "<":
            d += 1
        elif t == ">":
            d -= 1
        if t == "," and d == 0:
            groups.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        groups.append(cur)
    rest = toks[j + 1:]
    kept = []
    for g in groups:
        if len(g) == 2 and g[0] == "'" and g[1] not in ("_", "static"):
            uses = [k for k in range(len(rest) - 1) if rest[k] == "'" and rest[k + 1] == g[1]]
            if len(uses) == 1:
                rest[uses[0] + 1] = "_"
                continue
        kept.append(g)
    head = toks[:i + 1]
    if kept:
        head.append("<")
        for k, g in enumerate(kept):
            if k:
                head.append(",")
            head.extend(g)
        head.append(">")
    return " ".join(head + rest)


def _impl_parts(doc, it, scope, where):
    """Associated items of an impl block + its residue (the block with every
    associated item excised, canon form, impl lifetimes elided)."""
    methods = []
    covered = set()
    for m in it["methods"]:
        methods.append(Item(scope, m["kind"], m["name"], m["cfgs"], m["vis"],
                            _dedent(item_text(doc, m)), where))
        covered.update(range(m["lead_start"], m["end_line"] + 1))
    rest = [doc.lines[i] for i in range(it["lead_start"], it["end_line"] + 1) if i not in covered]
    return methods, _elide_lifetimes(_canon("\n".join(rest)))


def collect(doc, where, scope, side):
    """Walk a Doc into `side`. Items land in side.items, unrecognised
    non-blank non-comment residue in side.chunks. A bodied `mod tests` marks
    `<scope>::tests` in side.tests_scopes and its body is walked with that
    scope; any other bodied `mod X` becomes a ModRec and its body is walked
    with scope `<scope>::X`. `mod x;` declarations are plumbing here (the
    directory walk records the new-side ones)."""
    covered = set()
    for it in enumerate_items(doc):
        covered.update(range(it["lead_start"], it["end_line"] + 1))
        if it["kind"] in PLUMBING_KINDS:
            continue
        if it["kind"] == "mod":
            if it["body_open_line"] is None:
                continue
            sub = _sub_scope(scope, it["name"])
            if it["name"] == "tests":
                side.tests_scopes.add(sub)
            else:
                side.mods.append(ModRec(scope, it["name"], it["cfgs"], it["vis"],
                                        _mod_lead(doc, it), where, bodied=True))
            collect(Doc(_mod_body(doc, it)), where, sub, side)
            continue
        name = _elide_lifetimes(it["header"]) if it["kind"] == "impl" else it["name"]
        item = Item(scope, it["kind"], name, it["cfgs"], it["vis"], item_text(doc, it), where)
        if it["kind"] == "impl":
            item.header = it["header"]
            item.methods, item.residue = _impl_parts(doc, it, scope, where)
        side.items.append(item)
    # residue: lines not covered by any item whose masked form is non-blank
    run = []
    for i, ml in enumerate(doc.mlines):
        if i not in covered and ml.strip():
            run.append(i)
            continue
        if run:
            side.chunks.append(_chunk(doc, run, where))
            run = []
    if run:
        side.chunks.append(_chunk(doc, run, where))
    side.chunks = [c for c in side.chunks if c is not None]


def _chunk(doc, lines, where):
    first = doc.mlines[lines[0]].lstrip()
    if first.startswith("#![") or first.startswith("extern crate"):
        return None  # inner attribute / extern crate = plumbing
    text = "\n".join(doc.lines[i] for i in lines)
    return (_canon(text), doc.lines[lines[0]].strip(), where, lines[0] + 1)


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------

def _normalised(text, assoc):
    """rustfmt-normalised, vis-stripped fragment (the slow path); `text` is
    the placeholder-protected item text."""
    return normalized_fragment(text, assoc, True)


_INNER_VIS = re.compile(r"^(\s*)pub(?:\((?:crate|super|self|in\s+[A-Za-z0-9_:]+)\))?\s+", re.M)
_TUPLE_VIS = re.compile(r"([(,]\s*)pub(?:\((?:crate|super|self|in\s+[A-Za-z0-9_:]+)\))?\s+")


def strip_inner_vis(text):
    """Remove `pub`/`pub(...)` tokens on EVERY line (struct fields, methods
    inside an impl, tuple-struct fields), not only the item's signature line.
    A split routinely promotes a private field or method to pub(super) so a
    sibling child can reach it; that is a visibility change, never a body
    change, and the checker must not fail it."""
    return _TUPLE_VIS.sub(r"\1", _INNER_VIS.sub(r"\1", text))


def bodies_equal(base, new, assoc=False):
    """(equal, base_norm, new_norm). Fast path: vis-stripped texts of the
    whole-file-formatted docs are byte-identical. Slow path: rustfmt each
    fragment on its own (absorbs the indentation-dependent reflow of an item
    that moved from an inline `mod tests` body to a file top level).
    Visibility tokens are stripped on every line on both sides (inner
    promotions such as `pub(super) fn` / `pub(super) field:` are allowed).
    String literals ride through both paths as placeholders and are put
    back byte-exact (continuation whitespace as the compiler reads it, see
    literal_compare_form) before the texts are compared and diffed."""
    bt, blits = protect_literals(base.text)
    nt, nlits = protect_literals(new.text)
    blits = [literal_compare_form(lit) for lit in blits]
    nlits = [literal_compare_form(lit) for lit in nlits]
    b = restore_literals(strip_inner_vis(strip_item_vis(bt)), blits)
    n = restore_literals(strip_inner_vis(strip_item_vis(nt)), nlits)
    if b == n:
        return True, b, n
    # Strip the inner visibility BEFORE rustfmt, as the signature-level strip
    # already is: a `pub(super)` added to a method can push its signature past
    # the width limit and rustfmt would reflow only the new side.
    b = restore_literals(_normalised(strip_inner_vis(bt), assoc), blits)
    n = restore_literals(_normalised(strip_inner_vis(nt), assoc), nlits)
    return b == n, b, n


def _diff(label, base_norm, new_norm, base_where, new_where):
    lines = list(difflib.unified_diff(
        base_norm.split("\n"), new_norm.split("\n"),
        fromfile="base:" + base_where, tofile="head:" + new_where, lineterm="", n=2))
    if len(lines) > DIFF_CAP:
        lines = lines[:DIFF_CAP] + ["... (%d more diff lines)" % (len(lines) - DIFF_CAP)]
    return ["FAIL body %s differs:" % label] + ["  " + ln for ln in lines]


def _group(items):
    groups = {}
    for it in items:
        groups.setdefault(it.key, []).append(it)
    return groups


def compare_items(base_items, new_items, extras=None):
    """Returns (problems, infos, matched_count). New-side items with no base
    counterpart are FAIL extra, or, when `extras` is a list, appended to it
    instead (the pre-existing-child self-compare hands them on)."""
    problems, infos = [], []
    base_groups = _group(base_items)
    new_groups = _group(new_items)
    matched = 0
    for key, bgroup in base_groups.items():
        ngroup = new_groups.pop(key, [])
        label = bgroup[0].label()
        if not ngroup:
            problems.append("FAIL missing %s (base %s) not found in any child" % (label, bgroup[0].where))
            continue
        if bgroup[0].kind == "impl" and (len(bgroup) > 1 or len(ngroup) > 1
                                         or ngroup[0].header != bgroup[0].header):
            p, i = _compare_split_impl(label, bgroup, ngroup)
            problems.extend(p)
            infos.extend(i)
            matched += len(bgroup)
            continue
        if len(bgroup) > 1 or len(ngroup) > 1:
            p, i, m = _compare_same_key(label, bgroup, ngroup, assoc=False)
            problems.extend(p)
            infos.extend(i)
            matched += m
            continue
        base, new = bgroup[0], ngroup[0]
        p, i = _compare_one(label, base, new, assoc=False)
        problems.extend(p)
        infos.extend(i)
        matched += 1
    for key, ngroup in new_groups.items():
        for n in ngroup:
            if extras is not None:
                extras.append(n)
            else:
                problems.append("FAIL extra %s in %s" % (n.label(), n.where))
    return problems, infos, matched


def _compare_same_key(label, bgroup, ngroup, assoc):
    """Items that share one key (anonymous `const _` compile-time asserts,
    a name repeated behind different cfgs): pair each base item with a
    new-side item whose body is identical, in any order. A base item with
    no identical landing is missing; a new-side item left over is a
    duplicate. Returns (problems, infos, matched)."""
    problems, infos = [], []
    remaining = list(ngroup)
    matched = 0
    for base in bgroup:
        hit = None
        for new in remaining:
            if bodies_equal(base, new, assoc)[0]:
                hit = new
                break
        if hit is None:
            problems.append("FAIL missing %s (base %s, one of %d sharing the key) has no byte-identical landing in any child"
                            % (label, base.where, len(bgroup)))
            continue
        remaining.remove(hit)
        p, i = _compare_one(label, base, hit, assoc)
        problems.extend(p)
        infos.extend(i)
        matched += 1
    if remaining:
        problems.append("FAIL duplicate %s lands in %s" % (label, ", ".join(n.where for n in ngroup)))
    return problems, infos, matched


def _compare_one(label, base, new, assoc):
    problems, infos = [], []
    if base.vis != new.vis:
        infos.append("INFO vis %s: %s -> %s (%s)" % (label, base.vis or "private", new.vis or "private", new.where))
    eq, bn, nn = bodies_equal(base, new, assoc)
    if not eq:
        problems.extend(_diff(label, bn, nn, base.where, new.where))
    return problems, infos


def _compare_split_impl(label, bgroup, ngroup):
    """Method-level compare for an impl header that is split across children
    (or duplicated in the base). Every associated item lands exactly once;
    every part's residue (header + attributes + docs, methods excised) must
    equal a base residue."""
    problems, infos = [], []
    base_residues = {b.residue for b in bgroup}
    base_headers = {b.header for b in bgroup}
    for n in ngroup:
        if n.header not in base_headers:
            infos.append("INFO impl header lifetime elided: %s (%s)" % (n.header, n.where))
        if n.residue not in base_residues:
            problems.append("FAIL impl residue of split %s in %s differs from base (header/attrs/docs or non-item content)" % (label, n.where))
    bmethods = _group([m for b in bgroup for m in b.methods])
    nmethods = _group([m for n in ngroup for m in n.methods])
    for key, bm in bmethods.items():
        mlabel = "%s of %s" % (bm[0].label(), label)
        nm = nmethods.pop(key, [])
        if not nm:
            problems.append("FAIL missing %s (base %s) not found in any child" % (mlabel, bm[0].where))
            continue
        if len(bm) > 1 or len(nm) > 1:
            p, i, _ = _compare_same_key(mlabel, bm, nm, assoc=True)
            problems.extend(p)
            infos.extend(i)
            continue
        p, i = _compare_one(mlabel, bm[0], nm[0], assoc=True)
        problems.extend(p)
        infos.extend(i)
    for key, nm in nmethods.items():
        for x in nm:
            problems.append("FAIL extra %s of %s in %s" % (x.label(), label, x.where))
    return problems, infos


def compare_mods(base_mods, new_mods, extras=None):
    """Mod records 1:1. Returns (problems, infos). A base record needs exactly
    one new-side counterpart (bodied mod in the same scope, or a decl in a
    file of that scope): cfg mismatch = FAIL, vis change = INFO, doc/attribute
    lead neither on the decl nor at the top of the target file = INFO. A
    new-side record without a base one is FAIL extra (or handed to `extras`)
    unless it is a tests mount or a decl for a child file (plumbing)."""
    problems, infos = [], []
    new_groups = _group(new_mods)
    for b in base_mods:
        label = b.label()
        cands = new_groups.pop(b.key, [])
        if not cands:
            problems.append("FAIL missing %s (base %s) not found in any child" % (label, b.where))
            continue
        if len(cands) > 1:
            problems.append("FAIL duplicate %s lands in %s" % (label, ", ".join(n.where for n in cands)))
            continue
        n = cands[0]
        if b.cfgs != n.cfgs:
            problems.append("FAIL cfg on %s differs: %s -> %s (%s)" % (label, _cfg_str(b.cfgs), _cfg_str(n.cfgs), n.where))
        if b.vis != n.vis:
            infos.append("INFO vis %s: %s -> %s (%s)" % (label, b.vis or "private", n.vis or "private", n.where))
        if b.lead != n.lead and not (n.file_lead is not None and b.lead == n.file_lead):
            infos.append("INFO doc on %s moved/changed (%s)" % (label, n.where))
    for key, cands in new_groups.items():
        for n in cands:
            if _is_tests_mod(n.name) or (not n.bodied and n.target != "dir"):
                continue  # tests mount / decl for a child file / dangling decl = plumbing
            if extras is not None:
                extras.append(n)
            else:
                problems.append("FAIL extra %s in %s" % (n.label(), n.where))
    return problems, infos


def compare_chunks(base_chunks, new_chunks, extras=None):
    """Every unrecognised block of the base must land exactly once.

    The base may itself hold byte-identical twins (two `proptest!` tails,
    two closing `);` lines): a twin on the new side is only a duplicate when
    the new side holds MORE copies than the base still has to place."""
    problems = []
    remaining = list(new_chunks)
    base_left = {}
    for canon_text, _first, _where, _line in base_chunks:
        base_left[canon_text] = base_left.get(canon_text, 0) + 1
    for canon_text, first, where, line in base_chunks:
        hits = [c for c in remaining if c[0] == canon_text]
        if not hits:
            problems.append("FAIL missing unrecognised block from base %s:%d (%r) not found in any child" % (where, line, first))
            base_left[canon_text] -= 1
            continue
        if len(hits) > base_left[canon_text]:
            problems.append("FAIL duplicate unrecognised block %r lands in %s" % (first, ", ".join("%s:%d" % (h[2], h[3]) for h in hits)))
        base_left[canon_text] -= 1
        remaining.remove(hits[0])
    for canon_text, first, where, line in remaining:
        if extras is not None:
            extras.append((canon_text, first, where, line))
        else:
            problems.append("FAIL extra unrecognised block in %s:%d (%r)" % (where, line, first))
    return problems


def _self_compare(pb, pn, sink):
    """A pre-existing child's new version against its own base version.
    Content it gained (unmatched items / mods / residue) is not an extra
    here: it goes to `sink` (the main new side) as a candidate landing spot
    for the split's items. Returns (problems, infos, n_items_handed_on)."""
    ei, em, ec = [], [], []
    p1, i1, _ = compare_items(pb.items, pn.items, extras=ei)
    p2, i2 = compare_mods(pb.mods, pn.mods, extras=em)
    p3 = compare_chunks(pb.chunks, pn.chunks, extras=ec)
    sink.items.extend(ei)
    sink.mods.extend(em)
    sink.chunks.extend(ec)
    return p1 + p2 + p3, i1 + i2, len(ei)


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def _fmt_doc(src, what):
    try:
        return Doc(rustfmt(src))
    except RuntimeError as e:
        raise RuntimeError("%s: %s" % (what, e))


def _skip_tests_info(where, scope):
    if scope == TOP:
        return "INFO skipped %s (base file had no inline `mod tests`)" % where
    return "INFO skipped %s (base mod %s had no inline `mod tests`)" % (where, scope)


class Walker:
    """New-side traversal: reads files, applies the pre-existing rule,
    resolves `mod` declarations, collects into `new`."""

    def __init__(self, root, base_rev, base, new, problems, infos):
        self.root = root
        self.base_rev = base_rev
        self.base = base
        self.new = new
        self.problems = problems
        self.infos = infos

    def file(self, rel, scope, skip_info=None):
        """Read + rustfmt one new-side file. Pre-existing at base_rev and
        unchanged: skipped (INFO). Pre-existing and modified: compared against
        its own base version, gained content handed to the main compare.
        Otherwise collected with `scope`, unless `skip_info` says the file is
        a tests file with no base counterpart. Returns (doc, pre_existing)."""
        with open(os.path.join(self.root, rel), encoding="utf-8") as f:
            src = f.read()
        doc = _fmt_doc(src, "rustfmt on %s" % rel)
        base_src = _git_show_or_none(self.root, self.base_rev, rel)
        if base_src is None:
            if skip_info:
                self.infos.append(skip_info)
            else:
                collect(doc, rel, scope, self.new)
            return doc, False
        if base_src == src:
            self.infos.append("INFO skipped %s (pre-existing, unchanged)" % rel)
            return doc, True
        pb = Side()
        collect(_fmt_doc(base_src, "rustfmt on base %s" % rel), "%s@%s" % (rel, self.base_rev), scope, pb)
        pn = Side()
        collect(doc, rel, scope, pn)
        p, i, moved = _self_compare(pb, pn, self.new)
        self.problems.extend(p)
        self.infos.extend(i)
        if not p:
            note = " (+%d items moved in)" % moved if moved else ""
            self.infos.append("INFO pre-existing child re-plumbed: %s%s" % (rel, note))
        return doc, True

    def walk_dir(self, dir_rel, scope, inherited=(), owner=None):
        """One directory level with the given scope, then every subdirectory
        that holds Rust files. `owner` = repo-relative path of the sibling
        `D.rs` owning a mod.rs-less (Rust-2018) directory; without it a
        mod.rs is required. `inherited` = declaration targets resolved one
        level up. Returns the number of *.rs files visited."""
        dir_abs = os.path.join(self.root, dir_rel)
        entries = sorted(os.listdir(dir_abs))
        files = [f for f in entries if f.endswith(".rs") and os.path.isfile(os.path.join(dir_abs, f))]
        subdirs = [d for d in entries if os.path.isdir(os.path.join(dir_abs, d)) and _has_rs_files(os.path.join(dir_abs, d))]
        n_files = len(files)
        if owner is None and "mod.rs" not in files:
            self.problems.append("FAIL %s/mod.rs missing" % dir_rel)
            return n_files
        decl_owner = owner or "%s/mod.rs" % dir_rel
        base_mods_here = self.base.mods_in(scope)
        declared = set(inherited)
        scope_of, pre = {}, {}
        for fname in files:
            rel = "%s/%s" % (dir_rel, fname)
            stem = fname[:-3]
            skip = None
            if _is_tests_file(fname):
                fscope = _sub_scope(scope, "tests")
                if fscope not in self.base.tests_scopes:
                    skip = _skip_tests_info(rel, scope)
            elif stem in base_mods_here:
                fscope = _sub_scope(scope, stem)  # module flattened into one file
            else:
                fscope = scope
            doc, pre[fname] = self.file(rel, fscope, skip)
            scope_of[fname] = None if (skip and not pre[fname]) else fscope
            for it in enumerate_items(doc):
                if it["kind"] != "mod" or it["body_open_line"] is not None:
                    continue
                kind, target = _resolve_decl(doc, it, dir_abs, fname)
                if target:
                    declared.add(target)
                if not pre[fname]:
                    self.new.mods.append(ModRec(fscope, it["name"], it["cfgs"], it["vis"], _mod_lead(doc, it), rel,
                                                bodied=False, target=kind,
                                                file_lead=_file_lead(target) if target else None))
        for fname in files:
            if fname != "mod.rs" and not pre[fname] and os.path.join(dir_abs, fname) not in declared:
                self.problems.append("FAIL %s does not declare `mod %s;`" % (decl_owner, fname[:-3]))
        for d in subdirs:
            sub_rel = "%s/%s" % (dir_rel, d)
            sub_abs = os.path.join(dir_abs, d)
            if os.path.isfile(os.path.join(sub_abs, "mod.rs")):
                if os.path.join(sub_abs, "mod.rs") not in declared:
                    self.problems.append("FAIL %s does not declare `mod %s;`" % (decl_owner, d))
                if _is_tests_mod(d):
                    sub_scope = _sub_scope(scope, "tests")
                    if sub_scope not in self.base.tests_scopes:
                        self.infos.append(_skip_tests_info(sub_rel + "/", scope))
                        continue
                else:
                    sub_scope = _sub_scope(scope, d)
                n_files += self.walk_dir(sub_rel, sub_scope, declared)
            elif d + ".rs" in files:
                sub_scope = scope_of[d + ".rs"]
                if sub_scope is None:
                    self.infos.append(_skip_tests_info(sub_rel + "/", scope))
                    continue
                n_files += self.walk_dir(sub_rel, sub_scope, declared, owner="%s/%s.rs" % (dir_rel, d))
            else:
                self.problems.append("FAIL orphan directory %s (no mod.rs and no sibling %s.rs)" % (sub_rel, d))
        return n_files


def check(base_rev, old_files, new_path, out=print):
    old_list = [f for f in old_files.split(",") if f]
    root = _repo_root(os.path.abspath(new_path), os.path.abspath(old_list[0]))
    old_rels = [_rel(root, f) for f in old_list]
    old_label = ",".join(old_rels)
    new_rel = _rel(root, new_path)
    new_abs = os.path.join(root, new_rel)
    problems, infos = [], []

    base = Side()
    sources = list(old_rels)
    for old_rel in sources:
        base_doc = _fmt_doc(_git(root, "show", "%s:%s" % (base_rev, old_rel)), "rustfmt on base %s" % old_rel)
        collect(base_doc, old_rel, TOP, base)
        if os.path.exists(os.path.join(root, old_rel)):
            problems.append("FAIL old file still present: %s" % old_rel)
        for child in _vanished_children(root, base_rev, old_rel, base_doc):
            if child not in sources:
                sources.append(child)
                infos.append("INFO absorbed %s (child module of %s at base, gone from the tree)" % (child, old_rel))

    new = Side()
    walker = Walker(root, base_rev, base, new, problems, infos)
    if new_rel.endswith(".rs"):
        if not os.path.isfile(new_abs):
            problems.append("FAIL new file missing: %s" % new_rel)
            return _finish(out, problems, infos, old_label, 0, 0)
        walker.file(new_rel, TOP)
        n_children = 1
    else:
        if not os.path.isdir(new_abs):
            problems.append("FAIL new dir missing: %s" % new_rel)
            return _finish(out, problems, infos, old_label, 0, 0)
        n_children = walker.walk_dir(new_rel, TOP)
        if not os.path.isfile(os.path.join(new_abs, "mod.rs")):
            return _finish(out, problems, infos, old_label, n_children, 0)

    p, i = compare_mods(base.mods, new.mods)
    problems.extend(p)
    infos.extend(i)
    p, i, matched = compare_items(base.items, new.items)
    problems.extend(p)
    infos.extend(i)
    problems.extend(compare_chunks(base.chunks, new.chunks))
    return _finish(out, problems, infos, old_label, n_children, matched)


def _finish(out, problems, infos, old_rel, n_children, n_items):
    for line in problems:
        out(line)
    for line in infos:
        out(line)
    if problems:
        out("SPLIT-CHECK FAIL %s: %d problem(s)" % (old_rel, sum(1 for p in problems if p.startswith("FAIL"))))
        return 1
    out("SPLIT-CHECK OK %s -> %d children (%d items)" % (old_rel, n_children, n_items))
    return 0


def main(argv):
    if len(argv) != 3 or argv[0] in ("-h", "--help"):
        print("usage: split_check.py <base-rev> <old-file>[,<old-file>...] <new-dir | new-file>", file=sys.stderr)
        return 2
    try:
        return check(*argv)
    except Exception as e:  # fail closed
        traceback.print_exc()
        print("SPLIT-CHECK-ERROR %s: %s" % (type(e).__name__, e))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
