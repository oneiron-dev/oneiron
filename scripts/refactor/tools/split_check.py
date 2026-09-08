#!/usr/bin/env python3
"""Manifest-free move-only split checker.

    split_check.py <base-rev> <old-file> <new-dir>

Checks that `<old-file>` (as it was at `<base-rev>`) was split into the
directory module `<new-dir>/` (`mod.rs` + children, read from the working tree)
as a pure MOVE: every item of the old file lands in exactly one child,
byte-equivalent after rustfmt, and the children add nothing but module
plumbing. The manifest-driven sibling is `../conformance.sh`; this tool covers
the common case with no manifest.

Rules (see README.md for the full list):
  - Items are matched by (scope, kind, name-or-impl-header canon, cfgs).
    scope is a `::`-joined module path: `top` for the file body, `tests` for
    an inline `mod tests {..}` body, `seam` for a bodied `mod seam {..}`,
    `seam::tests` / `seam::inner` for mods nested inside it, and so on.
  - Base side: a bodied `mod X {..}` (X != tests) is not one opaque item; its
    body is walked recursively with scope `X` and the mod itself becomes a
    "mod record" (name, cfgs, vis, doc/attribute lead).
  - New side: the directory is walked recursively. A subdirectory `D/` that
    holds a `mod.rs` is the nested module `D` (its parent `mod.rs` must declare
    `mod D;`); `D/mod.rs` + `D/*.rs` are collected with scope `<parent>::D`.
    A flat child `D.rs` whose stem matches a base mod record at that level is
    the module `D` flattened into one file. A bodied `mod Y {..}` inside any
    new-side file is collected with scope `<file scope>::Y`. `tests.rs` /
    `*_tests.rs` at any level are `<level>::tests` and are skipped (INFO) when
    the base mod at that level had no inline `mod tests`.
  - Mod records are compared 1:1: a base `mod X` at scope S needs a bodied
    `mod X` at S or a `mod X;` decl in S's `mod.rs` (FAIL missing / duplicate);
    its cfg tuple must match (FAIL); a visibility change is INFO; its `///`
    doc + non-cfg attributes must be on the decl verbatim or as `//!` /
    `#![..]` at the top of `X/mod.rs` / `X.rs`, otherwise INFO. A new-side mod
    (bodied, or a `mod.rs` decl) with no base record is FAIL extra unless it is
    a tests mount or a decl for a sibling `X.rs` child (plumbing).
  - Bodies are compared with the leading visibility keyword stripped; a
    visibility change is reported as INFO, not a failure.
  - An impl block whose header lands in more than one child (or that the base
    file already carried more than once) is compared per associated item
    instead; the header/attribute residue of every part must match the base.
  - Allowed new-side extras: `use` items (any vis, cfg'd or not), `mod` decls
    for sibling children, `#![..]` inner attributes, `//!` docs, `extern
    crate`, free comments.
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

    __slots__ = ("scope", "kind", "name", "cfgs", "vis", "text", "where", "methods", "residue")

    def __init__(self, scope, kind, name, cfgs, vis, text, where):
        self.scope = scope
        self.kind = kind
        self.name = name
        self.cfgs = tuple(cfgs)
        self.vis = vis
        self.text = text
        self.where = where
        self.methods = None
        self.residue = None

    @property
    def key(self):
        return (self.scope, self.kind, self.name, self.cfgs)

    def label(self):
        s = self.name if self.kind == "impl" else "%s %s" % (self.kind, self.name)
        if self.cfgs:
            s += " " + _cfg_str(self.cfgs)
        if self.scope != TOP:
            s += " (in %s)" % self.scope
        return s


def _cfg_str(cfgs):
    return " ".join("#[cfg(%s)]" % c for c in cfgs) if cfgs else "none"


class ModRec:
    """A module boundary: a bodied `mod X {..}` (base or new side) or a
    `mod X;` declaration in a new-side `mod.rs`. `scope` is the scope the mod
    sits in; the mod's own scope is `_sub_scope(scope, name)`. `target` on a
    decl: "file" (sibling `X.rs`), "dir" (`X/mod.rs`) or None (dangling).
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
        self.mods = []          # ModRec: bodied mods (both sides) + mod.rs decls (new side)
        self.tests_scopes = set()  # scopes whose inline `mod tests` was seen, e.g. {"tests", "seam::tests"}

    def mods_in(self, scope):
        return {m.name for m in self.mods if m.scope == scope and m.bodied}


def _dedent(text):
    return textwrap.dedent(text)


def _mod_body(doc, it):
    """Dedented body text of a bodied `mod x { .. }` item (lines strictly
    between the opening and closing brace lines)."""
    return _dedent("\n".join(doc.lines[it["body_open_line"] + 1:it["end_line"]]))


_CFG_ATTR = re.compile(r"^#\s*\[\s*cfg\s*\(")


def _mod_lead(doc, it):
    """(doc lines, attribute canons) of the `///` docs and non-cfg attributes
    leading a mod item. Doc lines are compared with the marker and surrounding
    whitespace stripped."""
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
            if not _CFG_ATTR.match(ms):
                attrs.append(canon("\n".join(doc.lines[i:j])))
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


def _impl_parts(doc, it, scope, where):
    """Associated items of an impl block + its residue (the block with every
    associated item excised, canon form)."""
    methods = []
    covered = set()
    for m in it["methods"]:
        methods.append(Item(scope, m["kind"], m["name"], m["cfgs"], m["vis"],
                            _dedent(item_text(doc, m)), where))
        covered.update(range(m["lead_start"], m["end_line"] + 1))
    rest = [doc.lines[i] for i in range(it["lead_start"], it["end_line"] + 1) if i not in covered]
    return methods, canon("\n".join(rest))


def collect(doc, where, scope, side):
    """Walk a Doc into `side`. Items land in side.items, unrecognised
    non-blank non-comment residue in side.chunks. A bodied `mod tests` marks
    `<scope>::tests` in side.tests_scopes and its body is walked with that
    scope; any other bodied `mod X` becomes a ModRec and its body is walked
    with scope `<scope>::X`. `mod x;` declarations are plumbing here (the
    directory walk records the ones in a `mod.rs`)."""
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
        name = it["header"] if it["kind"] == "impl" else it["name"]
        item = Item(scope, it["kind"], name, it["cfgs"], it["vis"], item_text(doc, it), where)
        if it["kind"] == "impl":
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
    return (canon(text), doc.lines[lines[0]].strip(), where, lines[0] + 1)


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------

def _normalised(item, assoc):
    """rustfmt-normalised, vis-stripped fragment (the slow path)."""
    return normalized_fragment(item.text, assoc, True)


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
    promotions such as `pub(super) fn` / `pub(super) field:` are allowed)."""
    b = strip_inner_vis(strip_item_vis(base.text))
    n = strip_inner_vis(strip_item_vis(new.text))
    if b == n:
        return True, b, n
    b = strip_inner_vis(_normalised(base, assoc))
    n = strip_inner_vis(_normalised(new, assoc))
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


def compare_items(base_items, new_items):
    """Returns (problems, infos, matched_count)."""
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
        if bgroup[0].kind == "impl" and (len(bgroup) > 1 or len(ngroup) > 1):
            p, i = _compare_split_impl(label, bgroup, ngroup)
            problems.extend(p)
            infos.extend(i)
            matched += len(bgroup)
            continue
        if len(bgroup) > 1:
            problems.append("FAIL ambiguous %s appears %d times in base %s" % (label, len(bgroup), bgroup[0].where))
            continue
        if len(ngroup) > 1:
            problems.append("FAIL duplicate %s lands in %s" % (label, ", ".join(n.where for n in ngroup)))
            continue
        base, new = bgroup[0], ngroup[0]
        p, i = _compare_one(label, base, new, assoc=False)
        problems.extend(p)
        infos.extend(i)
        matched += 1
    for key, ngroup in new_groups.items():
        for n in ngroup:
            problems.append("FAIL extra %s in %s" % (n.label(), n.where))
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
    for n in ngroup:
        if n.residue not in base_residues:
            problems.append("FAIL impl residue of split %s in %s differs from base (header/attrs/docs or non-item content)" % (label, n.where))
    bmethods = _group([m for b in bgroup for m in b.methods])
    nmethods = _group([m for n in ngroup for m in n.methods])
    for key, bm in bmethods.items():
        mlabel = "%s of %s" % (bm[0].label(), label)
        nm = nmethods.pop(key, [])
        if len(bm) > 1:
            problems.append("FAIL ambiguous %s appears %d times in base" % (mlabel, len(bm)))
            continue
        if not nm:
            problems.append("FAIL missing %s (base %s) not found in any child" % (mlabel, bm[0].where))
            continue
        if len(nm) > 1:
            problems.append("FAIL duplicate %s lands in %s" % (mlabel, ", ".join(x.where for x in nm)))
            continue
        p, i = _compare_one(mlabel, bm[0], nm[0], assoc=True)
        problems.extend(p)
        infos.extend(i)
    for key, nm in nmethods.items():
        for x in nm:
            problems.append("FAIL extra %s of %s in %s" % (x.label(), label, x.where))
    return problems, infos


def compare_mods(base_mods, new_mods):
    """Mod records 1:1. Returns (problems, infos). A base record needs exactly
    one new-side counterpart (bodied mod in the same scope, or a decl in that
    scope's mod.rs): cfg mismatch = FAIL, vis change = INFO, doc/attribute
    lead neither on the decl nor at the top of the target file = INFO. A
    new-side record without a base one is FAIL extra unless it is a tests
    mount or a decl for a sibling `X.rs` child (plumbing)."""
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
            if _is_tests_mod(n.name):
                continue
            if not n.bodied and n.target == "file":
                continue  # `mod x;` for a sibling child = plumbing
            problems.append("FAIL extra %s in %s" % (n.label(), n.where))
    return problems, infos


def compare_chunks(base_chunks, new_chunks):
    problems = []
    remaining = list(new_chunks)
    for canon_text, first, where, line in base_chunks:
        hits = [c for c in remaining if c[0] == canon_text]
        if not hits:
            problems.append("FAIL missing unrecognised block from base %s:%d (%r) not found in any child" % (where, line, first))
            continue
        if len(hits) > 1:
            problems.append("FAIL duplicate unrecognised block %r lands in %s" % (first, ", ".join("%s:%d" % (h[2], h[3]) for h in hits)))
        remaining.remove(hits[0])
    for canon_text, first, where, line in remaining:
        problems.append("FAIL extra unrecognised block in %s:%d (%r)" % (where, line, first))
    return problems


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


def _walk_dir(root, dir_rel, scope, base, new, problems, infos):
    """Collect one directory level of the new side into `new` with the given
    scope, then recurse into every subdirectory that holds a `mod.rs`.
    Returns the number of `*.rs` files visited (this level + below)."""
    dir_abs = os.path.join(root, dir_rel)
    entries = sorted(os.listdir(dir_abs))
    files = [f for f in entries if f.endswith(".rs") and os.path.isfile(os.path.join(dir_abs, f))]
    subdirs = [d for d in entries if os.path.isdir(os.path.join(dir_abs, d))]
    n_files = len(files)
    if "mod.rs" not in files:
        problems.append("FAIL %s/mod.rs missing" % dir_rel)
        return n_files
    base_mods_here = base.mods_in(scope)
    declared = {}
    mod_doc = None
    for fname in files:
        where = "%s/%s" % (dir_rel, fname)
        with open(os.path.join(dir_abs, fname), encoding="utf-8") as f:
            src = f.read()
        doc = _fmt_doc(src, "rustfmt on %s" % where)
        stem = fname[:-3]
        if fname == "mod.rs":
            mod_doc = doc
            for it in enumerate_items(doc):
                if it["kind"] == "mod" and it["body_open_line"] is None:
                    declared[it["name"]] = it
        if _is_tests_file(fname):
            fscope = _sub_scope(scope, "tests")
            if fscope not in base.tests_scopes:
                infos.append(_skip_tests_info(where, scope))
                continue
        elif stem in base_mods_here:
            fscope = _sub_scope(scope, stem)  # module flattened into one file
        else:
            fscope = scope
        collect(doc, where, fscope, new)
    mod_where = "%s/mod.rs" % dir_rel
    for name, it in declared.items():
        if name + ".rs" in files:
            target, tpath = "file", os.path.join(dir_abs, name + ".rs")
        elif os.path.isfile(os.path.join(dir_abs, name, "mod.rs")):
            target, tpath = "dir", os.path.join(dir_abs, name, "mod.rs")
        else:
            target, tpath = None, None
        new.mods.append(ModRec(scope, name, it["cfgs"], it["vis"], _mod_lead(mod_doc, it), mod_where,
                               bodied=False, target=target,
                               file_lead=_file_lead(tpath) if tpath else None))
    for fname in files:
        if fname != "mod.rs" and fname[:-3] not in declared:
            problems.append("FAIL %s does not declare `mod %s;`" % (mod_where, fname[:-3]))
    for d in subdirs:
        sub_rel = "%s/%s" % (dir_rel, d)
        if not os.path.isfile(os.path.join(dir_abs, d, "mod.rs")):
            if _has_rs_files(os.path.join(dir_abs, d)):
                problems.append("FAIL %s/mod.rs missing" % sub_rel)
            continue
        if d not in declared:
            problems.append("FAIL %s does not declare `mod %s;`" % (mod_where, d))
        if _is_tests_mod(d):
            sub_scope = _sub_scope(scope, "tests")
            if sub_scope not in base.tests_scopes:
                infos.append(_skip_tests_info(sub_rel + "/", scope))
                continue
        else:
            sub_scope = _sub_scope(scope, d)
        n_files += _walk_dir(root, sub_rel, sub_scope, base, new, problems, infos)
    return n_files


def check(base_rev, old_file, new_dir, out=print):
    root = _repo_root(os.path.abspath(new_dir), os.path.abspath(old_file))
    old_rel = _rel(root, old_file)
    dir_rel = _rel(root, new_dir)
    dir_abs = os.path.join(root, dir_rel)
    problems, infos = [], []

    base_src = _git(root, "show", "%s:%s" % (base_rev, old_rel))
    base_doc = _fmt_doc(base_src, "rustfmt on base %s" % old_rel)
    base = Side()
    collect(base_doc, old_rel, TOP, base)

    if os.path.exists(os.path.join(root, old_rel)):
        problems.append("FAIL old file still present: %s" % old_rel)
    if not os.path.isdir(dir_abs):
        problems.append("FAIL new dir missing: %s" % dir_rel)
        return _finish(out, problems, infos, old_rel, 0, 0)

    new = Side()
    n_children = _walk_dir(root, dir_rel, TOP, base, new, problems, infos)
    if not os.path.isfile(os.path.join(dir_abs, "mod.rs")):
        return _finish(out, problems, infos, old_rel, n_children, 0)

    p, i = compare_mods(base.mods, new.mods)
    problems.extend(p)
    infos.extend(i)
    p, i, matched = compare_items(base.items, new.items)
    problems.extend(p)
    infos.extend(i)
    problems.extend(compare_chunks(base.chunks, new.chunks))
    return _finish(out, problems, infos, old_rel, n_children, matched)


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
        print("usage: split_check.py <base-rev> <old-file> <new-dir>", file=sys.stderr)
        return 2
    try:
        return check(*argv)
    except Exception as e:  # fail closed
        traceback.print_exc()
        print("SPLIT-CHECK-ERROR %s: %s" % (type(e).__name__, e))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
