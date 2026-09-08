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
    scope is `top` for the file body, `tests` for an inline `mod tests {..}`
    body on the base side and for `tests.rs` / `*_tests.rs` children or an
    inline `mod tests {..}` in any child on the new side.
  - Bodies are compared with the leading visibility keyword stripped; a
    visibility change is reported as INFO, not a failure.
  - An impl block whose header lands in more than one child (or that the base
    file already carried more than once) is compared per associated item
    instead; the header/attribute residue of every part must match the base.
  - Allowed new-side extras: `use` items (any vis, cfg'd or not), `mod` decls,
    `#![..]` inner attributes, `//!` docs, `extern crate`, free comments.
  - Anything the item enumerator does not recognise (e.g. a top-level macro
    invocation) is compared as an opaque residue chunk, 1:1 as well.
Fails CLOSED: any exception prints `SPLIT-CHECK-ERROR` and exits 1.
"""
import difflib
import os
import subprocess
import sys
import textwrap
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rustlex import Doc, canon, enumerate_items, item_text, normalized_fragment, rustfmt, strip_item_vis  # noqa: E402

DIFF_CAP = 60
PLUMBING_KINDS = ("use",)


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
            s += " " + " ".join("#[cfg(%s)]" % c for c in self.cfgs)
        if self.scope != "top":
            s += " (in %s)" % self.scope
        return s


def _dedent(text):
    return textwrap.dedent(text)


def _mod_body(doc, it):
    """Dedented body text of a bodied `mod x { .. }` item (lines strictly
    between the opening and closing brace lines)."""
    return _dedent("\n".join(doc.lines[it["body_open_line"] + 1:it["end_line"]]))


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


def collect(doc, where, scope):
    """Walk a Doc. Returns (items, chunks, has_inline_tests).
    items: list[Item]; chunks: list[(canon, first_line, where)] of unrecognised
    non-blank, non-comment residue; has_inline_tests: a bodied `mod tests`
    was found at top level (its body is walked with scope='tests')."""
    items, chunks = [], []
    has_inline_tests = False
    covered = set()
    for it in enumerate_items(doc):
        covered.update(range(it["lead_start"], it["end_line"] + 1))
        if it["kind"] in PLUMBING_KINDS:
            continue
        if it["kind"] == "mod":
            if it["body_open_line"] is None:
                continue  # `mod x;` declaration = plumbing
            if it["name"] == "tests" and scope == "top":
                has_inline_tests = True
                sub = Doc(_mod_body(doc, it))
                sub_items, sub_chunks, _ = collect(sub, where, "tests")
                items.extend(sub_items)
                chunks.extend(sub_chunks)
                continue
        name = it["header"] if it["kind"] == "impl" else it["name"]
        item = Item(scope, it["kind"], name, it["cfgs"], it["vis"], item_text(doc, it), where)
        if it["kind"] == "impl":
            item.methods, item.residue = _impl_parts(doc, it, scope, where)
        items.append(item)
    # residue: lines not covered by any item whose masked form is non-blank
    run = []
    for i, ml in enumerate(doc.mlines):
        if i not in covered and ml.strip():
            run.append(i)
            continue
        if run:
            chunks.append(_chunk(doc, run, where))
            run = []
    if run:
        chunks.append(_chunk(doc, run, where))
    chunks = [c for c in chunks if c is not None]
    return items, chunks, has_inline_tests


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


def bodies_equal(base, new, assoc=False):
    """(equal, base_norm, new_norm). Fast path: vis-stripped texts of the
    whole-file-formatted docs are byte-identical. Slow path: rustfmt each
    fragment on its own (absorbs the indentation-dependent reflow of an item
    that moved from an inline `mod tests` body to a file top level)."""
    b = strip_item_vis(base.text)
    n = strip_item_vis(new.text)
    if b == n:
        return True, b, n
    b = _normalised(base, assoc)
    n = _normalised(new, assoc)
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


def check(base_rev, old_file, new_dir, out=print):
    root = _repo_root(os.path.abspath(new_dir), os.path.abspath(old_file))
    old_rel = _rel(root, old_file)
    dir_rel = _rel(root, new_dir)
    dir_abs = os.path.join(root, dir_rel)
    problems, infos = [], []

    base_src = _git(root, "show", "%s:%s" % (base_rev, old_rel))
    base_doc = _fmt_doc(base_src, "rustfmt on base %s" % old_rel)
    base_items, base_chunks, base_has_tests = collect(base_doc, old_rel, "top")

    if os.path.exists(os.path.join(root, old_rel)):
        problems.append("FAIL old file still present: %s" % old_rel)
    if not os.path.isdir(dir_abs):
        problems.append("FAIL new dir missing: %s" % dir_rel)
        return _finish(out, problems, infos, old_rel, 0, 0)
    children = sorted(f for f in os.listdir(dir_abs)
                      if f.endswith(".rs") and os.path.isfile(os.path.join(dir_abs, f)))
    mod_rs = os.path.join(dir_abs, "mod.rs")
    if not os.path.isfile(mod_rs):
        problems.append("FAIL %s/mod.rs missing" % dir_rel)
        return _finish(out, problems, infos, old_rel, len(children), 0)

    new_items, new_chunks = [], []
    declared = set()
    for fname in children:
        where = "%s/%s" % (dir_rel, fname)
        with open(os.path.join(dir_abs, fname), encoding="utf-8") as f:
            src = f.read()
        doc = _fmt_doc(src, "rustfmt on %s" % where)
        if fname == "mod.rs":
            for it in enumerate_items(doc):
                if it["kind"] == "mod" and it["body_open_line"] is None:
                    declared.add(it["name"])
        if _is_tests_file(fname):
            if not base_has_tests:
                infos.append("INFO skipped %s (base file had no inline `mod tests`)" % where)
                continue
            scope = "tests"
        else:
            scope = "top"
        items, chunks, _ = collect(doc, where, scope)
        new_items.extend(items)
        new_chunks.extend(chunks)
    for fname in children:
        if fname != "mod.rs" and fname[:-3] not in declared:
            problems.append("FAIL %s/mod.rs does not declare `mod %s;`" % (dir_rel, fname[:-3]))

    p, i, matched = compare_items(base_items, new_items)
    problems.extend(p)
    infos.extend(i)
    problems.extend(compare_chunks(base_chunks, new_chunks))
    return _finish(out, problems, infos, old_rel, len(children), matched)


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
