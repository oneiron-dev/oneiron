#!/usr/bin/env python3
"""Conformance checks 1-8 (check 7, the cargo gate, is run by conformance.sh).

v2 — TS D6 + D9.4. Manifest-driven. Base-side content from `git show <base>:<p>`,
HEAD-side from `git show HEAD:<p>`. File access goes through base_file()/head_file()
so the self-test can inject constructed trees.

Order (first failure exits non-zero, no override):
  1 forbidden-zone (liftable guard) + allowed-files
  2 surface inventory (pub decls + impl headers) + flat-name-set diff (lib.rs)
  E declared-edit validation (`## edit` shape + existence)
  3 moved-block byte-equivalence (+ HEAD-src zero-match removal; edits applied to base)
  4 frozen anchors (edits applied to base)
  5 api name-uniqueness
  6 error-literal inventory
  8 insertion integrity (per-item excision; private-smuggle detector)
  X src-exhaustion (T12: reconstruct+excise deleted src, residue whitespace-only)
"""
import collections
import glob
import os
import re
import subprocess
import sys

try:
    import rustlex as R
except ImportError:  # embedded into conformance.sh: rustlex prepended into this module
    R = sys.modules[__name__]

# Guard zone (in-flight collision guard, TS D6 #1). LIFTED by owner 2026-07-08
# (ONE-1443=063340de5, ONE-1554=b2437d700 both landed). When lifted, these files
# are allowed iff a stage lists them; when not, they are globally forbidden.
# The old batch/outbound/anchored_annotation LEAVE-ALONE fence is GONE.
GUARD = [
    "crates/oneiron/src/agent_def.rs", "crates/oneiron/src/agent_def/",
    "crates/oneiron/src/edit_settle.rs", "crates/oneiron/src/edit_settle/",
]
LIFTED = True


class Violation(Exception):
    def __init__(self, check, msg):
        self.check = check
        super().__init__(msg)


# ---- file access (injection points for the self-test) --------------------

def git_show(root, rev, path):
    p = subprocess.run(["git", "-C", root, "show", f"{rev}:{path}"],
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


def base_file(root, base, path):
    return git_show(root, base, path)


def head_file(root, path):
    return git_show(root, "HEAD", path)


def changed_files(root, base):
    p = subprocess.run(["git", "-C", root, "diff", "--name-only", base, "HEAD"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise Violation(0, f"git diff failed: {p.stderr.strip()}")
    return [ln for ln in p.stdout.split("\n") if ln.strip()]


# ---- manifest parsing ----------------------------------------------------

TSV_COLS = ["kind", "container", "item_name", "cfg", "src_file", "dst_file", "header_change"]


def parse_tsv(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.rstrip("\n")
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            parts = ln.split("\t")
            if len(parts) != 7:
                raise Violation(0, f"bad TSV row ({len(parts)} cols): {ln!r}")
            rows.append(dict(zip(TSV_COLS, parts)))
    return rows


def parse_decls(path):
    sections = collections.defaultdict(list)
    cur = None
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.rstrip("\n")
            if ln.startswith("## "):
                cur = ln[3:].strip()
                sections.setdefault(cur, [])
                continue
            if cur is None or ln.strip() == "":
                continue
            sections[cur].append(ln)
    return sections


def _parse_edits(decls):
    """`## edit` rows: file<TAB>old<TAB>new (old/new stripped). Returns list."""
    out = []
    for ln in decls.get("edit", []):
        parts = ln.split("\t")
        if len(parts) != 3:
            raise Violation(0, f"bad edit row (file<TAB>old<TAB>new): {ln!r}")
        out.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
    return out


def _parse_fragedits(decls):
    """`## frag-edit` rows: src_file<TAB>old<TAB>new — applied to a moved item's
    base fragment (TS D9.4 #2, the ForeignWorldId doctest class)."""
    out = []
    for ln in decls.get("frag-edit", []):
        parts = ln.split("\t")
        if len(parts) != 3:
            raise Violation(0, f"bad frag-edit row: {ln!r}")
        out.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
    return out


def _parse_comments(decls):
    """`## comment` rows: src:start-end<TAB>dst (interstitial // blocks)."""
    out = []
    for ln in decls.get("comment", []):
        parts = ln.split("\t")
        if len(parts) != 2:
            raise Violation(0, f"bad comment row (src:start-end<TAB>dst): {ln!r}")
        loc, dst = parts[0].strip(), parts[1].strip()
        try:
            src, rng = loc.rsplit(":", 1)
            a, b = rng.split("-")
            out.append((src, int(a), int(b), dst))
        except ValueError:
            raise Violation(0, f"bad comment row (src:start-end<TAB>dst): {ln!r}")
    return out


def _parse_adds(decls):
    """`## add` rows: file<TAB>exact-stripped-line — non-item lines a stage adds to
    a dst (module doc, imports, `impl Vault {`, `}`, `mod tests;`)."""
    out = collections.defaultdict(list)
    for ln in decls.get("add", []):
        parts = ln.split("\t", 1)
        if len(parts) != 2:
            raise Violation(0, f"bad add row (file<TAB>line): {ln!r}")
        out[parts[0].strip()].append(parts[1])
    return out


def _strip_nonblank(text):
    return [ln.strip() for ln in text.split("\n") if ln.strip()]


def _is_use(s):
    return s.startswith("use ") or s.startswith("pub use ") or s.startswith("pub(crate) use ")


def _content_lines(text):
    """Stripped non-blank lines EXCLUDING `use` statements — check-8 accounting
    ignores imports (executor-reconciled per TS D2.3, gate-verified; a private
    `use` cannot smuggle code behavior, and smuggled items are still caught)."""
    return [s for s in (ln.strip() for ln in text.split("\n")) if s and not _is_use(s)]


def _nonuse_lines(text):
    """Stripped non-blank lines excluding whole use STATEMENTS — multi-line
    aware, unlike _content_lines: a `use …::{` header pulls its continuation
    lines (through the terminating `;`) out of the remainder too. A use
    statement cannot contain an interior `;`, so scanning to the first `;`
    is exact."""
    lines = text.split("\n")
    skip = set()
    i = 0
    while i < len(lines):
        if _is_use(lines[i].strip()):
            j = i
            skip.add(j)
            while ";" not in lines[j] and j + 1 < len(lines):
                j += 1
                skip.add(j)
            i = j + 1
        else:
            i += 1
    out = []
    for k, ln in enumerate(lines):
        s = ln.strip()
        if s and k not in skip:
            out.append(s)
    return out


# ---- check 1: forbidden zone + allowed files -----------------------------

def check1(root, base, decls):
    changed = changed_files(root, base)
    forbid = ([] if LIFTED else list(GUARD)) + [x.strip() for x in decls.get("forbid", [])]
    allowed = set(x.strip() for x in decls.get("allowed", []))
    for f in changed:
        for fb in forbid:
            if fb.endswith("/"):
                if f.startswith(fb):
                    raise Violation(1, f"forbidden-zone file touched: {f} (under {fb})")
            elif f == fb:
                raise Violation(1, f"forbidden-zone file touched: {f}")
        if f not in allowed:
            raise Violation(1, f"changed file not in allowed list: {f}")
    return (f"OK check 1 (forbidden-zone{' [guard lifted]' if LIFTED else ''} + "
            f"allowed-files): {len(changed)} changed file(s)")


# ---- check 2: surface inventory + flat-name-set --------------------------

def _counter_diff(base_c, head_c):
    return head_c - base_c, base_c - head_c


def _parse_signed(lines):
    added, removed = collections.Counter(), collections.Counter()
    for ln in lines:
        if not ln:
            continue
        sign, content = ln[0], ln[1:].strip()
        if sign == "+":
            added[content] += 1
        elif sign == "-":
            removed[content] += 1
        else:
            raise Violation(2, f"bad decl/impl-delta line (no +/-): {ln!r}")
    return added, removed


def _parse_signed_impl(lines):
    added, removed = collections.Counter(), collections.Counter()
    for ln in lines:
        if not ln:
            continue
        sign, content = ln[0], ln[1:].strip()
        if sign not in "+-":
            raise Violation(2, f"bad impl-delta sign (expected leading +/-): {ln!r}")
        parts = content.split("\t")
        if len(parts) != 2:
            raise Violation(2, f"bad impl-delta line (file<TAB>header): {ln!r}")
        (added if sign == "+" else removed)[(parts[0].strip(), parts[1].strip())] += 1
    return added, removed


def check2(root, base, decls):
    changed = [f for f in changed_files(root, base)
               if f.endswith(".rs") and f.startswith("crates/")]
    base_inv, head_inv = collections.Counter(), collections.Counter()
    base_impl, head_impl = collections.Counter(), collections.Counter()
    lib_touched = False
    for f in changed:
        if f.endswith("/lib.rs"):
            lib_touched = True
        bt = base_file(root, base, f)
        if bt is not None:
            d = R.Doc(bt)
            base_inv.update(R.inventory(d))
            base_impl.update((f, h) for h in R.impl_headers(d))
        ht = head_file(root, f)
        if ht is not None:
            d = R.Doc(ht)
            head_inv.update(R.inventory(d))
            head_impl.update((f, h) for h in R.impl_headers(d))

    add, rem = _counter_diff(base_inv, head_inv)
    exp_add, exp_rem = _parse_signed(decls.get("decl", []))
    if add != exp_add or rem != exp_rem:
        _report_diff(2, "declaration inventory (2a)", add, rem, exp_add, exp_rem)
    add_i, rem_i = _counter_diff(base_impl, head_impl)
    exp_add_i, exp_rem_i = _parse_signed_impl(decls.get("impl-delta", []))
    if add_i != exp_add_i or rem_i != exp_rem_i:
        _report_diff(2, "impl-header inventory (2b)", add_i, rem_i, exp_add_i, exp_rem_i,
                     fmt=lambda t: f"{t[0]}\t{t[1]}")

    flat_note = ""
    if lib_touched or decls.get("flat-name-check"):
        libpath = "crates/oneiron/src/lib.rs"
        bt = base_file(root, base, libpath)
        ht = head_file(root, libpath)
        if bt is not None and ht is not None:
            bset = R.flat_names(R.Doc(bt))
            hset = R.flat_names(R.Doc(ht))
            if bset != hset:
                raise Violation(2, "flat-name façade SET changed (must diff empty):\n"
                                   f"  removed: {sorted(bset - hset)}\n  added: {sorted(hset - bset)}")
            flat_note = f", flat-name set stable ({len(bset)})"
    return (f"OK check 2 (surface inventory): {len(add)} decl+ / {len(rem)} decl- / "
            f"{len(add_i)} impl+ / {len(rem_i)} impl-{flat_note}")


def _report_diff(check, label, add, rem, exp_add, exp_rem, fmt=str):
    lines = [f"{label} mismatch (actual HEAD-vs-BASE vs manifest):"]
    for tag, actual, expected in (("added(+)", add, exp_add), ("removed(-)", rem, exp_rem)):
        for k in sorted(expected - actual, key=fmt):
            lines.append(f"  {tag} declared but MISSING: {fmt(k)}")
        for k in sorted(actual - expected, key=fmt):
            lines.append(f"  {tag} observed but UNDECLARED: {fmt(k)}")
    raise Violation(check, "\n".join(lines))


# ---- check E: declared-edit validation -----------------------------------

def checkE(root, base, decls, tsv):
    edits = _parse_edits(decls)
    fragedits = _parse_fragedits(decls)
    for f, old, new in edits:
        if not R.edit_delta_ok(old, new):
            raise Violation("E", f"illegal edit delta (not a single ::-path region): "
                               f"{f}: {old!r} -> {new!r}")
        bt = base_file(root, base, f)
        if bt is None:
            raise Violation("E", f"edit base file missing: {f}")
        base_lines = _strip_nonblank(bt)
        if base_lines.count(old) == 0:
            raise Violation("E", f"edit old-line not present at BASE {f}: {old!r}")
        ht = head_file(root, f)
        head_lines = _strip_nonblank(ht) if ht is not None else []
        if head_lines.count(new) == 0:
            raise Violation("E", f"edit new-line not present at HEAD {f}: {new!r}")
        if head_lines.count(old) != 0:
            raise Violation("E", f"edit old-line still present at HEAD {f}: {old!r}")
    for src, old, new in fragedits:
        if not R.edit_delta_ok(old, new):
            raise Violation("E", f"illegal frag-edit delta: {src}: {old!r} -> {new!r}")
        bt = base_file(root, base, src)
        if bt is None or old not in _strip_nonblank(bt):
            raise Violation("E", f"frag-edit old-line not at BASE {src}: {old!r}")
    return f"OK check E (declared edits): {len(edits)} consumer edit(s), {len(fragedits)} frag-edit(s)"


def _edits_for_file(edits, f):
    return [(old, new) for (ef, old, new) in edits if ef == f]


# ---- check 3: moved-block byte equivalence -------------------------------

def _exactly_one(matches, where, row):
    if len(matches) == 0:
        raise Violation(3, f"item NOT FOUND in {where} (item not yet moved / wrong key): "
                           f"kind={row['kind']} container={row['container']!r} "
                           f"name={row['item_name']!r} cfg={row['cfg']!r}")
    if len(matches) > 1:
        raise Violation(3, f"AMBIGUOUS: {len(matches)} matches in {where}: "
                           f"kind={row['kind']} name={row['item_name']!r}")
    return matches[0]


def mod_inner(doc, it):
    mls = doc.mlines[it["sig_line"]].lstrip()
    start_off = doc.loff[it["sig_line"]] + (len(doc.mlines[it["sig_line"]]) - len(mls))
    bo, eo = R._scan_extent(doc, start_off)
    return doc.src[bo + 1:eo]


def _find_row(doc, row):
    if row["kind"] == "method":
        return R.find_item(doc, "method", row["container"], row["item_name"], row["cfg"])
    if row["kind"] == "impl":
        return R.find_item(doc, "impl", "-", row["item_name"], row["cfg"])
    if row["container"] and row["container"] not in ("-", ""):
        return R.find_item(doc, row["kind"], row["container"], row["item_name"], row["cfg"])
    return R.find_item(doc, row["kind"], "-", row["item_name"], row["cfg"])


def check3(root, base, tsv, decls):
    edits = _parse_edits(decls)
    fragedits = _parse_fragedits(decls)
    n = 0
    for row in tsv:
        bt = base_file(root, base, row["src_file"])
        if bt is None:
            raise Violation(3, f"src_file missing at base: {row['src_file']}")
        bdoc = R.Doc(bt)

        if row["kind"] == "mod":
            bm = _exactly_one(R.find_item(bdoc, "mod", "-", row["item_name"], row["cfg"]),
                              f"BASE {row['src_file']}", row)
            base_frag = mod_inner(bdoc, bm)
            fe = [(o, nw) for (s, o, nw) in fragedits if s == row["src_file"]]
            base_frag = R.apply_edits(base_frag, fe)
            ht = head_file(root, row["dst_file"])
            if ht is None:
                raise Violation(3, f"dst not present — item not yet moved: {row['dst_file']}")
            # mod_inner starts right after `{`, so the fragment carries a leading
            # newline that rustfmt preserves — strip outer blank lines on both
            # sides before comparing.
            base_norm = R.rustfmt(base_frag.strip("\n") + "\n").rstrip("\n")
            head_norm = R.rustfmt(ht.strip("\n") + "\n").rstrip("\n")
            if base_norm != head_norm:
                raise Violation(3, f"MOD body mismatch: {row['src_file']}:mod {row['item_name']} "
                                   f"!= {row['dst_file']}")
            # src-side: the inline mod must be gone, replaced by a declaration-only
            # mount (`mod NAME;`) so cargo actually wires the new dst file — without
            # this a copy-left-behind (or unwired dst) passes as a "move".
            hsrc = head_file(root, row["src_file"])
            if hsrc is None:
                raise Violation(3, f"src missing at HEAD for mod row: {row['src_file']}")
            hm = _exactly_one(R.find_item(R.Doc(hsrc), "mod", "-", row["item_name"], row["cfg"]),
                              f"HEAD {row['src_file']}", row)
            if hm["body_open_line"] is not None:
                raise Violation(3, f"inline mod {row['item_name']} still has a body in src at HEAD "
                                   f"({row['src_file']}) — expected declaration-only mount "
                                   f"(mod {row['item_name']};)")
            n += 1
            continue

        bm = _exactly_one(_find_row(bdoc, row), f"BASE {row['src_file']}", row)
        base_text = R.item_text(bdoc, bm)
        fe = [(o, nw) for (s, o, nw) in fragedits if s == row["src_file"]]
        base_text = R.apply_edits(base_text, _edits_for_file(edits, row["src_file"]) + fe)

        ht = head_file(root, row["dst_file"])
        if ht is None:
            raise Violation(3, f"dst not present — item not yet moved: {row['dst_file']} "
                               f"(item {row['item_name']})")
        hdoc = R.Doc(ht)
        hm = _exactly_one(_find_row(hdoc, row), f"HEAD {row['dst_file']}", row)
        head_text = R.item_text(hdoc, hm)

        if row["src_file"] != row["dst_file"]:
            hsrc = head_file(root, row["src_file"])
            if hsrc is not None:
                still = _find_row(R.Doc(hsrc), row)
                if len(still) != 0:
                    raise Violation(3, f"item STILL present in src at HEAD "
                                       f"({row['src_file']}): {row['item_name']} — copy left behind")

        is_fn = row["kind"] in ("method", "fn")
        hc = row["header_change"] == "yes"
        try:
            base_norm = R.normalized_fragment(base_text, is_fn, hc)
            head_norm = R.normalized_fragment(head_text, is_fn, hc)
        except Exception as e:
            raise Violation(3, f"rustfmt/normalise failed for {row['item_name']}: {e}")
        if base_norm != head_norm:
            raise Violation(3, f"MOVED-BLOCK mismatch: {row['item_name']} "
                               f"({row['src_file']} -> {row['dst_file']})\n"
                               + _first_diff(base_norm, head_norm))
        n += 1
    return f"OK check 3 (moved-block equivalence): {n} item(s) byte-identical"


def _first_diff(a, b):
    al, bl = a.split("\n"), b.split("\n")
    for i in range(max(len(al), len(bl))):
        x = al[i] if i < len(al) else "<eof>"
        y = bl[i] if i < len(bl) else "<eof>"
        if x != y:
            return f"    first diff @ line {i+1}:\n      BASE: {x!r}\n      HEAD: {y!r}"
    return "    (lengths differ)"


# ---- check 4: frozen anchors ---------------------------------------------

def check4(root, base, decls):
    edits = _parse_edits(decls)
    n = 0
    for ln in decls.get("anchors", []):
        parts = ln.split("\t")
        if len(parts) != 5:
            raise Violation(4, f"bad anchor row (need 5 cols): {ln!r}")
        kind, container, name, cfg, f = [p.strip() for p in parts]
        bt = base_file(root, base, f)
        ht = head_file(root, f)
        if bt is None or ht is None:
            raise Violation(4, f"anchor file missing base/head: {f}")
        bdoc, hdoc = R.Doc(bt), R.Doc(ht)
        row = {"kind": kind, "container": container, "item_name": name, "cfg": cfg}
        bm = _exactly_one(_find_row(bdoc, row), f"BASE {f}", row)
        hm = _exactly_one(_find_row(hdoc, row), f"HEAD {f}", row)
        is_fn = kind in ("method", "fn")
        base_text = R.apply_edits(R.item_text(bdoc, bm), _edits_for_file(edits, f))
        base_norm = R.normalized_fragment(base_text, is_fn, False)
        head_norm = R.normalized_fragment(R.item_text(hdoc, hm), is_fn, False)
        if base_norm != head_norm:
            raise Violation(4, f"FROZEN ANCHOR changed: {kind} {name} in {f}\n"
                               + _first_diff(base_norm, head_norm))
        n += 1
    return f"OK check 4 (frozen anchors): {n} anchor(s) unchanged"


# ---- check 5: name-uniqueness (api stages) -------------------------------

def check5(root, stage, decls):
    globs = [g.strip() for g in decls.get("uniqueness", [])]
    if not globs:
        return "OK check 5 (name-uniqueness): skipped"
    names = collections.Counter()
    seen = 0
    for g in globs:
        for f in sorted(glob.glob(os.path.join(root, g))):
            rel = os.path.relpath(f, root)
            ht = head_file(root, rel)
            if ht is None:
                continue
            seen += 1
            for it in R.enumerate_items(R.Doc(ht)):
                if it["kind"] in ("impl", "use", "mod") or not it["name"]:
                    continue
                # key by Rust namespace: a type and a value sharing a name do not
                # collide under glob re-exports, so they must not trip the gate
                ns = {"struct": "type", "enum": "type", "trait": "type", "type": "type",
                      "union": "type", "fn": "value", "const": "value",
                      "static": "value"}.get(it["kind"], it["kind"])
                names[(ns, it["name"])] += 1
    dups = {k: v for k, v in names.items() if v > 1}
    if dups:
        raise Violation(5, "duplicate top-level names across modules: "
                           + ", ".join(f"{k[1]} ({k[0]})×{v}" for k, v in sorted(dups.items())))
    return f"OK check 5 (name-uniqueness): {seen} file(s), no duplicates"


# ---- check 6: error-literal inventory ------------------------------------

_ERRLIT = re.compile(r'Error::(?:Invalid\w+Body|InvariantViolation|CorruptedIndex|Invalid\w+|MaintenanceKindNotWritable)\(\s*"(?:\\.|[^"\\])*"')

# scaffolding lines that legitimately remain after every item is excised from a
# deleted file (check X): module doc, imports, attrs, mod decls, mod-tests shell braces.
_SCAFFOLD = re.compile(r'^(//!|use\s|pub\s+use\s|pub\(crate\)\s+use\s|#!?\[|(pub(\([^)]*\))?\s+)?mod\b|\})')


def _strip_line_comments(text):
    return "\n".join(re.sub(r"//.*$", "", ln) for ln in text.split("\n"))


def check6(root, base, decls):
    files = [x.strip() for x in decls.get("error-literal", [])]
    if not files:
        return "OK check 6 (error-literal): skipped"
    for f in files:
        bt = base_file(root, base, f) or ""
        ht = head_file(root, f) or ""
        bc = collections.Counter(_ERRLIT.findall(_strip_line_comments(bt)))
        hc = collections.Counter(_ERRLIT.findall(_strip_line_comments(ht)))
        if bc != hc:
            raise Violation(6, f"error-literal multiset changed in {f}: "
                               f"+{list((hc-bc).elements())} -{list((bc-hc).elements())}")
    return f"OK check 6 (error-literal): {len(files)} module(s) unchanged"


# ---- check 8: insertion integrity ----------------------------------------

def _excise_items(doc, rows_for_dst):
    drop = set()
    for row in rows_for_dst:
        if row["kind"] == "mod":
            continue
        m = _find_row(doc, row)
        if len(m) != 1:
            raise Violation(8, f"check8 could not uniquely locate {row['item_name']} "
                               f"in dst {row['dst_file']} ({len(m)} matches)")
        it = m[0]
        drop.update(range(it["lead_start"], it["end_line"] + 1))
    return drop


def check8(root, base, tsv, decls):
    edits = _parse_edits(decls)
    adds = _parse_adds(decls)
    comments = _parse_comments(decls)
    by_dst = collections.defaultdict(list)
    for row in tsv:
        by_dst[row["dst_file"]].append(row)

    n = 0
    for dst, rows in by_dst.items():
        if all(r["kind"] == "mod" for r in rows):
            continue  # pure tests-mod move: check 3 covers it (whole-file compare)
        ht = head_file(root, dst)
        if ht is None:
            raise Violation(8, f"dst missing at HEAD: {dst}")
        hdoc = R.Doc(ht)
        drop = _excise_items(hdoc, rows)
        remaining = "\n".join(ln for i, ln in enumerate(hdoc.lines) if i not in drop)
        head_set = collections.Counter(_content_lines(remaining))

        bt = base_file(root, base, dst)
        base_edited = R.apply_edits(bt, _edits_for_file(edits, dst)) if bt is not None else ""
        base_set = collections.Counter(_content_lines(base_edited))

        # dst import delta: plain imports stay executor-reconciled (they are
        # compile-verified and moved code is byte-identical), but the sharp
        # shadow vectors must be DECLARED in ## add — aliases (`as`) and glob
        # imports can silently re-bind bare names in pre-existing dst code
        # (explicit use beats `use super::*`), and `pub use` changes API surface
        base_uses = collections.Counter(
            ln.strip() for ln in base_edited.split("\n") if _is_use(ln.strip()))
        head_uses = collections.Counter(
            ln.strip() for ln in remaining.split("\n") if _is_use(ln.strip()))
        declared_uses = collections.Counter(
            s for s in (a.strip() for a in adds.get(dst, [])) if _is_use(s))
        for u in (head_uses - base_uses - declared_uses):
            if (" as " in u or "::*" in u
                    or u.startswith("pub use") or u.startswith("pub(crate) use")):
                raise Violation(8, f"undeclared hazardous import in dst {dst}: {u!r} "
                                   f"(aliases, globs, and re-exports must be declared in ## add)")

        add_set = collections.Counter(s for s in (a.strip() for a in adds.get(dst, []))
                                      if s and not _is_use(s))
        for (csrc, ca, cb, cdst) in comments:
            if cdst != dst:
                continue
            cbt = base_file(root, base, csrc)
            if cbt is None:
                raise Violation(8, f"comment src missing at base: {csrc}")
            clines = "\n".join(cbt.split("\n")[ca - 1:cb])
            add_set.update(_content_lines(clines))

        expected = base_set + add_set
        if head_set != expected:
            lines = [f"insertion integrity FAIL in {dst}:"]
            for k in sorted(head_set - expected):
                lines.append(f"  UNDECLARED line present in dst: {k!r}")
            for k in sorted(expected - head_set):
                lines.append(f"  declared/base line MISSING from dst: {k!r}")
            raise Violation(8, "\n".join(lines))
        n += 1
    return f"OK check 8 (insertion integrity): {n} dst file(s) clean"


# ---- check F: file relocation (B1 git mv) --------------------------------

def checkF(root, base, decls):
    rows = decls.get("filemove", [])
    n = 0
    for ln in rows:
        parts = ln.split("\t")
        if len(parts) != 2:
            raise Violation("F", f"bad filemove row (src<TAB>dst): {ln!r}")
        src, dst = parts[0].strip(), parts[1].strip()
        bsrc = base_file(root, base, src)
        hdst = head_file(root, dst)
        hsrc = head_file(root, src)
        if bsrc is None:
            raise Violation("F", f"filemove src missing at base: {src}")
        if hdst is None:
            raise Violation("F", f"filemove dst missing at HEAD: {dst}")
        if hsrc is not None:
            raise Violation("F", f"filemove src still present at HEAD: {src}")
        if bsrc != hdst:
            raise Violation("F", f"filemove content changed: {src} != {dst} "
                               f"(relocation must be byte-identical)")
        n += 1
    return f"OK check F (file relocation): {n} file(s) relocated byte-identically"


# ---- check C: consumer-diff-shape (anti-smuggle net) ---------------------

def _git_diff_file(root, base, f):
    p = subprocess.run(["git", "-C", root, "diff", "--no-color", "-U0", base, "HEAD", "--", f],
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else ""


def checkC(root, base, tsv, decls):
    """A CONSUMER file's non-import content must be byte-identical to BASE
    modulo the `## edit` rows declared for THAT file. Import statements —
    including the continuation lines of multi-line `use …::{…};` blocks —
    are executor-reconciled and verified by the build, check 2 and the
    flat-name set instead. Replaces the per-diff-line shape check, which
    (a) could not recognize multi-line use-block continuation lines and
    (b) keyed declared edits globally, letting an edit for file A authorize
    the same-looking change in file B."""
    edits = _parse_edits(decls)
    fragedits = _parse_fragedits(decls)
    dst = set(r["dst_file"] for r in tsv)
    src = set(r["src_file"] for r in tsv)
    # `## consumer-exempt`: files with declared STRUCTURAL edits that aren't
    # import-shaped (e.g. the U stage deleting #[path] mod mounts in types.rs).
    # Verified elsewhere: gate compile + conventions-gate #[path]==0 + flat-name set.
    # `## exhaust`: whole-file deletions validated by check_exhaustion, which
    # runs after this check — without the exemption the deletion false-fails
    # here first.
    exempt = dst | src | {"crates/oneiron/src/lib.rs"} | set(
        x.strip() for x in decls.get("consumer-exempt", [])) | set(
        x.strip() for x in decls.get("exhaust", []))
    n = 0
    for f in changed_files(root, base):
        if not f.endswith(".rs") or f in exempt:
            continue
        n += 1
        bt = base_file(root, base, f) or ""
        ht = head_file(root, f) or ""
        fe = ([(o, nw) for (ef, o, nw) in edits if ef == f]
              + [(o, nw) for (sf, o, nw) in fragedits if sf == f])
        base_rem = _nonuse_lines(R.apply_edits(bt, fe)) if fe else _nonuse_lines(bt)
        head_rem = _nonuse_lines(ht)
        if base_rem != head_rem:
            import difflib
            d = [ln for ln in difflib.unified_diff(base_rem, head_rem, lineterm="", n=0)
                 if not ln.startswith(("---", "+++"))]
            raise Violation("C", f"consumer non-import content changed beyond declared "
                               f"edits in {f} (first divergences, base-with-edits vs HEAD):\n"
                               + "\n".join(d[:12]))
    return f"OK check C (consumer-diff-shape): {n} consumer file(s) import-only beyond declared edits"


# ---- check X: src-exhaustion (T12 finale) --------------------------------

def check_exhaustion(root, base, decls):
    ex = [x.strip() for x in decls.get("exhaust", [])]
    if not ex:
        return "OK check X (src-exhaustion): skipped"
    movesdir = decls["_movesdir"][0]
    union_stages = decls["_exhaust_stages"]
    n = 0
    for src in ex:
        bt = base_file(root, base, src)
        if bt is None:
            raise Violation("X", f"exhaustion src missing at base: {src}")
        doc = R.Doc(bt)
        drop = set()
        for st in union_stages:
            stsv = parse_tsv(os.path.join(movesdir, f"{st}.tsv"))
            sdecls = parse_decls(os.path.join(movesdir, f"{st}.decls"))
            for row in stsv:
                if row["src_file"] != src:
                    continue
                if row["kind"] == "mod":
                    m = R.find_item(doc, "mod", "-", row["item_name"], row["cfg"])
                else:
                    m = _find_row(doc, row)
                if len(m) == 1:
                    drop.update(range(m[0]["lead_start"], m[0]["end_line"] + 1))
            for (csrc, ca, cb, cdst) in _parse_comments(sdecls):
                if csrc == src:
                    drop.update(range(ca - 1, cb))
        # excise whole `use` items (multi-line import trees) and SAFE `mod` items: the
        # `mod tests` shell (its fns were moved individually above) + declaration-only
        # `#[path] pub mod` mounts. A non-tests mod WITH a body is NOT auto-excised — its
        # items must be moved individually or they surface as residue (MINOR: prevents a
        # future missed mod's contents being silently swallowed).
        for it in R.enumerate_items(doc):
            if it["kind"] == "use":
                drop.update(range(it["lead_start"], it["end_line"] + 1))
            elif it["kind"] == "mod" and (it["name"] == "tests" or it["body_open_line"] is None):
                drop.update(range(it["lead_start"], it["end_line"] + 1))
        # residue must be SCAFFOLDING only (D9.4 #3): module doc, imports, attrs, mod
        # decls, and the emptied `mod tests { use super::*; }` shell all vanish with the
        # deleted file — they are not items. Anything else = an item that wasn't moved.
        residue = [ln.strip() for i, ln in enumerate(doc.lines)
                   if i not in drop and ln.strip() and not _SCAFFOLD.match(ln.strip())]
        if residue:
            raise Violation("X", f"src-exhaustion FAIL: {src} has {len(residue)} "
                               f"non-scaffolding line(s) — item not moved, first: {residue[0]!r}")
        n += 1
    return f"OK check X (src-exhaustion): {n} src file(s) fully accounted"


# ---- driver --------------------------------------------------------------

def run_checks(root, stage, base, movesdir):
    tsv = parse_tsv(os.path.join(movesdir, f"{stage}.tsv"))
    decls = parse_decls(os.path.join(movesdir, f"{stage}.decls"))
    decls["_movesdir"] = [movesdir]
    decls["_exhaust_stages"] = [x.strip() for x in decls.get("exhaust-stages", [])]
    results = [
        check1(root, base, decls),
        check2(root, base, decls),
        checkE(root, base, decls, tsv),
        check3(root, base, tsv, decls),
        check4(root, base, decls),
        check5(root, stage, decls),
        check6(root, base, decls),
        check8(root, base, tsv, decls),
        checkC(root, base, tsv, decls),
        checkF(root, base, decls),
        check_exhaustion(root, base, decls),
    ]
    return results


def main(argv):
    if len(argv) < 4 or argv[0] != "checks":
        print("usage: driver checks <root> <stage> <base> [<movesdir>]", file=sys.stderr)
        return 2
    root, stage, base = argv[1], argv[2], argv[3]
    movesdir = argv[4] if len(argv) > 4 else os.path.join(root, "scripts/refactor/moves")
    try:
        for line in run_checks(root, stage, base, movesdir):
            print(line)
    except Violation as v:
        print(f"CONFORMANCE FAILED at check {v.check}:\n{v}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"CONFORMANCE ERROR (tooling, not a manifest verdict): {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"CONFORMANCE ERROR (manifest parse): {e}", file=sys.stderr)
        return 1
    print(f"CONFORMANCE checks 1-8 PASSED for stage {stage}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
