#!/usr/bin/env python3
"""Count the test suite by bucket, for the retained-suite prune (L4-23).

Canon, implementation-baseline-v1 #tests-prune: the retained suite is pruned to
about 2,000-3,000 tests; the vendored stemma-engine suites and the office suite
are counted apart. This census reads git objects at --rev (no cargo, no
checkout) and finds tests with scripts/ci/test_count.py's scanner, so its total
equals that gate's tests_total at the same revision.

Each test lands in one bucket, the first that matches:
  vendored     a path with a vendor component; reported, never in total
  office       oneiron-seal, oneiron-docedit, oneiron-xlsx-formula, the core
               office modules (edit_roundtrip, anchored_annotation, edit_settle,
               docx_zip_budget.rs), packages/xlsx-viewer and the office grader
               scripts in scripts/tests (TEST-PASS-PLAN 1.7)
  e2e          tests/e2e/*.test.ts cases, by state
  python, js   the other Python and JS/TS tests
  quarantined  Rust tests that never compile: inside a module the code gates
               with #[cfg(any())], or under their own #[cfg(any())]
  ignored      Rust tests under #[ignore]
  rust         every other Rust test, per crate directory, as lib (under src/),
               integration (under tests/) or other
total = every bucket but vendored.

scripts/nightly/libtest-quarantine-baseline.tsv (the gates when the quarantine
landed) is checked against the code: a mod or fn row the code no longer gates
is listed in quarantine_ported (the nightly's word: a gate gone from the tree
is ported), and a gate that holds tests and has no row in quarantine_unlisted.
.config/test-quarantine.toml (flaky tests; they compile) is reported as its
entry count only.

Usage: suite_census.py [--repo DIR] [--rev REV] [--json] [--files]
Exit: 0; 2 scan error.
"""
import argparse
import json
import posixpath
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_count as tc  # noqa: E402

BASELINE = "scripts/nightly/libtest-quarantine-baseline.tsv"
FLAKY = ".config/test-quarantine.toml"
OFFICE_CRATES = {"oneiron-seal", "oneiron-docedit", "oneiron-xlsx-formula"}
OFFICE_MODULES = {"edit_roundtrip", "anchored_annotation", "edit_settle", "docx_zip_budget"}
OFFICE_PACKAGE = "packages/xlsx-viewer/"
OFFICE_GRADERS = re.compile(r"scripts/tests/(?:test_excel_\w+|test_word_oracle|test_real_workbook_oracle|test_docedit_direction)\.py")
CRATE_ROOT_DIRS = {"tests", "benches", "examples", "bin"}

_CFG_ANY = re.compile(r"#\s*\[\s*cfg\s*\(\s*any\s*\(\s*\)\s*\)\s*\]")
_IGNORE = re.compile(r"#\s*\[\s*ignore\b")
_MOD_DECL = re.compile(r"(?<![A-Za-z0-9_])mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*([;{])")
_PATH_ATTR = re.compile(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]')
_FN_NAME = re.compile(r"fn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)")
_FN_DECL = re.compile(r"(?<![A-Za-z0-9_])" + _FN_NAME.pattern)
_E2E_STATE = re.compile(r"\.\s*(test|skip|todo|pendingDoor)")
E2E_STATES = ("test", "skip", "todo", "pendingDoor")


def vendored_kind(path):
    """The kind a path under a vendor directory would count as, or None."""
    parts = path.split("/")
    if "vendor" not in parts[:-1]:
        return None
    return tc.kind_of("/".join([p for p in parts[:-1] if p != "vendor"] + parts[-1:]))


def is_office(path, kind):
    parts = path.split("/")
    if kind == "py":
        return bool(OFFICE_GRADERS.fullmatch(path))
    if kind == "js":
        return path.startswith(OFFICE_PACKAGE)
    if kind != "rust":
        return False
    stems = {p.removesuffix(".rs") for p in parts[2:]}
    return (parts[0] == "crates" and parts[1] in OFFICE_CRATES) or bool(stems & OFFICE_MODULES)


def crate_and_section(path):
    parts = path.split("/")
    crate = parts[1] if parts[0] == "crates" else "/".join(parts[:2])
    for comp in parts[2:-1]:
        if comp == "src":
            return crate, "lib"
        if comp == "tests":
            return crate, "integration"
    return crate, "other"


def mask_rust(text):
    """text with comments, strings and char literals blanked (newlines kept), so offsets do not move."""
    spans, pos = [], 0
    while True:
        m = tc._RUST_TOKEN.search(text, pos)
        if not m:
            break
        kind, pos = m.lastgroup, m.end()
        if kind in ("line", "str", "char"):
            spans.append((m.start(), m.end()))
        elif kind == "block":
            depth, end = 1, len(text)
            for b in tc._RUST_BLOCK.finditer(text, pos):
                depth += 1 if b.group() == "/*" else -1
                if depth == 0:
                    end = b.end()
                    break
            spans.append((m.start(), end))
            pos = end
        elif kind == "raw":
            close = text.find('"' + m.group("hashes"), pos)
            end = len(text) if close < 0 else close + 1 + len(m.group("hashes"))
            spans.append((m.start(), end))
            pos = end
    out, last = [], 0
    for a, b in spans:
        out += [text[last:a], re.sub(r"[^\n]", " ", text[a:b])]
        last = b
    out.append(text[last:])
    return "".join(out)


def item_start(masked, pos):
    """Where the attributes of the item at pos begin: just after the previous ; { or }."""
    return max(masked.rfind(c, 0, pos) for c in ";{}") + 1


def close_brace(masked, open_pos):
    depth = 0
    for i in range(open_pos, len(masked)):
        c = masked[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(masked)


def mod_decls(text, masked):
    """[(item, offset, inline span or None, #[path] value or None, gated)] for each mod declared in a file."""
    out = []
    for m in _MOD_DECL.finditer(masked):
        start = item_start(masked, m.start())
        gated = bool(_CFG_ANY.search(masked, start, m.start()))
        if m.group(2) == "{":
            out.append((m.group(1), m.start(), (m.end() - 1, close_brace(masked, m.end() - 1)), None, gated))
            continue
        attr = _PATH_ATTR.search(text, start, m.start())
        out.append((m.group(1), m.start(), None, attr.group(1) if attr else None, gated))
    return out


def module_files(path, item, attr, path_loaded):
    """(module file, module directory or None) that `mod item;` declared in path loads, by rustc's rules: a #[path]
    is relative to the declaring file's directory; otherwise a mod.rs-like file (mod.rs, a crate root, or a file that
    was itself loaded by #[path]) keeps its children in its own directory, and any other file in a directory named
    after its stem. A #[path] inside an inline mod block is read as if the block were not there."""
    here = posixpath.dirname(path)
    if attr:
        target = posixpath.normpath(posixpath.join(here, attr))
        return target, posixpath.dirname(target) if target.endswith("/mod.rs") else None
    parts = path.split("/")
    mod_rs = path_loaded or parts[-1] in ("mod.rs", "lib.rs", "main.rs", "build.rs") or (
        len(parts) > 1 and parts[-2] in CRATE_ROOT_DIRS)
    child_dir = here if mod_rs else path.removesuffix(".rs")
    return f"{child_dir}/{item}.rs", f"{child_dir}/{item}"


def gated_fns(masked):
    """Names of the fns (tests or helpers) under their own #[cfg(any())]."""
    return {m.group(1) for m in _FN_DECL.finditer(masked) if _CFG_ANY.search(masked, item_start(masked, m.start()), m.start())}


def census(repo, rev):
    sha = tc.git(repo, "rev-parse", "--verify", f"{rev}^{{commit}}").decode().strip()
    files = tc.tree_files(repo, sha, keep=lambda p: tc.kind_of(p) or vendored_kind(p) or p in (BASELINE, FLAKY))
    if not any(tc.kind_of(p) for p in files):
        raise tc.ScanError(f"no test file found in {rev}: empty scan")
    counts = {"office": 0, "python": 0, "js": 0, "quarantined": 0, "ignored": 0}
    e2e = dict.fromkeys(E2E_STATES, 0)
    rust = {}
    vendored, baseline_rows, flaky = 0, [], 0
    rust_tests, decls = {}, {}  # path -> [(offset, fn name, ignored, self-gated)]; declaring file -> mod_decls
    rows, gated_fn_rows = {}, set()
    for path, data in tc.read_blobs(repo, files):
        text = data.decode("utf-8", errors="replace")
        if path == BASELINE:
            baseline_rows = [line.split("\t") for line in text.splitlines()[1:] if line.strip()]
            continue
        if path == FLAKY:
            flaky = len(re.findall(r"(?m)^\s*\[\[test\]\]", text))
            continue
        vkind = vendored_kind(path)
        if vkind:
            vendored += tc.count_blob(vkind, data)
            continue
        kind = tc.kind_of(path)
        if kind == "rust":
            offsets = list(tc.rust_test_fns(text))
            if not offsets and "any()" not in text and not _PATH_ATTR.search(text):
                continue
            masked = mask_rust(text)
            decls[path] = mod_decls(text, masked)
            if "any()" in text:
                gated_fn_rows |= {(path, name) for name in gated_fns(masked)}
            if offsets:
                rust_tests[path] = [
                    (o, _FN_NAME.match(masked, o).group(1), bool(_IGNORE.search(masked, item_start(masked, o), o)),
                     bool(_CFG_ANY.search(masked, item_start(masked, o), o)))
                    for o in offsets
                ]
            continue
        n = tc.count_blob(kind, data)
        if not n:
            continue
        bucket = "office" if is_office(path, kind) else {"e2e": "e2e", "py": "python", "js": "js"}[kind]
        if bucket == "e2e":
            for m in tc._JS_TOKEN.finditer(text):
                if m.lastgroup == "e2e":
                    e2e[_E2E_STATE.match(m.group()).group(1)] += 1
        else:
            counts[bucket] += n
        rows[path] = {bucket: n}

    def path_targets():
        return {module_files(p, i, a, False)[0] for p, ds in decls.items() for i, _, span, a, _ in ds if a and not span}

    loaded_by_path = path_targets()
    inline, by_file = {}, {}  # declaring file -> [(span, gate)]; module file or directory -> gate
    for decl, ds in decls.items():
        for item, _, span, attr, gated in ds:
            if not gated:
                continue
            if span:
                inline.setdefault(decl, []).append((span, (decl, item)))
            else:
                for where in module_files(decl, item, attr, decl in loaded_by_path):
                    if where:
                        by_file[where] = (decl, item)

    def gates_of(path, offset):
        """The gated (declaring file, item) that hold the item at offset in path."""
        held = {gate for span, gate in inline.get(path, ()) if span[0] <= offset < span[1]}
        parts = path.split("/")
        held |= {by_file["/".join(parts[:i])] for i in range(1, len(parts) + 1) if "/".join(parts[:i]) in by_file}
        return held

    # A gate holds every module its gated code declares, wherever the module file lies. The file and directory
    # prefixes above cover a plain child; a #[path] child (comm/tests.rs loads comm/thread_alias_tests.rs) and the
    # children of a file loaded by #[path] (they sit beside it) lie outside them, so carry the gate down each
    # declaration until nothing changes, reading the declarations of a gated #[path] file that was not read yet.
    while True:
        grew = False
        for decl, ds in list(decls.items()):
            for item, offset, span, attr, gated in ds:
                held = () if span or gated else gates_of(decl, offset)
                for where in module_files(decl, item, attr, decl in loaded_by_path) if held else ():
                    if where and where not in by_file:
                        by_file[where] = min(held)
                        grew = True
        unread = {p: files[p] for p in loaded_by_path if p in files and p not in decls and gates_of(p, 0)}
        for path, data in tc.read_blobs(repo, unread):
            text = data.decode("utf-8", errors="replace")
            decls[path] = mod_decls(text, mask_rust(text))
            grew = True
        if not grew:
            break
        loaded_by_path = path_targets()

    holding = set()  # gated (declaring file, item) that hold at least one test, and gated test fns
    gated = {(decl, d[0]) for decl, ds in decls.items() for d in ds if d[4]} | gated_fn_rows
    for path, tests in rust_tests.items():
        if is_office(path, "rust"):
            counts["office"] += len(tests)
            rows[path] = {"office": len(tests)}
            continue
        crate, section = crate_and_section(path)
        row = {}
        for offset, name, ignored, self_gated in tests:
            held_by = gates_of(path, offset) | ({(path, name)} if self_gated else set())
            holding |= held_by
            if held_by:
                bucket = "quarantined"
            elif ignored:
                bucket = "ignored"
            else:
                bucket = f"rust_{section}"
                rust.setdefault(crate, dict.fromkeys(("lib", "integration", "other"), 0))[section] += 1
            if bucket in counts:
                counts[bucket] += 1
            row[bucket] = row.get(bucket, 0) + 1
        rows[path] = row

    listed = {(r[2], r[5]) for r in baseline_rows if len(r) >= 6 and r[3] in ("mod", "fn")}
    ported = sorted(f"{f}::{i}" for f, i in listed if (f, i) not in gated)
    unlisted = sorted(f"{f}::{i}" for f, i in holding if (f, i) not in listed)
    rust_totals = {s: sum(c[s] for c in rust.values()) for s in ("lib", "integration", "other")}
    rust_total = sum(rust_totals.values())
    e2e_total = sum(e2e.values())
    total = rust_total + e2e_total + sum(counts.values())
    return {
        "schema": 1,
        "rev": sha,
        "total": total,
        "vendored": vendored,
        "office": counts["office"],
        "e2e": {"total": e2e_total, **e2e},
        "python": counts["python"],
        "js": counts["js"],
        "quarantined": counts["quarantined"],
        "ignored": counts["ignored"],
        "rust": {"total": rust_total, **rust_totals, "crates": dict(sorted(rust.items(), key=lambda kv: -sum(kv[1].values())))},
        "flaky_quarantine_entries": flaky,
        "quarantine_baseline_rows": len(baseline_rows),
        "quarantine_ported": ported,
        "quarantine_unlisted": unlisted,
        "files": [{"path": p, "crate": crate_and_section(p)[0], **rows[p]} for p in sorted(rows)],
    }


def table(c):
    e, r = c["e2e"], c["rust"]
    lines = [
        f"suite census at {c['rev'][:12]}",
        f"{'office':<12} {c['office']:>6}",
        f"{'e2e':<12} {e['total']:>6}  ({', '.join(f'{s} {e[s]}' for s in E2E_STATES)})",
        f"{'python':<12} {c['python']:>6}",
        f"{'js':<12} {c['js']:>6}",
        f"{'quarantined':<12} {c['quarantined']:>6}  (never compiles: #[cfg(any())])",
        f"{'ignored':<12} {c['ignored']:>6}",
        f"{'rust':<12} {r['total']:>6}  (lib {r['lib']}, integration {r['integration']}, other {r['other']})",
        f"{'total':<12} {c['total']:>6}",
        f"{'vendored':<12} {c['vendored']:>6}  (not in total)",
        "",
        f"{'crate':<32} {'lib':>6} {'integ':>6} {'other':>6}",
    ]
    lines += [f"{name:<32} {n['lib']:>6} {n['integration']:>6} {n['other']:>6}" for name, n in r["crates"].items()]
    lines += [
        "",
        f"quarantine baseline rows {c['quarantine_baseline_rows']}, ported {len(c['quarantine_ported'])}, unlisted {len(c['quarantine_unlisted'])}; flaky entries {c['flaky_quarantine_entries']}",
    ]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--json", action="store_true", help="print one JSON object instead of the table")
    ap.add_argument("--files", action="store_true", help="keep the per-file rows in the JSON")
    a = ap.parse_args(argv)
    try:
        c = census(a.repo, a.rev)
    except (tc.ScanError, OSError, ValueError) as err:
        print(f"suite_census=error {err}", file=sys.stderr)
        return 2
    if not a.files:
        c.pop("files")
    print(json.dumps(c, indent=1) if a.json else table(c))
    return 0


if __name__ == "__main__":
    sys.exit(main())
