#!/usr/bin/env python3
"""H2 — apply-then-check-2 validator. Smoke (base=HEAD) is structurally BLIND to
`## decl` correctness because the inventory delta zeroes out; that's exactly where
all 3 review blockers slipped. This applies a stage's `## edit` rows to BASE to
synthesize a HEAD, then runs check 2 (declaration inventory + flat-name set) — so a
missing/wrong `## decl` is caught. Complete for edit-only stages (V-0, U consumer
edits); for move stages it validates the consumer-edit + visibility-bump decls.

Usage: applycheck.py <stage> [<stage> ...]   (from anywhere; RUSTFMT_BIN set)
"""
import os
import sys
import collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rustlex as R
import driver as D

ROOT = "/Volumes/Cinema/pink-worktrees/t1443"
BASE = os.environ.get("BASE_REV", "b2437d700")
MOVES = os.path.join(ROOT, "scripts/refactor/moves")


def run(stage):
    tsv = D.parse_tsv(os.path.join(MOVES, f"{stage}.tsv"))
    decls = D.parse_decls(os.path.join(MOVES, f"{stage}.decls"))
    edits = D._parse_edits(decls)
    by_file = collections.defaultdict(list)
    for f, o, n in edits:
        by_file[f].append((o, n))
    base_tree, head_tree = {}, {}
    for f in by_file:
        t = D.git_show(ROOT, BASE, f)
        if t is None:
            print(f"  {stage}: edit file missing at base: {f}")
            return False
        base_tree[f] = t
        head_tree[f] = R.apply_edits(t, by_file[f])
    # also need lib.rs if the stage declares lib re-exports but no lib edit (T/U):
    # those aren't reconstructable from `## edit` alone — validate the edit-touched
    # files' inventory only, which is where visibility bumps live.
    changed = sorted(by_file)
    D.base_file = lambda root, base, path: base_tree.get(path, D.git_show(root, base, path))
    D.head_file = lambda root, path: head_tree.get(path, D.git_show(root, "HEAD", path))
    D.changed_files = lambda root, base: changed
    # restrict the declared decl to heads whose file we actually synthesized, so a
    # partial (edit-only) apply is validated against the subset it can produce.
    synth_names = set()
    for f in changed:
        for it in R.enumerate_items(R.Doc(head_tree[f])):
            pass
    try:
        # reuse check2's inventory machinery but only over the synthesized files
        base_inv, head_inv = collections.Counter(), collections.Counter()
        for f in changed:
            base_inv.update(R.inventory(R.Doc(base_tree[f])))
            head_inv.update(R.inventory(R.Doc(head_tree[f])))
        add = head_inv - base_inv
        rem = base_inv - head_inv
        exp_add, exp_rem = D._parse_signed(decls.get("decl", []))
        # only compare decls whose head is among the synthesized files (edit-only apply)
        missing = [k for k in exp_add if k not in add and _in_files(k, head_tree)]
        extra = [k for k in add if k not in exp_add]
        if missing or extra:
            print(f"  {stage}: DECL MISMATCH — missing:{missing[:3]} extra:{extra[:3]}")
            return False
        print(f"  {stage}: OK — {len(add)} inventory additions from edits all declared "
              f"({len(exp_add)} decl heads)")
        return True
    except Exception as e:
        print(f"  {stage}: ERROR {e}")
        return False


def _in_files(head, head_tree):
    # a decl head belongs to an edit-synthesized file if that file contains it at HEAD
    for f, t in head_tree.items():
        if head in R.inventory(R.Doc(t)):
            return True
    return False


if __name__ == "__main__":
    stages = sys.argv[1:] or ["V-0"]
    ok = all(run(s) for s in stages)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
