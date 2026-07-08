#!/usr/bin/env python3
"""H3 — consumer-completeness gate. Independently (NOT via the generator) re-derives
every moved pub/pub(crate) item's cross-module consumers — inline paths AND brace-
nested / multi-line use-trees — and asserts each consumer FILE appears in the stage's
`## allowed`. Catches the missing-consumer class (review BLOCKER 2/3) mechanically;
run at every package-cut. Read-only against BASE.

Usage: consumer_complete.py [<stage> ...]   (default: all T/V/U stages)
"""
import os
import re
import subprocess
import sys
import collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rustlex as R
import driver as D
import gen
import gen_t

ROOT = "/Volumes/Cinema/pink-worktrees/t1443"
BASE = os.environ.get("BASE_REV", "b2437d700")
MOVES = os.path.join(ROOT, "scripts/refactor/moves")

# stage -> (old-path prefixes, name->dest map for the stage's own moved pub names)
V_ENTITY = ["habit", "access_grant", "outbound_grant", "channel_identity",
            "counterparty_contact", "authority", "claim", "companion", "affect",
            "provenance", "deletion"]


def allowed_of(stage):
    d = D.parse_decls(os.path.join(MOVES, f"{stage}.decls"))
    return set(x.strip() for x in d.get("allowed", []))


def base_doc(path):
    t = D.git_show(ROOT, BASE, path)
    return R.Doc(t) if t is not None else None


def pub_moved_names(stage, src):
    """moved item names that are pub/pub(crate) at base (so they are path-referenced)."""
    tsv = D.parse_tsv(os.path.join(MOVES, f"{stage}.tsv"))
    doc = base_doc(src)
    out = []
    for r in tsv:
        if r["kind"] in ("method", "mod", "impl"):
            continue  # methods resolve via type; mods/impls aren't path-named
        m = D._find_row(doc, r)
        if len(m) == 1 and m[0]["vis"] in ("pub", "pub ( crate )"):
            out.append(r["item_name"])
    return out


def inline_consumer_files(prefixes, names):
    """files with an inline PREFIX::NAME occurrence (not a use statement)."""
    files = set()
    alt = "|".join(re.escape(n) for n in names)
    if not alt:
        return files
    for pfx in prefixes:
        p = subprocess.run(["git", "-C", ROOT, "grep", "-n", "-I", "-E",
                            re.escape(pfx) + r"::(" + alt + r")", BASE, "--", "*.rs"],
                           capture_output=True, text=True)
        for ln in p.stdout.splitlines():
            try:
                _, path, no, content = ln.split(":", 3)
            except ValueError:
                continue
            files.add(path)
    return files


def nested_consumer_files(nested_prefixes):
    """files with a bare `PFX::submodule::` path — catches NON-flat nested consumers
    (D-3: e.g. oneiron::types::psych_profile::psych_mirror_drift_anchor_events, whose
    leaf name is invisible to the flat-name scan)."""
    files = set()
    for np in nested_prefixes:
        p = subprocess.run(["git", "-C", ROOT, "grep", "-l", "-I", "-F", np, BASE, "--", "*.rs"],
                           capture_output=True, text=True)
        files |= {ln.split(":", 1)[1] for ln in p.stdout.splitlines() if ":" in ln}
    return files


def check(stage, prefixes, name_to_dest, src, nested_prefixes=()):
    names = list(name_to_dest)
    allowed = allowed_of(stage)
    consumers = set()
    # inline
    consumers |= inline_consumer_files(prefixes, names)
    # use-trees (single + multi-line)
    for pfx in prefixes:
        a, _ = gen.use_tree_scan(pfx, name_to_dest)
        for dstm, fs in a.items():
            consumers |= fs
    # nested-path (non-flat) consumers
    consumers |= nested_consumer_files(nested_prefixes)
    consumers.discard(src)
    consumers.discard("crates/oneiron/src/lib.rs")
    missing = sorted(c for c in consumers if c not in allowed)
    if missing:
        print(f"  {stage}: *** {len(missing)} consumer(s) MISSING from allowed ***")
        for m in missing:
            print(f"      {m}")
        return False
    print(f"  {stage}: OK — {len(consumers)} cross-module consumer file(s) all in allowed")
    return True


def main(stages):
    ok = True
    for st in stages:
        if st.startswith("T") and st[1:].isdigit():
            if st == "T12":
                print(f"  {st}: (finale, no moves)")
                continue
            # this batch's own pub-moved names -> their module
            n2d = {n: gen_t.DEST[n] for n in pub_moved_names(st, "crates/oneiron/src/types.rs")
                   if n in gen_t.DEST}
            ok &= check(st, ["crate::types", "oneiron::types"], n2d, "crates/oneiron/src/types.rs")
        elif st.startswith("V-") and st != "V-0":
            entity = st[2:]
            n2d = {n: entity for n in pub_moved_names(st, "crates/oneiron/src/vault.rs")}
            ok &= check(st, ["crate::vault"], n2d, "crates/oneiron/src/vault.rs")
        elif st == "U":
            # companion/psych flat + non-flat names re-exported through types
            types = base_doc("crates/oneiron/src/types.rs")
            comp = psych = []
            for it in R.enumerate_items(types):
                if it["kind"] == "use" and it["vis"] == "pub":
                    h = R.logical_head(types, it["sig_line"])
                    if h.startswith("pub use companion ::"):
                        comp = [x.strip() for x in h[h.index("{")+1:h.rindex("}")].split(",")]
                    elif h.startswith("pub use psych_profile ::"):
                        psych = [x.strip() for x in h[h.index("{")+1:h.rindex("}")].split(",")]
            n2d = {n: "companion" for n in comp}
            n2d.update({n: "psych_profile" for n in psych})
            nested = ["crate::types::companion::", "crate::types::psych_profile::",
                      "oneiron::types::companion::", "oneiron::types::psych_profile::"]
            ok &= check("U", ["crate::types", "oneiron::types"], n2d,
                        "crates/oneiron/src/types.rs", nested_prefixes=nested)
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    st = sys.argv[1:] or ([f"T{i}" for i in range(1, 13)] + [f"V-{e}" for e in V_ENTITY] + ["U"])
    sys.exit(main(st))
