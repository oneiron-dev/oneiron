#!/usr/bin/env python3
"""Build `manifest.json` for the error-enum split. python3 stdlib only.

    scripts/refactor/error_split/build_manifest.py [--out manifest.json]

Joins three inputs:

* the live `pub enum Error` in `crates/oneiron/src/error.rs` (parsed);
* the hand-authored domain table in `assignment.py`;
* a census of every `Error::<Variant>` reference under `crates/`, split into
  production and test lines.

Exits 1 if the table and the enum disagree (a variant with no domain, or a
domain naming a variant that no longer exists), so the manifest can never be
silently stale after main moves.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)

import assignment  # noqa: E402
import errparse  # noqa: E402

ERROR_RS = os.path.join(REPO, "crates", "oneiron", "src", "error.rs")
REF = re.compile(r"\bError::([A-Z][A-Za-z0-9_]*)")
# `pkix_path::Error::X`, `heed::Error::X`, ... belong to other crates' enums.
FOREIGN = re.compile(r"(?:^|[^A-Za-z0-9_:])((?:" + errparse.IDENT + r")(?:::" + errparse.IDENT + r")*)::Error::$")
OURS = {"crate", "oneiron", "super", "self", "error", "crate::error", "oneiron::error"}


def qualifier(line: str, at: int) -> str | None:
    """The path qualifying an `Error::` occurrence at index `at`, or None."""
    m = FOREIGN.search(line[:at] + "Error::")
    return m.group(1) if m else None


def census(variant_names: set[str]) -> dict:
    counts = collections.defaultdict(
        lambda: {
            "prod": 0,
            "test": 0,
            "files": set(),
            "modules": set(),
            "crates": collections.Counter(),
            "foreign_skipped": 0,
        }
    )
    for dirpath, dirnames, filenames in os.walk(os.path.join(REPO, "crates")):
        dirnames[:] = [d for d in dirnames if d not in {"target", ".git", "node_modules", "vendor"}]
        for fn in filenames:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(dirpath, fn)
            if os.path.realpath(path) == os.path.realpath(ERROR_RS):
                continue
            rel = os.path.relpath(path, REPO)
            try:
                text = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            if "Error::" not in text:
                continue
            crate = rel.split(os.sep)[1]
            tlines = errparse.test_line_numbers(text)
            whole_test = errparse.is_test_path(rel)
            for lineno, line in enumerate(text.split("\n"), 1):
                seen = set()
                for m in REF.finditer(line):
                    name = m.group(1)
                    if name not in variant_names or name in seen:
                        continue
                    qual = qualifier(line, m.start())
                    if qual is not None and qual.split("::")[0] not in OURS:
                        counts[name]["foreign_skipped"] += 1
                        continue
                    seen.add(name)
                    entry = counts[name]
                    if whole_test or lineno in tlines:
                        entry["test"] += 1
                    else:
                        entry["prod"] += 1
                    entry["files"].add(rel)
                    entry["modules"].add(os.path.dirname(rel))
                    entry["crates"][crate] += 1
    out = {}
    for name in variant_names:
        e = counts.get(name)
        if e is None:
            out[name] = {"prod": 0, "test": 0, "total": 0, "files": 0, "modules": 0,
                         "module_list": [], "crates": {}, "foreign_skipped": 0}
            continue
        out[name] = {
            "prod": e["prod"],
            "test": e["test"],
            "total": e["prod"] + e["test"],
            "files": len(e["files"]),
            "modules": len(e["modules"]),
            "module_list": sorted(e["modules"]),
            "crates": dict(e["crates"]),
            "foreign_skipped": e["foreign_skipped"],
        }
    return out


def top_segments(module_list: list[str]) -> list[str]:
    """The distinct first path segment under crates/oneiron/src for each module."""
    segs = []
    for mod in module_list:
        rel = mod.replace("crates/oneiron/src", "").strip("/")
        segs.append(rel.split("/")[0] if rel else "<crate root>")
    return [s for s, _ in collections.Counter(segs).most_common()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "manifest.json"))
    args = ap.parse_args()

    text = open(ERROR_RS, encoding="utf-8").read()
    variants = errparse.parse_enum(text, "Error")
    kinds = errparse.parse_enum(text, "ErrorKind")
    by_name = {v["name"]: v for v in variants}

    domain_of: dict[str, str] = {n: "root" for n in assignment.ROOT}
    for domain, names in assignment.ASSIGNMENT.items():
        for n in names:
            if n in domain_of:
                print(f"MANIFEST-ERROR: {n} assigned twice ({domain_of[n]} and {domain})", file=sys.stderr)
                return 1
            domain_of[n] = domain

    missing = [v["name"] for v in variants if v["name"] not in domain_of]
    stale = [n for n in domain_of if n not in by_name]
    if missing or stale:
        for n in missing:
            print(f"MANIFEST-ERROR: variant {n} has no domain in assignment.py", file=sys.stderr)
        for n in stale:
            print(f"MANIFEST-ERROR: assignment.py names {n}, which is not a variant of Error", file=sys.stderr)
        return 1

    refs = census(set(by_name))

    try:
        rev = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        rev = "unknown"

    rows = []
    for v in variants:
        name = v["name"]
        domain = domain_of[name]
        r = refs[name]
        note = assignment.NOTES.get(name)
        rows.append(
            {
                "name": name,
                "domain": domain,
                "enum": "Error" if domain == "root" else assignment.DOMAINS[domain][0],
                "file": "crates/oneiron/src/" + (assignment.ROOT_FILE if domain == "root"
                                                 else assignment.DOMAINS[domain][1]),
                "shape": v["shape"],
                "payload": v["payload"],
                "error_attr": v["error_attr"],
                "cfg": v["cfg"],
                "other_attrs": v["other_attrs"],
                "has_source": v["has_source"],
                "has_from": v["has_from"],
                "src_line": v["line"],
                "refs": {
                    "prod": r["prod"],
                    "test": r["test"],
                    "total": r["total"],
                    "files": r["files"],
                    "modules": r["modules"],
                    "crates": r["crates"],
                    "top_modules": top_segments(r["module_list"])[:6],
                },
                # `move` = rewrite its call sites into the nested form.
                # `keep` = stays flat on the root enum, zero call sites touched.
                # `delete` = drop the variant AND its ErrorKind twin. Nothing is
                # marked `delete` by default; see DEAD_CANDIDATES below.
                "action": assignment.DEAD_VERDICTS.get(name, {}).get(
                    "action", "keep" if domain == "root" else "move"),
                "dead": r["total"] == 0 and name not in assignment.REACHABLE_WITHOUT_NAMING,
                "reachable_via": assignment.REACHABLE_WITHOUT_NAMING.get(name),
                "dead_verdict": assignment.DEAD_VERDICTS.get(name),
                "note": note[1] if note else None,
            }
        )

    promotion_candidates = [
        {"name": r["name"], "domain": r["domain"], "modules": r["refs"]["modules"],
         "top_modules": r["refs"]["top_modules"], "total": r["refs"]["total"]}
        for r in rows
        if r["domain"] != "root" and r["refs"]["modules"] >= 10
    ]
    promotion_candidates.sort(key=lambda x: -x["modules"])

    dead = [r["name"] for r in rows if r["dead"]]

    manifest = {
        "schema": 1,
        "base_rev": rev,
        "source": "crates/oneiron/src/error.rs",
        "totals": {
            "variants": len(rows),
            "error_kind_variants": len(kinds),
            "per_domain": dict(collections.Counter(r["domain"] for r in rows)),
            "shapes": dict(collections.Counter(r["shape"] for r in rows)),
            "cfg_gated": sum(1 for r in rows if r["cfg"]),
        },
        "domains": {
            "root": {"enum": "Error", "file": "crates/oneiron/src/error.rs", "wrapper": None},
            **{
                d: {
                    "enum": e,
                    "file": "crates/oneiron/src/" + f,
                    "wrapper": w,
                    "wrapper_decl": f'#[error(transparent)]\n{w}(#[from] {e}),',
                }
                for d, (e, f, w) in assignment.DOMAINS.items()
            },
        },
        "variants": rows,
        "moving_items": [
            {"item": i, "kind": k, "from": "crates/oneiron/src/" + f, "to_domain": d, "note": n}
            for (i, k, f, d, n) in assignment.MOVING_ITEMS
        ],
        "from_impls": assignment.FROM_IMPLS,
        "root_methods": assignment.ROOT_METHODS,
        "promotion_candidates": promotion_candidates,
        "dead_candidates": dead,
        "dead_verdicts": assignment.DEAD_VERDICTS,
        "reachable_without_naming": assignment.REACHABLE_WITHOUT_NAMING,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
        fh.write("\n")

    print(f"manifest: {len(rows)} variants, {len(kinds)} ErrorKind variants, base {rev[:12]}")
    for d, n in sorted(manifest["totals"]["per_domain"].items(), key=lambda x: -x[1]):
        print(f"  {d:12s} {n:3d}")
    print(f"dead (zero references): {', '.join(dead) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
