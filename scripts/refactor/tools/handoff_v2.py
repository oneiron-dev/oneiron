#!/usr/bin/env python3
"""Emit the 24 Codex handoff packages (T1-T12 + V-0..V-11) from the committed
manifests, re-deriving move-list line numbers from BASE at cut time (MM F7)."""
import os
import subprocess
import sys
import collections
sys.path.insert(0, "/Users/olety/.claude-pink/jobs/0b1ef39f/tmp")
import rustlex as R
import driver as D

ROOT = "/Volumes/Cinema/pink-worktrees/t1443"
BASE = "b2437d700"
MOVES = os.path.join(ROOT, "scripts/refactor/moves")
OUT = "/Users/olety/Desktop/code/fable-queue/oneiron/handoffs"
SESSION = "https://claude.ai/code/session_01Ahja3evrLPJVmg8ErBsg6R"
GUARD = "crates/oneiron/src/agent_def[.rs/] · crates/oneiron/src/edit_settle[.rs/]"

FABLE_REVIEW = {"T1", "T2", "T4"}
# dependency + one-line scope per stage
DEP = {"T1": "S2 (U + B1 + deferred test-splits)", "T2": "T1", "T3": "T2", "T4": "T3",
       "T5": "T4", "T6": "T5", "T7": "T6", "T8": "T7", "T9": "T8", "T10": "T9",
       "T11": "T10", "T12": "T11",
       "V-0": "stage T complete", "V-habit": "V-0 + T11 (habit.rs exists)",
       "V-access_grant": "V-0 + tests-w1", "V-outbound_grant": "V-0 + tests-w1",
       "V-channel_identity": "V-0 + tests-w1", "V-counterparty_contact": "V-0 + tests-w1",
       "V-authority": "V-0 + tests-w1", "V-claim": "V-0 + tests-w1",
       "V-companion": "V-0 + tests-s2-unmount", "V-affect": "V-0 + T3",
       "V-provenance": "V-0 + T (before V-deletion)", "V-deletion": "V-0 + V-affect + V-provenance"}
SCOPE = {}
for i in range(1, 12):
    SCOPE[f"T{i}"] = "Move the types.rs items below into their concept module, byte-identically, and re-point the declared consumers."
SCOPE["T12"] = "Delete types.rs, remove `pub mod types;` from lib.rs. No item moves."
SCOPE["V-0"] = "Promote the listed items to `pub(crate)` in vault.rs (first-line visibility edits only). No moves."
for e in ["habit", "access_grant", "outbound_grant", "channel_identity", "counterparty_contact",
          "authority", "claim", "companion", "affect", "provenance", "deletion"]:
    SCOPE[f"V-{e}"] = f"Move the entity's `impl Vault` methods (+ entity-coupled free items) out of the vault.rs god-impl into a new `impl Vault {{…}}` block in {e}.rs, byte-identically, and re-point the declared consumers."

# S1/S2/S6 stages
DEP.update({"U": "S1 (test-split waves)", "B1": "U", "api-A": "stage T complete", "api-B": "api-A",
            "tests-w1": "PR-0 (S0)", "tests-w2": "PR-0 (S0)", "tests-w3": "PR-0 (S0)",
            "tests-w4": "PR-0 (S0)", "tests-s2-unmount": "U", "tests-s2-export": "B1"})
SCOPE.update({
    "U": "Delete the two `#[path]` mounts + pub-use blocks in types.rs, re-point the lib.rs flat façade and every crate::types::{companion,psych_profile} consumer to the un-mounted modules. No item moves.",
    "B1": "`git mv` export.rs/secret_scan.rs into src/batch/ and drop the two `#[path]` attrs. Byte-identical relocation; module paths unchanged. No item moves.",
    "api-A": "Split 11 leaf HTTP domains out of api.rs into api/<domain>.rs (MM D2, unchanged).",
    "api-B": "Split the core/run_tree/memory/conversations/context_pack domains + api tests out of api.rs.",
    "tests-w1": "Move each module's inline `#[cfg(test)] mod tests` block to a sibling `<mod>/tests.rs`, verbatim.",
    "tests-w2": "Move each module's inline `#[cfg(test)] mod tests` block to a sibling `<mod>/tests.rs`, verbatim.",
    "tests-w3": "Move each submodule's inline tests block to a sibling `tests.rs`, verbatim.",
    "tests-w4": "Move each oneiron-server module's inline tests block to a sibling `<mod>/tests.rs`, verbatim.",
    "tests-s2-unmount": "Move companion/psych_profile inline tests to sibling `tests.rs` (after un-mount).",
    "tests-s2-export": "Move the relocated export module's inline tests to `batch/export/tests.rs`.",
})


def git_show(path):
    p = subprocess.run(["git", "-C", ROOT, "show", f"{BASE}:{path}"], capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


def secs(stage):
    return D.parse_decls(os.path.join(MOVES, f"{stage}.decls"))


def rows(stage):
    return D.parse_tsv(os.path.join(MOVES, f"{stage}.tsv"))


def line_of(doc, row):
    m = D._find_row(doc, row)
    return (m[0]["sig_line"] + 1) if len(m) == 1 else "?"


def build(stage):
    m = rows(stage)
    d = secs(stage)
    doc_cache = {}

    def doc(path):
        if path not in doc_cache:
            t = git_show(path)
            doc_cache[path] = R.Doc(t) if t else None
        return doc_cache[path]

    out = [f"# HANDOFF {stage}: {SCOPE.get(stage,'').split('.')[0]}\n"]
    out.append(f"**BASE:** main tip after **{DEP.get(stage,'the prior stage')}** merges. "
               f"Re-derive every line number from your actual base at cut time (MM F7); the "
               f"numbers below are advisory (BASE `{BASE}`).")
    out.append(f"**BRANCH:** `refactor/{stage}`  ·  **WORKTREE:** fresh, per-worktree `target/`.")
    ex = "Codex" + ("  ·  **Fable reviews the conformance output** (consequence-grade ABI vocabulary)"
                    if stage in FABLE_REVIEW else "")
    out.append(f"**EXECUTOR:** {ex}\n")
    out.append(f"## Scope\n{SCOPE.get(stage,'')}\n")

    out.append("## Allowed files (exhaustive — touching ANY other file fails conformance)")
    for a in d.get("allowed", []):
        out.append(f"- `{a}`")
    if not d.get("allowed"):
        out.append("- (see manifest)")
    out.append("")

    out.append("## **FORBIDDEN ZONE — DO NOT TOUCH / \"FIX\" / REFORMAT:**")
    out.append(f"**{GUARD} (in-flight guard, allowed ONLY for this stage's declared use-line "
               f"splits if listed above) · any file not in Allowed · any item BODY (you MOVE, "
               f"never EDIT) · NO doc-comment/doc-link edits (byte-compared). NO semantic change "
               f"of any kind — this is a pure restructure.**\n")

    move_rows = [r for r in m if r["kind"] != "mod" or True]
    if move_rows and any(r["kind"] != "mod" for r in m) or m:
        out.append("## Move list (re-derived from BASE; if an item's identity doesn't resolve, STOP + report)")
        out.append("| kind | container | item (src:line) | cfg | dest | header change |")
        out.append("|---|---|---|---|---|---|")
        for r in m:
            dc = doc(r["src_file"])
            ln = line_of(dc, r) if dc else "?"
            hc = "add `pub(crate)`" if r["header_change"] == "yes" else "—"
            out.append(f"| {r['kind']} | {r['container']} | `{r['src_file']}:{ln}` | {r['cfg']} | "
                       f"`{r['dst_file']}` | {hc} |")
        out.append("")

    if d.get("add"):
        out.append("## Boilerplate to add VERBATIM (non-item additions)")
        out.append("```")
        for a in d["add"]:
            parts = a.split("\t", 1)
            out.append(f"# in {parts[0]}:" if len(parts) == 2 else a)
            if len(parts) == 2:
                out.append(parts[1])
        out.append("```")
        out.append("New modules/files start with `use super::*;` (or the declared imports); each "
                   "entity module gets exactly ONE new `impl Vault {…}` block at file tail, before "
                   "any trailing `#[cfg(test)] mod tests;`.\n")

    if d.get("decl"):
        out.append("## Declared surface changes (lib.rs re-exports / visibility bumps — apply exactly)")
        out.append("```")
        out.extend(d["decl"][:60])
        if len(d["decl"]) > 60:
            out.append(f"... (+{len(d['decl'])-60} more — see {stage}.decls)")
        out.append("```\n")

    ed = d.get("edit", [])
    if ed:
        out.append(f"## Consumer edits ({len(ed)}) — single-line `::`-path re-points, apply verbatim")
        out.append(f"**`{stage}.decls` (`## edit` section) is the AUTHORITATIVE complete list of all "
                   f"{len(ed)} edits — the excerpt below is illustrative. Apply every edit from the "
                   f"manifest, not just the ones shown here.**")
        out.append("Each is `file` → change the old line to the new line. Every OTHER changed line "
                   "in a consumer file must be `use`-shaped (use-tree splits) or these edits — the "
                   "consumer-diff-shape check hard-fails any smuggled change.")
        out.append("```")
        for e in ed[:40]:
            p = e.split("\t")
            if len(p) == 3:
                out.append(f"{p[0]}:")
                out.append(f"  - {p[1]}")
                out.append(f"  + {p[2]}")
        if len(ed) > 40:
            out.append(f"... (+{len(ed)-40} more — see {stage}.decls)")
        out.append("```\n")

    if d.get("frag-edit"):
        out.append("## Moved-item internal edits (frag-edit — inside the moved block)")
        out.append("```")
        for fe in d["frag-edit"]:
            p = fe.split("\t")
            if len(p) == 3:
                out.append(f"  - {p[1]}\n  + {p[2]}")
        out.append("```\n")

    out.append("## Rules")
    out.append("1. Cut-and-paste only. Attributes, doc comments, `#[cfg]` gates move WITH the item.")
    out.append("2. Bumps are `pub(crate)` only (never `pub(super)`/`pub(in …)`). Methods keep their vis.")
    out.append("3. Consumer files: ONLY `use`-line splits + the declared edits above. Nothing else.")
    out.append("4. If the build breaks on a missing name, add a `use`/re-export and note it. Any "
               "other break → STOP and report. Resolve NOTHING by judgment.\n")

    out.append("## Gate + conformance (run both; paste full output in the PR)")
    out.append("```bash")
    out.append(f"CARGO_TARGET_DIR=$PWD/target scripts/refactor/conformance.sh {stage} <BASE-SHA>")
    out.append("```")
    out.append("All checks (1–8 + E/C/F/X) then the WORKFLOW.md gate must print OK.\n")

    out.append("## Done-means")
    out.append(f"- `conformance.sh {stage}` OK for all checks, exit 0.")
    out.append(f"- PR titled `refactor({stage}): …`, body = conformance output.")
    out.append("- No file outside Allowed in `git diff --name-only`.")
    out.append("- You resolved no question yourself; anything ambiguous was reported back.\n")
    out.append(f"## Dependency\nDepends on **{DEP.get(stage,'?')}**. One PR in flight per file, ever.")

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, f"HANDOFF-{stage}.md"), "w") as f:
        f.write("\n".join(out) + "\n")
    return len(m)


if __name__ == "__main__":
    stages = [f"T{i}" for i in range(1, 13)] + ["V-0", "V-habit", "V-access_grant",
        "V-outbound_grant", "V-channel_identity", "V-counterparty_contact", "V-authority",
        "V-claim", "V-companion", "V-affect", "V-provenance", "V-deletion",
        "U", "B1", "api-A", "api-B", "tests-w1", "tests-w2", "tests-w3", "tests-w4",
        "tests-s2-unmount", "tests-s2-export"]
    for s in stages:
        n = build(s)
        print(f"HANDOFF-{s}.md: {n} rows")
    print(f"\n{len(stages)} handoffs written to {OUT}")
