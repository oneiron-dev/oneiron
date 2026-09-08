# scripts/refactor/tools — conformance + manifest generators

The machinery that produced `../conformance.sh` and everything under `../moves/`.
Committed so the manifests are reproducible and reviewable (not tmp-only). All
scripts default to `ROOT` = this repository (derived from the script's own
location) and `BASE_REV = b2437d700` (the wave's cut base; gen_t.py defaults to
`da0458dda`, the base its committed manifests were recut against) — override
with the `REFACTOR_ROOT` (older name `GEN_ROOT`, still honoured) and `BASE_REV`
env vars (empty values fall back to the defaults) to point at a cut worktree.
Generated output that is not a manifest goes under the gitignored `target/`:
`REFACTOR_REPORT_DIR` (line reports, default `target/refactor-linereports/`) and
`REFACTOR_HANDOFF_OUT` (handoff packages, default `target/refactor-handoffs/`).
Run with `RUSTFMT_BIN=$(rustup which rustfmt)` (or any rustfmt on PATH).

| file | purpose | invocation |
|---|---|---|
| `rustlex.py` | Rust structural extractor (mask strings/comments/chars, enumerate top-level items + impl methods + `mod tests` items, canon-tokenize heads, cfg filter, rustfmt byte-compare, edit-delta validator, flat-name parser). The engine embedded into `conformance.sh`. | library; CLI: `rustlex.py enumerate <file>` / `find <file> <kind> <container> <name> <cfg>` / `inventory` / `impls` |
| `driver.py` | Conformance checks 1–8 + E/C/F/X. Embedded into `conformance.sh`. | `driver.py checks <root> <stage> <base> <movesdir>` |
| `build_conformance.py` | Assembles `../conformance.sh` by embedding rustlex + driver as a `#>`-prefixed payload. **Re-run after any rustlex/driver edit.** | `build_conformance.py` |
| `gen.py` | PR-0 generator: VAULT_A/VAULT_B method lists, api partition, `gen_tests`. Imported by the others. | (library) |
| `gen_s1.py` | S1 test-split recut + S2 deferred. | `gen_s1.py` |
| `gen_t.py` | Stage-T (types.rs dissolution): partition + census + sweep + decl simulation → T1-T12. | `gen_t.py` |
| `gen_v.py` | Stage-V (vault-CRUD insertion): V-0 + 7 clean + 4 intricate entities. | `gen_v.py` |
| `gen_u.py` | Stage U (types.rs `#[path]` un-mount) decl + consumer sweep. | `gen_u.py` |
| `handoff_v2.py` | Emits the 34 Codex handoff packages to `$REFACTOR_HANDOFF_OUT` (default `target/refactor-handoffs/`). | `handoff_v2.py` |
| `v2_selftest.py` | Synthetic self-test of the v2 checks (move-to-new-file + insertion + edit + comment + flat-name + HEAD-src removal). | `v2_selftest.py` |

**Regenerate everything from base:** `gen_s1.py && gen_t.py && gen_v.py && gen_u.py`
then B1/tests-s2-export (inline snippets in the wave's continuation-state doc, which
is kept outside this repo), then `build_conformance.py`, then `handoff_v2.py`.

## Freshness (D-2 guard)

`conformance.sh` embeds `rustlex.py` + `driver.py` as a payload. **After ANY edit to
either, re-run `build_conformance.py`** or the shipped gate silently runs the old code.
`build_conformance.py --check` asserts freshness (exit 1 if stale) and is wired into
`v2_selftest.py`.

## check-X precondition (review round 2)

`check_exhaustion` (T12) auto-excises `use` items + the `mod tests` shell + declaration-
only `#[path]` mounts. A **non-`tests` mod WITH a body is NOT auto-excised** — its items
must be moved individually (manifest rows) or they surface as residue and fail the check.
For a future file whose dissolution moves a bodied non-tests submodule, add that
submodule's items as manifest rows; do not rely on shell excision.

## Consumer-completeness (H3)

`consumer_complete.py` asserts every moved pub/pub(crate) item's cross-module consumers —
inline paths, brace-nested + multi-line use-trees, AND nested-module paths (non-flat
names) — appear in the stage's `## allowed`. Run at every package-cut (T/V/U).

## `split_check.py` — manifest-free move-only split gate

`split_check.py <base-rev> <old-file> <new-dir>` (paths relative to the cwd; deps:
`python3` + `git` + `rustfmt`/`RUSTFMT_BIN`). The little sibling of `conformance.sh`
for the common campaign case — `foo.rs` → `foo/mod.rs` + children — with no manifest:
the old file at `<base-rev>` IS the manifest. Exit 0 = pure move, 1 = drift (one
`FAIL …` line per problem, then `SPLIT-CHECK OK <old> -> <n> children (<m> items)` /
`SPLIT-CHECK FAIL <old>: <k> problem(s)`); any exception fails closed with
`SPLIT-CHECK-ERROR` + exit 1.

What it checks (new side = working tree, every `*.rs` directly under `<new-dir>`):

- `<old-file>` no longer exists; `<new-dir>/mod.rs` exists and carries a `mod x;`
  for every child `x.rs`.
- Base file and each child are rustfmt-normalised whole (`rustlex.rustfmt`, edition
  2024, comment options off, no repo `rustfmt.toml`), then `rustlex.enumerate_items`
  on both. Items match by `(scope, kind, name | impl-header canon, cfgs)` and every
  base item must land in exactly one child: missing / duplicate / extra = FAIL.
- Bodies (doc comments + attributes included) must be byte-identical after the
  leading visibility keyword is stripped; a `pub`↔`pub(crate)`↔`pub(super)`↔private
  change is an `INFO vis …` line, never a failure. A mismatch prints a unified diff of
  the two normalised fragments (capped at 60 lines); an item that only reflows because
  it moved between an inline `mod tests` body and a file top level is re-formatted
  standalone before it is called a mismatch.
- Scope: `top` = the file body; `tests` = the base file's inline `mod tests { … }`
  body. On the new side `tests.rs` / `*_tests.rs` children and an inline `mod tests`
  in any child are the `tests` scope, so moved tests are still 1:1. `tests.rs` /
  `*_tests.rs` are skipped (INFO) when the base file had no inline `mod tests`.
- An impl header that lands in more than one child (the usual way a 6k-line
  `impl Vault {}` gets split), or that the base already carried more than once, is
  compared per associated item (`method` / `const` / `type`) instead; each part's
  residue — header, attributes, docs, anything that is not an associated item — must
  equal the base's.
- Allowed new-side extras (module plumbing, also ignored on the base side): `use` at
  any visibility incl. `#[cfg(test)] use …` seams, `mod x;` declarations, `#![…]`
  inner attributes, `//!` docs, `extern crate`, free comments and blank lines.
- Anything `enumerate_items` does not recognise (a top-level macro invocation such as
  `thread_local! { … }`, an `extern "C" { … }` block) is compared as an opaque
  canon-tokenised residue chunk, also 1:1. Reported line numbers are those of the
  rustfmt-normalised text, not the file on disk.

Cost: whole-file rustfmt once per side plus a byte-equality fast path; an 18k-line
file checks in ~0.5 s, so no per-fragment batching is needed. Tests:
`python3 -m pytest scripts/tests/test_split_check.py -q` (throwaway git repo + fixture).
