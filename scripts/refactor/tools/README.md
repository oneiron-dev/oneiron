# scripts/refactor/tools — conformance + manifest generators

The machinery that produced `../conformance.sh` and everything under `../moves/`.
Committed so the manifests are reproducible and reviewable (not tmp-only). All
scripts default to `ROOT = /Volumes/Cinema/pink-worktrees/t1443` and
`BASE_REV = b2437d700` (the cut worktree/base) — override with the `GEN_ROOT`
and `BASE_REV` env vars (empty values fall back to the defaults) to reuse
elsewhere. Run with `RUSTFMT_BIN=$(rustup which rustfmt)` (or any rustfmt on PATH).

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
| `handoff_v2.py` | Emits the 34 Codex handoff packages to `fable-queue/oneiron/handoffs/`. | `handoff_v2.py` |
| `v2_selftest.py` | Synthetic self-test of the v2 checks (move-to-new-file + insertion + edit + comment + flat-name + HEAD-src removal). | `v2_selftest.py` |

**Regenerate everything from base:** `gen_s1.py && gen_t.py && gen_v.py && gen_u.py`
then B1/tests-s2-export (inline snippets in the state doc), then `build_conformance.py`,
then `handoff_v2.py`. See `../../../fable-queue/oneiron/handoffs/S0-CONTINUATION-STATE.md`.

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
