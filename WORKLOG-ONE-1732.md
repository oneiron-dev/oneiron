# WORKLOG — ONE-1732 [L1-SPINE S1-4 · TERMINUS] storage ABI cutover + off-record docs repair

Lane: L1-STORAGE-SPINE, stack S1 layer 4 (the spine chain **ends here**).
Blueprint: `/Users/olety/.claude-wave5/blueprints/L1-STORAGE-SPINE/ONE-1732.md`
Engine worktree: `/Volumes/Cinema/w5-lt/l1-spine` (branch `ONE-1732`, cut off `4f5360daa`)
Docs worktree: `/Volumes/Cinema/w5-lt/docs` (branch `ONE-1732`, cut off `24ee8755`)

---

## 1. The number, read from the tree

`STORAGE_ABI_VERSION` on the rebased P6 head (`4f5360daa`, ONE-1731 #640 merged) was
**15**. Advanced exactly once to **16**. No target was assumed; the stale ticket
instruction "12 → 13" was never used, and no second bump exists anywhere in the diff.

```
crates/oneiron/src/store.rs:193   pub const STORAGE_ABI_VERSION: u16 = 16;
```

The v16 entry heads the version-history doc comment above the constant. It states the
reason (off-record fence families gone from the vault contract; off-record state is
session-ephemeral), why a v15 stamp cannot be honored (this engine carries no code that
reads those rows), and the verdict (fail closed; rebuild). The entry deliberately avoids
writing the fence-era key prefix literally — `branch_store_oracle.rs`'s
`fence_symbol_census_returns_zero_hits` greps every `src/**.rs` for those symbols and
would have failed on a doc comment.

## 2. The gate is untouched

`gate_storage_abi_value` is byte-identical to its pre-1732 form: strict equality,
fail-closed in both directions, `Ok(true)` only for a genuinely new vault. This ticket
ships **no** migration runner, legacy decoder, cleanup pass, compatibility flag, or
accept-previous branch. The 1754 single-predecessor carve-out belongs to 1754 and is not
anticipated here in any form.

## 3. `MIGRATIONS.md`

New final section `## OF-326 / ONE-1732: off-record branch store (storage ABI v15 → v16)`
carrying the actual numbers (15 → 16), the required statement verbatim —

> **off-record fence families removed; off-record state session-ephemeral; older vaults rebuild.**

— plus the explicit "**There is no migration pass**" and "**No production vaults exist**"
sentences. Note the file's previous last entry was ABI v3 (M2-5/ONE-1102); v4–v15 were
never recorded there. This ticket adds its own entry and does not backfill the gap.

## 4. Oracle: renamed, armed, literal-free

`crates/oneiron/src/branch_store_oracle.rs`

- `storage_abi_v12_vault_fails_closed_on_v13_engine` →
  **`storage_abi_previous_vault_fails_closed_on_current_engine`**. Zero source hits remain
  for the old name (`rg` over the whole worktree, `target/` excluded).
- `#[ignore = "armed by ONE-1732"]` removed; the test runs in the default suite.
- `current = crate::store::STORAGE_ABI_VERSION`, `previous = current.checked_sub(1)`. No
  ABI version literal appears in the fixture, the assertion, or the messages.
- `seam::open_with_abi_pair` no longer `unimplemented!()`. Empty directory → the open runs
  at `stored` (a new vault stamps whatever version the opening engine carries, so that IS
  how the fixture acquires its stamp); populated directory → the open runs at `engine`, and
  the gate compares. `map_abi_error` maps **only** `Error::StorageAbiVersionChanged` to
  `SeamError::AbiFailClosed` and panics with the production error on anything else —
  the same one-to-one discipline as the file's existing `map_session_error` /
  `map_executor_error`, so an unrelated open gate cannot satisfy the assertion.

## 5. The ABI-injection opener is test-only by construction

`crates/oneiron/src/vault.rs` gained `#[cfg(test)] pub(crate) fn
open_with_storage_abi_version_for_test(path, config, engine_storage_abi)`. It is absent
from every built artifact and invisible outside the crate. `Vault::open`,
`Vault::open_unseeded_for_test`, and `Store::open` take no ABI argument and continue to
gate on the compiled constant — there is no caller-supplied path around the gate.

To avoid duplicating the open body, `open_seeded` was split at the `Store::open` line:

- free `fn validate_open_config(&VaultConfig) -> Result<()>` — the three pre-mmap config
  preconditions, unchanged and still evaluated before the environment is opened;
- `fn finish_open(store, config, seed_default_manifest) -> Result<Self>` — analyzer
  discovery, text-index handshake, first-open seeding, reserved-actor census, skill-hub
  backfill. Byte-identical body, moved.

Both openers call the same two pieces, so the test path exercises the production assembly
rather than a parallel one. `Store::open_with_storage_abi_version_for_test` already existed
under `#[cfg(test)]` and was reused as-is.

## 6. Off-record module docs

- **`off_record/mod.rs`** — root docs rewritten around exactly the four public verbs
  **enter / mode flip / promote / close**, each with what it does and where writes land,
  followed by the session-ephemerality statement that motivates v16 and a pointer to
  `lifecycle` (enter/flip/close + registry) and `promote` (replay + receipt). Intra-doc
  links are restricted to public items — `off_record` is a `pub mod`, so linking
  `lifecycle` / `promote` / `SessionOverlay` would raise `private_intra_doc_links`; those
  are plain code spans.
- **`off_record/lifecycle.rs`** — **zero diff, deliberately** (see Deviation D1). ONE-1731
  already rewrote this header around the same four verbs; it contains no
  `Known limitations` heading and no fence-era mechanism claim (public/retro tag, durable
  fence rows, defer-sync scrub, export refusal, telemetry-registration MUST,
  delete-at-close cascade, closed-fence tombstones, orphan-fence recovery — all verified
  absent by grep). Rewriting correct prose for the sake of a diff would be churn.

## 7. Docs repair — canonical DATA, then the pages that render it

`site/src/data/oneiron-contracts.ts` is the source; the `.astro` pages import from it.

- `dbManifest` recounted against `store.rs::DB_MANIFEST` **at landing**: 28 rows. The three
  missing rows are `job_records` (26), `job_ready` (27), `job_dedupe` (28), group `Jobs`.
  Their `key` / `value` / `purpose` strings are grounded in `attempt_queue.rs`, not
  invented: `job_ready`'s 24 B key is `ready_at u64 BE ‖ attempt_id`, `job_dedupe`'s is a
  32 B blake3 over `domain ‖ len(kind) u16 BE ‖ kind ‖ len(dedupe_key) u16 BE ‖ dedupe_key`,
  `job_records` values are `record_version u8 ‖ MessagePack AttemptRecord`.
- `DbGroup` gained `"Jobs"`; `DbEntry.n` doc says `1..28`; the section banner, the
  `dbManifest` doc line, and the file-header `DB=25` note all say 28.
- `dbConfig`: `dbCount` 25 → **28**, new `attemptQueueDbs: 3`, `storageAbiVersion` 6 → **16**,
  `source` `DB=25` → `DB=28`, `maxDbsHistory` records that ONE-1206 consumed #26–#28.
- `storageAbiPolicy` rewritten to the truth: a strict-equality handshake that fails closed
  in both directions, **no** migration runner and **no** legacy decoder, rebuild pre-launch.
- New `storageAbiHistory` string (v16 first, then the grounded v15…v1 list read off the
  engine's own version-history comment).

`site/src/pages/oneiron/storage-abi/index.astro`

- ABI invariant row now renders `dbConfig.storageAbiPolicy` (fail-closed/rebuild), replacing
  "physical layout changes require migration, while append-only registry additions do not
  necessarily bump it" — which was false on both halves (there is no migration, and v15/v14/v10
  were exactly registry additions that DID bump).
- New `ABI history` invariant row.
- ARCH-0019's `owns` string is now `${dbConfig.dbCount}-DB manifest, fail-closed open gates`
  (was a hardcoded `25-DB manifest, ... migration runner`).
- Manifest-shape prose renders 28 = 23 core/retrieval + 2 sync + 3 attempt-queue.
- New negative constraint: no migration runner / legacy decoder / accept-the-previous-stamp
  exception is part of the ABI.
- New dated changelog entry (2026-08-07). The one surviving `v6` is the 2026-07-02 changelog
  entry, now explicitly prefixed `Historical:` and "then-current" — the blueprint's permitted
  clearly-dated historical wording. No current `v6` or `25 DBs` claim remains on the page.

`site/src/pages/oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.astro`

- §D9 now says: bump the current `STORAGE_ABI_VERSION` to its **next value at landing** —
  read the constant from the tree the change lands on and advance it exactly once, never a
  number pinned at design time — with the fence-removal/session-ephemeral/rebuild changelog
  statement, older development vaults rebuild, zero migration code. "12 → 13" and "v12
  vaults" are gone.
- §7 P7 bullet: "advance STORAGE_ABI_VERSION one step from whatever the landing tree carries
  (per D9)" — "STORAGE_ABI_VERSION 13" is gone.
- Forward-link title "Storage ABI explainer (v13 bump)" → "(the P7 bump)".
- §8 discrepancy bullet's stale "code says v12/28" replaced with the engine's real stamp and
  28-row manifest, marked "(fixed by the P7 landing)".

Generated mirrors were produced by `bun run export:agent` only — never hand-edited.

## 8. Follow-up issue (non-blocking)

Filed via `linearis` with the exact ratified title and body, no guessed id:

**ONE-1944 — `[BRST hardening] SessionOverlay process-memory hygiene`** (team ONE, Backlog).

Explicitly non-blocking for launch and for this merge. Link it from the implementation PR.

## 9. Gates

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo check -p oneiron --all-features --all-targets` | clean |
| `cargo clippy -p oneiron --all-features --all-targets` | clean (0 warnings) |
| `cargo test -p oneiron --all-features` | **52/52 binaries ok · 3983 lib + all integration + doctests passed · 0 failed** (log: `/tmp/one-1732-final-test.log`) |
| docs `bun run export:agent` | **PASS — no blocking problems** (0 broken links · 0 stale mirrors · 0 dup ids). 7 + 12 pre-existing warnings, none in this lane's files |

The 5 lib-ignored tests are other tickets' unarmed oracles; 1732's oracle is unignored and
passing. `Cargo.lock` is untouched (`git diff --name-only origin/main..HEAD` contains no
`Cargo*` path). No `git add -A` was used at any point.

---

## Deviations and PACKET_AMEND candidates — declared, none silently absorbed

### D1 — `off_record/lifecycle.rs`: zero diff (deviation, not an omission)
The blueprint says "rewrite the module docs at the top of `lifecycle.rs` … around the four
public verbs". ONE-1731's sweep already landed exactly that shape, including the deletion of
the `Known limitations (OFRC-2 scope)` section and every fence-era claim. The done-means
("name exactly the four verbs, describe overlay routing, no `Known limitations` heading, no
fence-era mechanism claim") is satisfied by the file as it stands. I made no edit rather than
re-word correct prose. The four-verb ROOT doc the blueprint also asked for landed in
`off_record/mod.rs`, which had only a one-line header.

### D2 — PACKET_AMEND candidate: `crates/oneiron/src/tests.rs` (out of packet)
Seven `assert_eq!(STORAGE_ABI_VERSION, 15, "ONE-1743 pins …")` tripwires. They exist to force
the bumping ticket to look, and they hard-fail on any bump. Retargeted mechanically to `16`
with the message renamed to ONE-1732 / the off-record fence-family removal. Nothing else in
the file was touched. CLAIMS.md lists `crates/oneiron/src/tests.rs` for 1754's
`all_entity_type_prefixes` table under a table-level partition — a different region, so no
collision. Precedent: ONE-1743 (the v15 bump) owns the current wording of those same lines.

### D3 — PACKET_AMEND candidate: `crates/oneiron/src/batch/export/tests.rs` (out of packet)
`export_manifest_stable_fixture_records_data_shape_and_secret_nulling` pins the whole export
manifest as one expected JSON string containing `"storage_abi_version": 15`. One number
changed to `16`; the rest of the fixture (28 named databases, groups, max_dbs) already matched
and was not touched.

### D4 — in-lane per CLAIMS.md, wider than the relay PACKET line: `store/tests.rs`
The relay PACKET named `store.rs`; CLAIMS.md's store row reads `store.rs + store/tests.rs`, so
this is in-lane. Two edits, both forced by the bump:
- `RECEIPT_FAMILY_VERSION_ABI_PINS` `(15, [0,2,1,1])` → `(16, [0,2,1,1])`. Note this table is
  **replaced, not appended**: `receipt_family_version_abi_pins_are_strictly_monotonic` requires
  each successive pin to change at least one receipt version, and this bump changed none.
- `abi_15_vault_is_rejected_before_an_abi_12_reader_checks_receipt_markers` →
  `current_abi_vault_is_rejected_before_an_older_abi_reader_checks_receipt_markers`, with the
  vault's own stamp now matched as the `STORAGE_ABI_VERSION` const pattern instead of a literal
  `15`. The older reader stays a named `OLDER_READER_ABI = 12` const — it deliberately names a
  version this engine is not.

### D5 — PACKET_AMEND candidate (docs): `site/src/pages/oneiron/core/oneiron-arch-0019-oneiron-db-v1.astro`
Not in the blueprint's claims, but it renders FROM `dbManifest` / `dbConfig`, so my data repair
propagates into it whether I touch it or not. Its manifest TABLE is fully data-driven and now
correctly lists all 28 rows; without an edit its intro prose would have read "Twenty-five named
databases sit inside: 23 core/retrieval plus 2 sync" directly under a data-driven "28 LMDB
databases per vault" heading and above a 28-row table. Two minimal edits: that one sentence,
and a `.grp-pill.grp-jobs` CSS rule so the new group's pill is not unstyled. Nothing else.

### KNOWN HOLE — the 25-DB claim survives outside this packet
`ARCH-0019`'s Fig. 1 SVG is driven by a hardcoded `groupBoxes` array of seven bands and does not
include `Jobs`; its figure caption, its `aria-label`, and the page-summary string still describe
25 databases, as do `system.astro`, `dec-0004`, the ARCH-0005/0005a backend diagrams, ARCH-0031,
and roughly a dozen research comparison tables. Correcting the SVG is diagram surgery (new band,
viewBox height, cell layout) and the rest is a repo-wide sweep — both well outside a P7 ABI
ticket. ONE-1732 repaired the canonical DATA and the two pages it claims; the propagation sweep
wants its own ticket. Flagging for the postmortem bank rather than absorbing it.

### Scope note — `system.astro` still says `STORAGE_ABI_VERSION=6`
`site/src/pages/oneiron/system.astro:314` carries a hardcoded `STORAGE_ABI_VERSION=6` and
"25 named databases" in a prose paragraph. Out of packet, and it belongs to the same sweep as
the known hole above. Named here so it is not lost.

---

## SIMPLIFY (K3, 2026-08-07)

Deletion-biased pass over the impl leg, both repos. One edit warranted:

- `branch_store_oracle.rs` seam: the single-use helper `map_abi_error` is inlined into
  `open_with_abi_pair`'s `map_err` closure (its "only the ABI mismatch is the verdict"
  rationale survives as an inline comment), and the four-line `read_dir` match collapses to
  one `map_or`. Net −14 lines, zero behavior change. Test assertions, fixtures, public API,
  and the strict-equality gate are all untouched.

Everything else was left as built, deliberately: the `validate_open_config` / `finish_open`
extractions in `vault.rs` ARE the deduplication (the test-only ABI opener shares the
production open body instead of copying it); the `store.rs` v16 doc entry, `MIGRATIONS.md`
section, `off_record/mod.rs` four-verb module docs, and all docs-repo wording are
blueprint-ratified text — a simplify pass does not edit ratified prose.

Gates after the edit: `cargo test -p oneiron --all-features` filters `storage_abi` (8/8,
incl. `storage_abi_previous_vault_fails_closed_on_current_engine`), `older_abi` /
`export_manifest_stable` / `open_rejects_abi` (9/9) all green; `cargo fmt -p oneiron
--check` clean; `cargo clippy -p oneiron --all-features --tests` clean.

Docs repo: no edit warranted — the diff is canonical-data repair plus ratified wording, and
the generated mirrors are export output only.
