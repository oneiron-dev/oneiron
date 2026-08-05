# WORKLOG — ONE-1919 [SECRET-01] custody classes + manifest

Relay segment 0 · marker RELAY-ONE-1919-impl-seg0 · seat K3 · started 2026-08-05.

Contract: /Users/olety/.claude-wave5/blueprints/L1-SECRET/ONE-1919.md (read end-to-end; it governs).
Lane claims: /Users/olety/.claude-wave5/blueprints/L1-SECRET/CLAIMS.md (read; staying inside 1919 rows only).
Worktree: /Volumes/Cinema/w5-lt/l1-secret @ e9d9e9a (template == head, clean apart from boot worklog).

## Byte-space rider verdict (pre-dispatch law — DONE)

- Byte 86 is FREE at engine ground: `rg "ENTITY_TYPE.*=\s*86"` → nothing; registry.rs productivity band has 80–85 taken, 86+ free. Matches orchestrator REGROUND verdict (free band 64–75/77–79/86–99; treating that as free within still-old-band regions — live-tree 64–75/77–79 free, 124/128/129 occupied).
- Spine-lane conflict check: ONE-1754 (L1-STORAGE-SPINE, post-spine) plans to RE-KEY old-band bytes (incl. 86's region) under byte-space v3, and pins "ENTITY_TYPE_NOTE = 86 always lands before 1754" via L1-ENTITY ONE-1377. Our mint of 86 is a same-band collision with 1377's NOTE byte BY DESIGN of the shared registry claim (CLAIMS.md: "byte registrations — first-come, conformance test arbitrates").
- DECISION: mint ENTITY_TYPE_SECRET_CUSTODY = 86 per blueprint line 146. If 1377 landed first we'd take next free (87..); it hasn't (no =86 at ground). 1754 re-keys whole bands later as one atomic map — registrations are not re-keys, per rider. Journal the collision surface: src/tests.rs conformance rows are the arbiter; if L1-ENTITY merges NOTE=86 before we merge, our rebase must re-pick 87 and adjust tests.rs rows. (Intent: re-pick, never re-key.)

## Conformance machinery (explored, task #15)

- crates/oneiron/src/tests.rs has all_entity_type_prefixes (~L6373) matching module PREFIX constants (e.g. blob_artifact::PREFIX → "blob_art9") — adding a module means adding a PREFIX const + a row here ("secret_custody" names ≤ 10 chars).
- tests.rs type_byte_band_allocation_matches_contract (~L6740) mirrors docs contracts.ts band allocation. New byte = new mirror row here; satellite docs PR adds the authority row to oneiron-docs/site/src/data/oneiron-contracts.ts.

## TODO (segment order)

1. [~] Explore engine idioms: gate.rs manifest resolution, error taxonomy, body-key pattern, Vault method shape, sync packing path (nearly done — compaction cut in)
2. [ ] Write crates/oneiron/src/secret_custody.rs (+ secret_custody/tests.rs)
3. [ ] Write crates/oneiron/src/secret_manifest.rs (+ tests) + fixtures dir
4. [ ] registry.rs row · error.rs variants · lib.rs mods · sync interim guard (ONE hunk, names ONE-1865) · tests.rs conformance rows
5. [ ] cargo test -p oneiron green (cheap gate, -j 6 max) → commit → push none (gh stack sync is orchestrator-only verb for publish; lane commits stay local until told)

NEXT: finish idiom exploration (error.rs taxonomy + sync packing filter), then write secret_custody.rs per blueprint keystone skeleton lines 41-128.

## SEGMENT 0 OUTCOME (RELAY-ONE-1919-impl-seg0) — implemented + full gate GREEN

- Byte rider verdict: minted **ENTITY_TYPE_SECRET_CUSTODY = 86** (blueprint line 146). Race vs L1-ENTITY ONE-1377's NOTE=86 is documented first-come (CLAIMS.md); if they merge first this lane rebases to 87. Spine ONE-1754 re-keys bands later — we register, never re-key.
- Files landed (all within lane claims):
  - `crates/oneiron/src/secret_custody.rs` — CustodyClass (kebab canon), CustodyTier (T0<T1<T2 exposure ordering), TierBand, SecretCustodyFloor (resolve from POLICY_MANIFEST bodies, most-restrictive merge), SecretBinding/Status/Record/Metadata (metadata value-less by construction; Debug redacts value_bytes), encode/decode (13 keys = 13 fields), SECRET_NAME_INDEX_PREFIX, Vault::{register_secret, resolve_secret_ref, get_secret_metadata, get_secret_value_in_txn}.
  - `crates/oneiron/src/secret_custody/tests.rs` — 15 tests.
  - `crates/oneiron/src/secret_manifest.rs` — SecretManifest/Entry, validate_secret_manifest (narrow-only, ManifestWidensFloor), parse_secret_manifest (minimal line-oriented TOML-surface parser — engine has NO toml dep; workspace deps forbid adding one outside claims, so a deliberately small subset parser covers the declared fixture shapes).
  - `crates/oneiron/src/secret_manifest/tests.rs` — 11 tests (parse + narrow/widen validation).
  - fixtures: `crates/oneiron/tests/fixtures/secret_manifest/{valid.toml, widening_reject.toml}`.
  - registry.rs: const + registry row (kind SECRET_CUSTODY, prefix "sc", Pack / Productivity).
  - error.rs: Error + ErrorKind — InvalidSecretCustodyBody, SecretNameInUse, SecretCustodyNotActive, SecretBindingDenied, ManifestWidensFloor.
  - lib.rs: `pub mod secret_custody; pub mod secret_manifest;`.
  - sync/selector.rs: interim ONE-1865 guard — `entity_selector_decision` returns None for ENTITY_TYPE_SECRET_CUSTODY (comment names ONE-1865).
  - tests.rs: conformance mirror row for byte 86; moved the two `register_structural_kind(86,...)` test uses to byte 87; unregistered-byte probe list 86→87.
- Deviations from a naive read of blueprint (both within claims): (a) manifest parse is a subset TOML parser, not the `toml` crate (no dep reservation); (b) `get_secret_value_in_txn` is `#[cfg_attr(not(test), allow(dead_code))]` — blueprint declares the door but SECRET-02 owns its consumers.
- Gates: `cargo check -p oneiron --all-features` clean; `cargo test -p oneiron` lib = **2757 passed / 0 failed / 24 ignored**; lane `secret_` filter = 39 passed. Committed as one commit (unsigned, no attribution) on `w5/l1-secret/main`.

INTENT for next segment (if any): docs-repo satellite PR adds the authority row to `oneiron-docs/site/src/data/oneiron-contracts.ts` (entityTypes row for SECRET_CUSTODY, byte 86) — separate same-day PR, not this worktree. Await orchestrator verdict on the byte-86 first-come outcome vs ONE-1377 before ONE-1920.
