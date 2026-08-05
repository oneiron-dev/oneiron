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

## SIMPLIFY SEGMENT 0 OUTCOME (RELAY-ONE-1919-simplify-seg0) — DONE

Single-pass inline cleanup completed without the usual four-agent fan-out (the `/simplify` skill reported Agent unavailable). The same pass covered all four required angles:

- **Reuse:** kept MessagePack/index helpers module-local because the matching `gate.rs`/`claim.rs` helpers are private and those files are outside this packet; aligned the local implementations with the established exact-key and `EntityId`-length idioms instead of adding a shared abstraction.
- **Simplification:** removed unused manifest line-number plumbing, manual scratch defaults, an unused derive, a trivial boolean wrapper, a redundant closure argument, and the single-use stored-record decode layer.
- **Efficiency:** removed three `String` clones from diverging error paths; ownership now moves only on branches that return.
- **Altitude:** used `ENTITY_ID_LEN` for exact type-index key parsing and removed a stale comment that claimed register-time floor recomputation not performed by this ticket. No call-site special case or new layer was added.

### Simplifiable-confess verdicts (2/2)

1. **Small TOML-subset parser instead of a `toml` dependency — KEEP, simplified internally.** `Cargo.toml` is outside ONE-1919's dependency reservations, and the declared fixture surface is intentionally narrow. The pass deleted parser bookkeeping without widening the grammar or adding a dependency.
2. **`#[cfg_attr(not(test), allow(dead_code))]` on `get_secret_value_in_txn` — KEEP.** SECRET-02 consumes this ratified crate-private keystone signature. Removing the door would break the next stacked ticket; adding a wrapper would be speculative structure.

No other simplifiable-confess appears in this worklog. Public API signatures, test assertions, test fixtures, registry byte 86, and the ONE-1865 interim sync guard are unchanged. Final vet result: **no issues found** (the pre-existing untracked `WORKLOG-LANE-BOOT.md` remains untouched and unstaged).

- Final gates: `cargo check -p oneiron --all-features --locked -j 6` **GREEN**; `cargo clippy -p oneiron --all-features --locked -j 6 -- -D warnings` **GREEN**.
- Simplify delta: **+84 / -132** across `secret_custody.rs` and `secret_manifest.rs` (net **-48** lines).
- Surviving ONE-1919 ticket diff, excluding worklogs: **+1875 / -3 across 11 files**.

NEXT: hand the simplified ONE-1919 base layer to the cross-model check; docs-repo satellite and byte-86 race handling remain orchestrator-owned.

## FIX LEG (K3 fix on 44849ed, 2026-08-05) — attacks the custody write/CRDT chokepoints

Seven verdict items applied in order, each its own commit on `w5/l1-secret/main`.

- **ONE-1919-FIX1 (CHOKEPOINT)** `sync/window.rs`: the selector decision already excluded byte 86 on selector export, but two canonical-doc copy paths did not. Added `is_secret_custody_record` (type-byte read) + `scrub_secret_custody_carriers`; `reverse_rematerialize` now refuses to insert a custody row AND scrubs a resident one (entity carrier + incident edges, tombstones untouched — mirrors the companion-local-only branch); `export_window_updates_since` runs the custody scrub beside the fence scrub and forces the window history-free on any removal. Tests `secret_custody_never_enters_doc_via_reverse_rematerialize` + `secret_custody_never_leaves_doc_via_export` run both pathways end-to-end against a live vault. PACKET-AMEND: `sync/window.rs` + its tests sit outside the seg0 CLAIMS rows (selector.rs ONE hunk); the hunks are minimal, all rejection plumbing lives in the lane-owned `secret_custody.rs`, and one constructor (`reject_secret_custody_byte`) is the single grep site for every door.
- **ONE-1919-FIX2 (BINDING-DOOR)** `secret_custody.rs`: `value_bytes` and `manifest_ref` dropped from `pub` to `pub(crate)`; added read-only `manifest_ref()` accessor. `Vault::get` returns opaque body bytes so a caller who decodes gets a record whose value field is a compile error outside the crate — the only sanctioned plaintext read is `get_secret_value_in_txn` (bound by effector). Test `value_read_goes_through_get_secret_value_in_txn_door` pins the bound/unbound decision at the door plus the accessor; the field-privacy half is the type boundary itself. Dependent crates (driver/ffi/napi/server) re-checked green.
- **ONE-1919-FIX3 (SCAN-CONFLICT)** `batch/secret_scan.rs` (lane's OF-067 claims slice): `scan_batch_ops` skips the credential-shape detector for `BatchOp::Put` with entity type byte 86 only — the custody record IS the safe container, scanning its value would reject the registration the module exists to hold. Every other entity type still scans (pinned by `credential_scan_still_rejects_other_entity_types`); `register_secret_with_credential_shaped_value_commits` registers ghp_+36 ASCII successfully.
- **ONE-1919-FIX4 (FLOOR-TOCTOU)** `register_secret` now resolves `SecretCustodyFloor` against the LIVE vault inside the write txn and enforces narrow-only: every binding's tier_ceiling <= live band max for the record's class, and the caller-attested `policy_floor_snapshot` must be narrower-or-equal to live (a stale wider snapshot can no longer launder exposure past commit). Tests pin `CrossVault`+`T2LocalRegistered` rejected against the default floor (band T0..T0) and portable+T2 accepted; a rejected registration never holds the name. (Verdict named `validate_secret_manifest`; the per-record binding/floor check enforces the identical narrow-only relation on the record actually being written, which is what register consumes.)
- **ONE-1919-FIX5 (BODY-SCHEMA)** `decode_secret_custody_body`: `bindings`, `manifest_ref`, `declared_paths`, `policy_floor_snapshot` now hard-reject when the key is MISSING (empty value remains legal — different concept from absent key). Test drops each key from a real body and pins the schema reject, plus present-but-empty still decodes.
- **ONE-1919-FIX6 (RAW-PUT-BYPASS)** `batch.rs` + door shape in `secret_custody.rs`: `validate_public_raw_put` rejects byte 86, and `apply_ops` rejects byte 86 on every shape except the engine-internal non-replicated door (`allow_maintenance && !allow_reserved_predicate` — the shape the default policy-manifest seeder uses). `register_secret` opts into that door shape, so the dedicated door commits while public puts, both batch builders, typed puts, and CRDT→LMDB sync replay all reject. `raw_put_doors_reject_secret_custody_byte` pins `put_entity` + batch put rejection and that no row lands. PACKET-AMEND: `batch.rs` is the engine's write-wall chokepoint (outside CLAIMS rows) — the arm is one early-return that names the custody module's constructor.
- **ONE-1919-FIX7 (REVERT-AND-LINT)** Reviewed simplify commit 44849ed hunk by hunk: it touched map-value helpers, parser scratch defaults, a `#[derive(PartialEq)]`, a trivial `as_bool` wrapper, three error-path String clones, and one stale comment (which wrongly asserted no register-time floor recompute; FIX4 now performs that recompute for real). **No FIX1..6 target line was deleted or modified by the simplify commit — nothing to revert; the blank-line/polish deltas ride forward intact.** Clippy found one `nonminimal_bool` in the new FIX6 door arm; simplified to `(!allow_maintenance || allow_reserved_predicate)`.

### Fix-leg gates

- `cargo test -p oneiron --all-features -j 6 —lib`: **3180 passed / 0 failed / 24 ignored** (includes 21 `secret_custody` + 2 `sync::window` custody tests).
- `cargo clippy -p oneiron --all-features -j 6 -- -D warnings`: **GREEN**.
- Commits: 2c59ed8 (FIX1) · e3bcc62 (FIX6) · c0f7dc9 (FIX2) · c33ba0c (FIX3) · b50db04 (FIX4) · 1c0f0fc (FIX5) · this commit (FIX-final). Worklogs (this file + WORKLOG-LANE-BOOT.md) committed here.

NEXT: hand `w5/l1-secret/main` to the running K3 verdict leg for a fresh read + ruling on the full diff from 44849ed through the FIX-final SHA.
