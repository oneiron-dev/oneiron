# WORKLOG — ONE-1377 [L1-ENTITY E2-L1] NOTE entity + `author_take`

Seat: Opus IMPL. Branch `ONE-1377`. Engine base `4f5360daa`; docs base `24ee8755`.
Blueprint: `/Users/olety/.claude-wave5/blueprints/L1-ENTITY/ONE-1377.md`.

## Final gate

- `cargo test -p oneiron --all-features` — **PASS** (3988 lib + all integration bins, 0 failed, 316s lib).
- `cargo clippy --workspace --all-features --all-targets` — clean.
- `cargo fmt --all` — applied.
- `cargo test -p oneiron-server --lib projection` — PASS (registry-iterating consumer of the new NOTE row).

Named tests, all green:
`note::tests::opinion_kind_round_trip` · `note::tests::decode_rejects_every_abi_deviation` ·
`facade::tests::two_actor_divergent_takes` · `facade::tests::take_never_mutates_claim` ·
`facade::tests::author_take_fails_closed_and_never_lets_a_caller_pick_the_author` ·
`serialize::tests::note_group_is_separate_from_claims_with_pinned_profile_fields` ·
`tests::all_entity_type_prefixes` · `tests::type_byte_band_allocation_matches_contract`.

## What landed

**Engine** (`/Volumes/Cinema/w5-lt/l1-entity`)
- `crates/oneiron/src/registry.rs` — `ENTITY_TYPE_NOTE = 86`, registry row `NOTE / 86 / Some("no") / Pack / Productivity`, inserted after `BLOB_ARTIFACT`. No engine constant names 106.
- `crates/oneiron/src/note.rs` (NEW) — `NOTE_BODY_KEYS`, closed `NoteKind{OpinionTake}` (wire literal `opinion/take`), `NoteBody`, `TakeTarget`, `encode_note_body` / `decode_note_body`.
- `crates/oneiron/src/note/tests.rs` (NEW) — kind round-trip + the full negative set.
- `crates/oneiron/src/facade.rs` — `MemoryFacade::author_take`; `put_structural` now refuses kind `NOTE`; module-level `registered_edge_weight`.
- `crates/oneiron/src/facade/tests.rs` — the three named behaviour tests.
- `crates/oneiron/src/serialize.rs` — `notes`/`NOTES`/`Notes` group + pinned per-profile field sets.
- `crates/oneiron/src/lib.rs` — `pub mod note;` + re-exports.

**Docs** (`/Volumes/Cinema/w5-lt/docs-1377`)
- `site/src/data/oneiron-contracts.ts` — `packEntityKinds` NOTE row → `typeByte: 106`; one `byteMigrationV3` row `{ NOTE, 86, 106, engine, assigned }`. Disjoint from the sections ONE-1732 is editing (`dbManifest` / `storageAbiVersion`).

## Hard-law compliance

- Byte split honoured: engine 86, canon 106, ONE-1754 owns the persisted re-key. No migration written here.
- `NoteKind` is closed at one variant; no placeholders for the other six ARCH-0032 kinds, no `Plugin`.
- Body ABI is exactly `kind` + `author_ref` + `markdown`. Decode rejects: bad MessagePack, trailing bytes, non-map, non-string keys, unknown keys, duplicate keys, unknown kinds, unparseable actor refs, blank markdown, missing keys.
- `author_ref` is stamped from the facade-bound actor only; the input carries no author field. `with_verified_actor_write_txn` performs the store-truth binding check inside the same write transaction.
- `TakeTarget::Subject` → `About`; `TakeTarget::Claim` proves type-0 CLAIM in-txn, then `ClaimOf`. Same transaction always writes NOTE + `AuthoredBy` → actor. Registered default weights used (`AuthoredBy` 0.9, `About` 0.5, `ClaimOf` 1.0) via `EdgeKind::default_weight()`; no edge kind minted, `edge.rs` untouched.
- Missing/wrong-class actor, missing target, non-CLAIM claim-target, and blank markdown all fail before any row is staged — asserted by the orphan check in the negative test.
- NEUTRAL-CLAIM invariant: `author_take` calls no claim verb. `take_never_mutates_claim` asserts the target's raw bytes, lifecycle, and short-ref content hash are identical and that `edges_in` gains exactly one edge, `(ClaimOf, note_id)`.
- Divergent takes append-only: two actors over one claim → two NOTE ids, two `AuthoredBy` edges, no dedupe.
- `serialize.rs`: Minimal = `kind` + `author_ref`; Standard and Full add `markdown`. Rows stay typed NOTE and never enter the CLAIM group (both asserted).
- `types.rs` not touched (does not exist). `edge.rs`, `Cargo.toml`, `Cargo.lock` untouched. Nothing pushed or merged.

## DEVIATIONS + PACKET_AMEND candidates — all declared, none silently absorbed

### PACKET_AMEND 1 — `crates/oneiron/src/error.rs` (TAKEN; additive)
Added `Error::InvalidNoteBody(&'static str)` + `ErrorKind::InvalidNoteBody` + its `kind()` arm.
- Why: `decode_note_body` returns `crate::error::Result` per the ratified skeleton, and every entity module in the repo owns an `Invalid<X>Body` variant (`InvalidBlobArtifactBody`, `InvalidAgentDefBody`, …). Reusing `InvariantViolation` would misroute the error to `FACADE_CODE_INTERNAL` instead of `BAD_REQUEST`.
- Pre-authorised by `CLAIMS.md:26` (lane owns `error.rs`, "additive; append-only enum edits merge-safe"). Not in the relay PACKET.
- Blast radius: append-only enum edits; `From<Error> for FacadeError` routes the new kind to `BAD_REQUEST` via its `_` arm, which is the correct code.

### PACKET_AMEND 2 — `crates/oneiron/src/tests.rs` (TAKEN; compile/assert-forced)
Added one `NOTE / 86 / Some("no") / Pack / Productivity` row to the `all_entity_type_prefixes` expected table, and `86` to the pack-byte loop.
- Why: that test does `assert_eq!(actual.as_slice(), expected)` over the whole registry — minting any row makes it red. Not optional.
- `CLAIMS.md:16` claims `tests.rs` for this lane but partitions "entity-type prefixes to 1754". Flagging for the seam: this is a one-row insertion in the shape 1754's sweep will re-key wholesale.

### PACKET_AMEND 3 — `crates/oneiron/src/serialize/tests.rs` (TAKEN; test-only)
Added `note_group_is_separate_from_claims_with_pinned_profile_fields`.
- Why: blueprint done-means "A test asserts the exact field set per profile." `fields_for_profile` and `group_labels` are private to `serialize.rs`, so the sibling tests file is the only home. Zero production surface. The lane already claims `serialize.rs` (`CLAIMS.md:17`).

### PACKET_AMEND 4 — `crates/oneiron/src/batch.rs` (**NOT TAKEN** — needs adjudication)
`apply_put` carries the per-type body-validation ladder (`validate_blob_artifact_body_bytes`, etc.). One additive arm there would enforce the NOTE ABI at the chokepoint for *every* write path including batch and sync replay.
- Not taken: `CLAIMS.md:12` puts `apply_put` in L1-STORAGE-SPINE's `batch-apply` partition, and the blueprint scopes validation to "every NOTE write path used by this ticket" — both of which this ticket's paths cover (see known hole 1).
- Recommendation: a one-line arm `else if entity_type == ENTITY_TYPE_NOTE { crate::note::validate_note_body_bytes(data)?; }` in the spine lane or a follow-up ticket. `validate_note_body_bytes` was deliberately NOT written here (it would be dead code).

### Implementation choice — `author_ref` is a 32-hex string on the wire, not `Value::Binary`
The blueprint skeleton pins the Rust type (`author_ref: EntityId`) but not the MessagePack scalar.
- Chose hex string: the generic retrieval projection (`context_pack::rmpv_to_json`) maps `Value::Binary` → JSON `null` (see the comment at `context_pack.rs:1866`: CLAIM's `subj` "is binary on disk so it projects as JSON null"). A binary `author_ref` would render the pinned Minimal-profile field as `null`, killing blueprint line 22's stated purpose — the renderer labelling the row "{actor} take".
- Prior art for hex-string ids in structural-kind bodies: `skill.rs:492` (`forked_from`) and `agent_def.rs:520` (`world`). Decode still rejects invalid actor bytes via `EntityId::from_hex`.

### Scope note — `put_structural` refuses kind `NOTE`
Not named in the blueprint, but forced by the hard law "author_ref comes ONLY from the MemoryFacade-bound actor; no caller override". Registering byte 86 makes `type_byte_for_kind("NOTE")` resolve, so without this refusal a caller could hand-write `author_ref` and forge another actor's take. Follows the existing `CLAIM` / `MACHINE` refusals on that door. Asserted in the negative test.

### Scope note — canon NOTE row also gets `shortIdPrefix: "no"`
The relay's docs packet named `typeByte: 106` + the migration row. I also set `shortIdPrefix: "no"` on that same row because the engine registry now pins that prefix; leaving canon `null` would ship a docs-vs-engine contradiction and a wrong `shortIdPrefixes` derived export. `"no"` is collision-free in both the engine registry and canon. Same row, same lane, additive.

## Known holes (banked, not fixed)

1. ~~**Raw batch/sync puts of byte 86 bypass the NOTE body ABI.**~~ **NARROWED by the VERDICT-FIX below to the SYNC half only.** The raw-batch half was adjudicated a REAL P1 and is closed (PACKET_AMEND 5): both public builders now refuse entity type 86. What remains is `put_replicated` / `replicated_put_op`, which skip `validate_public_raw_put` by design for every type — a peer's replicated NOTE body is not ABI-checked and its `author_ref` is peer-asserted. Same posture as the documented Habit-streak sync carve-out; spine/sync partition, not this lane's door.
2. **Docs `generated/**` mirror not refreshed.** The docs commit hook warns that `site/src` changed without `bun run export:agent`. Per relay, the ONE-1732 lane runs the export; `site/node_modules` is not installed in this worktree and the relay states the docs half needs no export run. Handoff item for whoever publishes the docs branch.
3. **No server/MCP surface for `author_take`.** Engine verb only, per blueprint scope (`ONE-1936` layers the verb-on-stale guard).

## SIMPLIFY pass (K3, 2026-08-07)

**NO EDIT WARRANTED.** Deletion-biased review of the full lane diff (note.rs, facade.rs, registry.rs, serialize.rs, error.rs, lib.rs + tests):

- `note.rs` is the pinned keystone skeleton; `KEY_*` consts exist because `&str` match arms need const patterns, `validate_markdown` is shared by encode/decode, the `unreachable!` arm is compile-forced. Nothing removable without touching the pinned public API.
- `registered_edge_weight` (facade.rs) was the one deletion candidate; kept — inlining would duplicate the `unwrap_or(1.0)` magic at two sites and lose the doc pinning parity with `put_structural`'s null-`pprWeight` fallback.
- The `put_structural` NOTE refusal mirrors the existing CLAIM/MACHINE refusals; no new layer.
- serialize.rs / registry.rs / error.rs additions match their surrounding patterns exactly.
- No defensive branches, no speculative generality, no duplication found. Doc verbosity is house style, not structure.

Gates after pass (tree unchanged from impl's green full run): `cargo fmt --all --check` OK; all 8 named tests green scoped (0.50s). No test assertions, fixtures, or public API touched.

## VERDICT-FIX (Opus, 2026-08-07)

Verdict `FIX-REQUIRED`, one REAL P1, banked `none`. Fixed at the chokepoint; nothing relitigated.

### P1 `attribution-integrity` — raw batch puts of byte 86 forge attribution — FIXED

Confirmed live before the fix: `vault.batch().put(&id, ENTITY_TYPE_NOTE, ..., &forged).commit()` returned `Ok(())` and stored a NOTE whose `author_ref` named an actor that never wrote it, with no `AuthoredBy` and no link edge. `put_structural` refusing the kind closed the typed door only; `validate_public_raw_put` fell through `_ => {}` for NOTE, so registering byte 86 as a public Pack kind opened the raw door in the same commit.

Fix, mirroring the CLAIM precedent one function above it:
- `crates/oneiron/src/batch.rs` — `validate_public_raw_put` gains a NOTE arm returning `Error::InvalidNoteBody(ERR_RAW_NOTE_PUT_REQUIRES_AUTHOR_TAKE)`. The type is refused outright rather than body-validated: no raw put can be handed the bound actor, and none can be made to carry the mandatory same-transaction edges. This covers BOTH public builders — `BatchBuilder::put` and `TxnBatchBuilder::put` call the same gate.
- `crates/oneiron/src/batch.rs` — new `pub(crate) TxnBatchBuilder::put_authored_note(id, author, occurred, learned_at, data)`, the typed crate-internal door the verdict's fix-shape constraint requires (a bare reject arm would have broken `author_take`, which routes through `batch_in().put`). It earns the bypass instead of inheriting it: `validate_authored_note_body` decodes under the pinned NOTE ABI and requires `body.author_ref == author` — the actor `with_verified_actor_write_txn` has already checked against the store — so the ABI stays enforced on every NOTE write path and the door cannot be misused by a future caller either.
- `crates/oneiron/src/facade.rs` — `author_take` calls `put_authored_note(&note_id, &self.actor, ...)`; doc updated to state it is the only NOTE writer.

Mutation-verified, both halves:
- New test `facade::tests::raw_note_put_is_refused_at_the_batch_door` — RED before the fix (`raw batch NOTE put must be refused: ()` — the forged put committed), GREEN after. Covers `BatchBuilder::put`, `TxnBatchBuilder::put`, "no NOTE left behind", and the honest `author_take` path still stamping the bound actor.
- Author-binding half mutated independently (`if false && body.author_ref != *author`) → the typed-door assertion goes RED (`the typed door must refuse a body attributed to another actor`); restored → GREEN.

Not touched, deliberately: `put_replicated` / `replicated_put_op` still bypass this gate, unchanged from the existing sync-door posture documented at the TASK/streak arm ("the sync-only replicated door deliberately does NOT run this check"). That is peer-trust surface and a spine partition, not this finding; known hole 1 below narrows to it.

### PACKET_AMEND 5 — `crates/oneiron/src/batch.rs` (TAKEN; verdict-forced)
Supersedes PACKET_AMEND 4's "NOT TAKEN". The verdict adjudicated the raw door REAL P1 and named the fix shape; the amendment is now forced, and it is the CHEAPER of the two shapes for the seam:
- It lands in the BUILDER half of `batch.rs` — one const, one arm in `validate_public_raw_put`, one new `TxnBatchBuilder` method beside the lane-owned `put_habit_checkin`, one new validation fn beside the lane-owned `validate_habit_checkin_body`.
- It does NOT enter `apply_put` / preflight / `apply_vector`, which `CLAIMS.md:12` partitions to L1-STORAGE-SPINE, nor the `apply_put` regions ONE-1890 claims. PACKET_AMEND 4's recommended `apply_put` arm would have; this does not.
- Collision check: no other L1-ENTITY lane and no declared spine/1890 claim names `validate_public_raw_put` or the `TxnBatchBuilder` put family. Same-file merges still serialize by PR order per the standing `batch.rs` seam note.
- `crates/oneiron/src/batch/tests.rs` NOT touched — the new test lives in the lane-owned `facade/tests.rs`, which is where the attribution fixtures (`put_person`, `facade_for`, `note_body_of`) already are.

Gates: `cargo fmt --all` clean · `cargo clippy -p oneiron --all-features --all-targets` zero warnings · final `cargo test -p oneiron --all-features` exit 0, 52/52 binaries ok, 0 failed.

## Commits (nothing pushed)

Engine `ONE-1377`:
- `9557489` WIP: NOTE entity + author_take (impl half)
- `631542d` author_take tests, NOTE serialize profile test, fmt/clippy

Docs `ONE-1377`:
- `42c85f1f` canon NOTE typeByte 106 + byteMigrationV3 86 -> 106
