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

1. **Raw batch/sync puts of byte 86 bypass the NOTE body ABI.** `author_take` builds the body itself and `put_structural` refuses the kind, so every path this ticket opens is covered — but a replicated or direct `BatchOp::Put` with entity type 86 and a garbage body is accepted. Closed by PACKET_AMEND 4 above.
2. **Docs `generated/**` mirror not refreshed.** The docs commit hook warns that `site/src` changed without `bun run export:agent`. Per relay, the ONE-1732 lane runs the export; `site/node_modules` is not installed in this worktree and the relay states the docs half needs no export run. Handoff item for whoever publishes the docs branch.
3. **No server/MCP surface for `author_take`.** Engine verb only, per blueprint scope (`ONE-1936` layers the verb-on-stale guard).

## Commits (nothing pushed)

Engine `ONE-1377`:
- `9557489` WIP: NOTE entity + author_take (impl half)
- `631542d` author_take tests, NOTE serialize profile test, fmt/clippy

Docs `ONE-1377`:
- `42c85f1f` canon NOTE typeByte 106 + byteMigrationV3 86 -> 106
