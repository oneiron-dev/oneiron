# WORKLOG — ONE-1765 [ED-09] SFT/DPO reservoir export projection

Branch `ONE-1765` off `origin/main` @ `a4dfcdf5e` (1763 #622 merged — ED-C L1 landed).
Worktree `/Volumes/Cinema/w5-lt/ed-1761`. Blueprint `/Users/olety/.claude-wave5/blueprints/ED/ONE-1765.md`.

## Gates

| gate | result |
|---|---|
| `cargo fmt --all` | clean |
| `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` | exit 0 |
| `cargo test -p oneiron --all-features` | 3895 lib + 48 binaries, **0 failed**, 17 pre-existing ignored |
| reservoir unit tests | 14 passed |

## Files (PACKET)

| file | change |
|---|---|
| `crates/oneiron/src/edit_distance/reservoir.rs` | **new**, 702 lines |
| `crates/oneiron/src/edit_distance/reservoir/tests.rs` | **new**, 625 lines |
| `crates/oneiron/src/edit_distance.rs` | +1 (`pub mod reservoir;`) |
| `crates/oneiron/src/lib.rs` | +6 (re-exports) |
| `crates/oneiron/src/receipt.rs` | +7 (**declared amendment — see D1**) |

`settings.rs` NEVER touched. `Cargo.toml` / `Cargo.lock` NEVER committed (`Cargo.lock` is dirty in
the worktree from pre-existing setup, deliberately left unstaged).

## The hard line: off-record

- **Exclusion is at the enumeration SOURCE, and it is CONSTRUCTIVE.** ONE-1570: a fenced turn is
  pipeline-inert, so no derived row exists and there is nothing to filter. There is no filter in
  this module to disable and no flag to flip. Proven by
  `a_fenced_session_contributes_no_candidates_at_all`.
- **Tripwire** (`resolve_candidates`): every artifact the scan enumerates has its persisted
  `source_turn_ref` probed against `off_record_fence_active` — the same durable per-entity probe the
  retrieval filter consults, never phrased against `OffRecordSessionRecord` (in-process, evaporates
  at close). A hit ABORTS the export with a typed error. **Loud, never a silent skip.**
  The probe runs BEFORE the pair filter and the scope filter, deliberately: a filter that ran first
  could hide an inertness bug behind a narrow scope.
- `source_turn_ref = None` passes (`a_pair_with_no_source_turn_passes_the_tripwire`); an unfenced
  turn exports normally (`an_unfenced_source_turn_exports_normally`).
- **Zero bytes on abort** — two-phase contract, asserted with a byte-counting sink
  (`a_fenced_source_turn_aborts_the_export_before_the_first_byte`).
- **No override API** — `no_override_api_on_the_export_surface` uses two guards: exhaustive
  destructuring of `ReservoirScope` + `TrainingPair` (a new admit-fenced field is a compile error at
  that line), plus a source grep for override-shaped identifiers, per the landed
  `napi_surface_never_constructs_auto_approval` pattern.
- `rebuild_reservoir_index` shares the ONE enumeration path, so it inherits the tripwire
  (`the_index_rebuild_shares_the_export_tripwire`).

## Deviations & PACKET_AMEND candidates — every one declared, none absorbed

### D1 — PACKET_AMEND (needs ruling): `receipt.rs` +7 lines, dispatcher wire

Relay PACKET said "receipt.rs/provenance.rs **consume only**". Blueprint Claims say
"`receipt.rs` — export receipt field consts (additive)"; `ED/CLAIMS.md` shared-file table lists
`receipt.rs | 1757, 1762, **1765** | field-key consts only`. I took **less than the consts** but
**more than consume-only**: a 4-line projector call inside the existing `ScopedRead` block of
`receipt::receipts` (+3 lines of comment).

- Precedent is in-lane and landed: ONE-1762's escalation projector is wired the identical way at
  `receipt.rs:2208`, from `edit_distance/escalation.rs`.
- Without it the export receipt is unreachable through `vault.receipts()` and done-means #4
  ("export receipt records scope+count") cannot be satisfied.
- **Zero field consts were added to `receipt.rs`** — `FIELD_EXPORT_*` live in `reservoir.rs`, the
  house per-feature-module pattern. So the blueprint's own receipt.rs claim went partly UNUSED.
- No refactor, no reordering, no existing line changed.

### D2 — Blueprint claim NOT taken: `FIELD_MODEL` visibility lift

Blueprint: "visibility lift: `FIELD_MODEL` is private today (receipt.rs:89) → `pub(crate)` (one
word, no logic)". **Not needed and not taken.** `ReceiptRecord::context_receipt_fields()`
(`receipt.rs:873`) is already a public accessor exposing `.model`. Zero-touch beats a lift.

### D3 — PACKET narrowing: `off_record/lifecycle.rs` NOT touched at all

PACKET allowed an additive query helper for `off_record_fence_active`. Not needed: it is already
`pub(crate) use`-exported at `crate::off_record::off_record_fence_active`
(`crates/oneiron/src/off_record/mod.rs:12`). Zero touch to the off_record tree.

### D4 — PACKET narrowing: `proposal_text.rs` NOT touched, and not imported

`edit_distance/proposal_text.rs` is `#[cfg(feature = "sync")]`. The reservoir must compile in every
build (napi/ffi/driver have no sync), so it reads the **unconditional** retention rows in
`edit_distance.rs` instead — which is what that module's own doc says the ladder must do
("Everything in this module root is UNCONDITIONAL ... because the downstream ED ladder (…,
reservoir) must compile in every build").

Mechanism: `reservoir` is a CHILD of `edit_distance`, so it reads the parent's private
`PROPOSAL_ARTIFACT_KEY_PREFIX` and `decode_finalized_proposal_text` directly via `super::`. That is
why `edit_distance.rs` needed only the one `pub mod` line.

### D5 — Typed error: `Error::InvariantViolation`, not a new variant

Blueprint: "aborts the export with a typed error". Used
`Error::InvariantViolation("reservoir candidate is sourced from an off-record fenced turn; fenced
turns are pipeline-inert and must produce no derived rows")`.

- **Considered and rejected `Error::OffRecordExportRefused { session_ref }`** (error.rs:1502): its
  semantics are "a whole-vault export refused while a session is OPEN", and it *requires* a
  `session_ref` — exactly the in-process-only handle the blueprint forbids the check from being
  phrased against.
- **Considered and rejected a new `error.rs` variant**: out of packet, and `InvariantViolation` is
  the house variant for "this means an upstream bug" throughout `edit_distance.rs`.
- **Bankable**: if the panel wants a dedicated `Error::ReservoirFencedCandidate`, it is a
  three-line error.rs addition plus one test-matcher change.

### D6 — Consent rail: audience/class/envelope are PINNED consts, not parameters

The ratified skeleton is `export_reservoir(vault, scope, out)` — no audience argument, so the door
**cannot** take one. Pinned `RESERVOIR_EXPORT_AUDIENCE` / `RESERVOIR_DISCLOSURE_CLASS` /
`RESERVOIR_ENVELOPE_SELECTOR`; the owner mints a standing disclosure grant naming them. A caller
therefore cannot widen the room by naming a different audience.

Not a re-implementation: `authorize_export` builds a `GrantBound::disclosure` and asks
`Vault::active_standing_consent_grants` + `GrantBound::contains` — the same rail
`edit_settle::authorize_settle` (`edit_settle.rs:549`) uses. Only ACTIVE rows are returned, so
revocation is immediate; both directions asserted in
`the_export_door_rides_the_disclosure_consent_rail`.

### D7 — One public door beyond the skeleton: `reservoir_candidates(vault, scope)`

`resolve_candidates` is the shared path behind both ratified doors; exposing the read is one line
and lets a caller see what an export WOULD carry without producing an artifact or spending consent.
Declared, not absorbed. **Bankable for deletion** if the panel prefers the skeleton verbatim.

### D8 — `serialize_with` hex attributes on `TrainingPair`

`EntityId` is not `Serialize`. Field TYPES are verbatim per the ratified skeleton
(`skill: Option<EntityId>`, `receipt_ref: EntityId`); only the wire encoding is specified — lower
hex, the spelling every other receipt field in this engine uses. `None` rides the wire as `null`.

### D9 — SEAM NOTE for ED-01/ED-02: the artifact↔tag join key

Nothing durably links a `FinalizedProposalText` to a receipt today. The tag join is
`amendment_evidence(vault, &artifact_ref.entity_id().to_hex())` — the artifact ref hex is the **only
durable id ED-00 mints**, so it is the id an ED-00-sourced amendment's evidence must be recorded
under. A miss is not a failure: it yields all-`None` tags, which is the blueprint's Notes contract
(absence explicit, never guessed).

**Failure direction if a producer picks a different receipt id: tags go silently ABSENT, never
wrong.** Worth a one-line confirmation at the deviation board that ED-01/ED-02 record evidence under
the artifact hex.

### D10 — `model_id` resolution

From `ReceiptRecord::context_receipt_fields().model` via ONE bounded receipt query built into a
`receipt_id → model` map (a map build, not a per-candidate fan-out). Deliberately NOT
`routing::serving_model_version` — that is the model serving NOW, and using it would be a guess
about history, which the Notes contract forbids.

### D11 — BANK-3 from 1763: `resolve_with_routing_hint` live consumer — NOT wired, per relay

Relay: "wire a live consumer of `resolve_with_routing_hint` where natural — if not in scope here,
worklog-note it, do not improvise."

**Confirmed still open**: `crates/oneiron/src/llm.rs:610` is the sole definition; zero non-test
callers. **Not natural in this lane** — the reservoir is an export projection and resolves no model
for drafting, so there is no call site here. Wiring one would be improvisation.

**Recommendation**: it belongs in the lane owning the drafting call site — `ED/CLAIMS.md` already
reserves the row `llm.rs OR engine_executor.rs | 1763 | ONE hint-read call site, Shadow default`.
Carry BANK-3 forward to whichever lane touches that seam.

## Two real bugs found in the gate loop (both named classes)

1. **Nested read transaction → LMDB `BadRslot`** (12 tests red). My projector opened its own rtxn
   while `receipt::receipts` already held the shared one. Fixed by taking `&heed::RoTxn` — the exact
   hazard `receipt.rs:2200-2222` documents for the ramp/escalation projectors.
2. **`seed-band-violation`** — `test_util::entity(0x42)`; `0x42` is in `PINNED_ID_BYTES`. Caught by
   the landed band assert (`lib.rs:1076`), moved to `0x52`. The chokepoint helper did its job.

## Done-means

- [x] Amended fixture → `rejected=proposed` / `chosen=final`; untouched/rejected → NO pairs
- [x] Off-record: constructive absence + injected fenced `source_turn_ref` → typed abort, **0 bytes**
      (byte-counting writer)
- [x] No override API: compile-surface review test (exhaustive destructure + source grep)
- [x] JSONL round-trips; hash stable; receipt records scope+count+hash; re-export same scope → same
      hash; filter order/duplicates normalize, a narrower scope does not
- [x] Consent rail via the rail's own door (grant → export succeeds; revoke → immediate refusal)
- [x] Rebuild-index identity + stale-row deletion
- [x] fmt · clippy -D warnings · full `-p oneiron --all-features`

## SIMPLIFY pass (K3, post-impl)

Deletion-biased, one bounded pass over `reservoir.rs` (+9/−11). Public API, tests, the tripwire
and the consent rail untouched.

1. **`receipt_model` helper inlined** into `export_models` — a one-line `Option` chain used at one
   call site does not earn a named fn (`context_receipt_fields().and_then(|f| f.model)`).
2. **`serialize_opt_entity_hex` collapsed** from a 5-line `match` to
   `id.as_ref().map(EntityId::to_hex).serialize(serializer)` — `Option<String>` already serializes
   as `some(string)`/`none(null)`, identical wire shape.
3. **Unused `Clone` derives dropped** from `StoredExport` / `StoredCandidate` — neither row is ever
   cloned; speculative generality.

Considered and left alone: the pinned-const table (house style, single-source-of-string), the
`reservoir_candidates` read door (public API; D7 already flags it for the panel), the write-only
candidate index (blueprint-mandated CID-7 derived state), module docs (ratified craft voice).

Gates after the pass: `cargo fmt --all` clean · `cargo clippy -p oneiron --all-features
--all-targets -- -D warnings` exit 0 · `cargo test -p oneiron --all-features` 3895 lib passed,
0 failed, 17 pre-existing ignored.
