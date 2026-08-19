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

## VERDICT-FIX (Opus, post-simplify)

Finder returned 1×P1 + 4×P2; verdict adjudicated **all five REAL**, banked none, → FIX-REQUIRED.
Every fix landed at its chokepoint and is mutation-verified (probe applied → named test RED →
probe reverted → GREEN). No finding was relitigated.

### F1 · P1 `consent-bypass` — the second door

`reservoir_candidates` was `pub` and re-exported at `lib.rs`, returning the entire corpus as owned
`String`s with no consent decision and no receipt. The doc defence ("this reads, it does not
disclose") was wrong: for a projection whose return value IS the content, the return is the
disclosure.

**Fix:** the public door is deleted, not gated. `resolve_candidates` is a private fn taking the
caller's snapshot; `export_reservoir` is the only `pub fn` in the module that yields a
`TrainingPair`. The `lib.rs` re-export is gone. Tests read candidates through the private fn —
a test helper is not a surface.

**Guard:** `the_export_door_is_the_only_public_surface_yielding_pairs` counts `pub fn` lines
mentioning `TrainingPair` (must be 0) and greps the old name — the landed
`napi_surface_never_constructs_auto_approval` pattern, because the defect is a `pub` keyword
rather than a behaviour.
**Mutation:** re-added `pub fn reservoir_candidates` → RED (`left: 1, right: 0`).

### F2 + F3 · P2 `candidate-eligibility` + `receipt-artifact-join` — one seam

Both findings were the same defect seen from two sides: the projection had no join to the
adjudication, and the key it did use (`artifact.entity_id().to_hex()`) is a key nothing in the
engine writes.

Ground-checked before fixing: `record_amendment_evidence` requires a Δ row under the SAME
`receipt_id` string; both in-crate Δ writers (`project_identity_amendment_deltas`,
`inbox`'s amend-accept) write only on an `approved_amended` outcome; both key on a NAMESPACED id
(`proposal_outcome:<hex>`, the gate-decision receipt id). The bare artifact hex is in nobody's
keyspace — production tags were all `None` and the tests only passed because they planted rows
under the bare hex themselves.

**Fix:**
- `AMENDMENT_RECEIPT_ID_PREFIX` + `pub fn amendment_receipt_id(EntityId) -> String` — the ED lane's
  spelling for a proposal-TEXT amendment, exported so the producer side and this reader share one
  function instead of a remembered convention. Namespaced for the reason every other family is:
  the Δ/evidence/fold ledgers are one flat string keyspace, and a bare entity hex collides.
- **Eligibility gate:** a differing-texts artifact is a candidate only if
  `amendment_recorded_in_txn` finds a row under that id. Differing texts alone say the body was
  EDITED — a rejected proposal was edited and discarded, one awaiting a ruling decided nothing —
  and only a recorded amendment says a decider kept what is in `final_text`. This is the same
  gate ED-03 applies before it will record evidence.
- **Tag joins** (`task_class`, `skill`) move to `amendment_evidence_in_txn` under that id.
- **Model join** rewritten. `export_models` scanned every receipt and keyed by
  `ReceiptRecord::receipt_id`, then looked up the ARTIFACT hex — structurally dead twice over
  (`context_receipt_fields()` returns `None` for every non-`Outbound` kind, and no receipt id is
  ever an artifact hex). It is deleted. The model now comes from ED-07's own run→generation
  binding (`folded_model_version_in_txn`), keyed by the same amendment receipt id as the other two
  ledgers: one key, three ledgers.
- `TrainingPair::receipt_ref` keeps its ratified `EntityId` type and now documents both ends of the
  join — the retention row lives under this id, the amendment ledgers under
  `amendment_receipt_id` of it.

**Guards:** `an_artifact_with_no_recorded_amendment_projects_no_pair` (same row, absent → present,
across the mark) · `the_ledger_join_key_is_the_namespaced_amendment_receipt_id` (a Δ planted under
the bare hex admits nothing) · `the_model_tag_is_the_generation_the_amendment_was_folded_under`
(fold under v1, swap serving to v2, pair still reads v1; an unfolded pair reads `None`) — the last
one is the honest model-tag test the verdict noted was missing.
**Mutations:** gate disabled → 2 RED · bare-hex key → 10 RED · model read from
`SERVING_MODEL_KEY` instead of the member row → RED (`left: stack:default-v2,
right: stack:default-v1`).

### F4 · P2 `consent-rail-integration` — the second ladder

`authorize_export` hand-scanned `active_standing_consent_grants` and called `GrantBound::contains`.
`gate.rs`'s own doctrine is explicit that a door opts in by composing a `ComposedEffect`, never by
re-implementing the ladder.

**Fix:** `export_effect()` composes the disclosure requirement with honest facts —
`external_observers: true`, `undo_fidelity: None`, no action requirement — and `authorize_export`
takes its verdict from `Vault::evaluate_consent_for`. Precedence, approve-once attestation and
spending, bound-exceeded reasons and live grant loading are now the rail's. The facts are
load-bearing: an irreversible PURE disclosure routes to the disclosure fail-safe (`Hide`), which is
what keeps an uncovered export fail-closed instead of being waved through by invariant 1.
`Error::ConsentGrantNotFound` is unchanged.

**Guards:** `the_export_door_rides_the_disclosure_consent_rail` now asserts the evaluator's own
verdict (`Hide` ungranted, `Auto` granted) alongside the door's behaviour ·
`the_export_never_re_implements_the_consent_ladder` forbids `active_standing_consent_grants`,
`evaluate_consent(`, `classify_composed_effect` in the module source and requires
`evaluate_consent_for`.
**Mutation:** hand-rolled scan restored → RED.

### F5 · P2 `torn-snapshot`

Artifact + fence reads shared one txn, `export_models` opened a later one, and every
`amendment_evidence` call opened its own — so one JSONL body could combine rows that never
coexisted while the receipt attested a point-in-time `content_hash`.

**Fix:** `resolve_candidates(vault, rtxn, scope)` takes the snapshot as an argument and every read
behind a body rides it — artifacts, `off_record_fence_active`, `amendment_recorded_in_txn`,
`amendment_evidence_in_txn`, `folded_model_version_in_txn`. `export_reservoir` opens exactly one;
`rebuild_reservoir_index` opens one covering BOTH the projection and the index it diffs for stale
rows (previously two). The consent decision stays ahead of the snapshot on purpose: the evaluator
spends approve-once markers, so it writes, and LMDB refuses a write txn on a thread holding a read
one.

**Guard:** `the_resolution_reads_every_ledger_on_one_snapshot` — holds a snapshot, lands a second
candidate and a fold from another thread (writer must be off-thread, same LMDB rule), asserts the
held snapshot's answer is byte-identical, then asserts a fresh snapshot sees all of it.
**Mutation:** evidence read swapped back to the own-txn `amendment_evidence` → RED
(`Storage(Mdb(BadRslot))` — the off-snapshot read is not merely wrong, it is unreachable).

### PACKET_AMEND — 3 additive read-only helpers in merged ED-lane files

The blueprint's packet is `reservoir.rs` + tests + `edit_distance.rs` + `lib.rs`. F5's
single-snapshot fix and F3's model join need transaction-composable readers that were
module-private. All three are read-only, additive, and in already-merged ED lanes (ED-01 #618,
ED-03 #618, ED-07 #622) — no live-lane collision. Same shape as the `FIELD_MODEL` visibility lift
the blueprint itself sanctioned.

- `edit_distance/attribution.rs` — `amendment_evidence_in_txn` `fn` → `pub(crate) fn` (+doc). One
  word.
- `edit_distance/delta.rs` — new `pub(crate) fn amendment_recorded_in_txn`, the named predicate
  behind the eligibility gate (both row shapes answer `true`: measured Δ and uncaptured marker
  differ on whether the MEASUREMENT succeeded, not on whether the amendment happened).
- `edit_distance/routing.rs` — new `pub(crate) fn folded_model_version_in_txn`, the run→generation
  binding read back on the caller's snapshot.

No behaviour in those files changed; no existing signature changed. `receipt.rs` stayed
consume-only (the model join no longer touches it at all), `settings.rs` untouched,
`Cargo.toml`/`Cargo.lock` untouched.

### BANK-3 (`resolve_with_routing_hint` live consumer)

Not in scope here and not improvised. This lane consumes ED-07 through
`folded_model_version_in_txn` — the historical binding a training pair needs — whereas
`resolve_with_routing_hint` answers "which model should serve NEXT", which is a serving-path
question a corpus projection must not ask. Wiring it here would put the model serving now onto a
pair it never produced, which is exactly what F3's fix removed. Left for a serving-path lane.

### Gates

`cargo fmt --all -- --check` clean · `cargo clippy -p oneiron --all-features --all-targets --
-D warnings` exit 0 · `cargo test -p oneiron --all-features` green. Diff ⊆ packet + the 3 amended
helpers + tests.

**Flake guard:** one full-suite run showed `embed::tests::partial_remote_completion_is_logged_when_local_batch_fails`
red. Quarantined, charged to no lane: the test asserts over a `tracing::subscriber::with_default`
capture, which is THREAD-LOCAL, so an event emitted off-thread lands on the global subscriber and
the capture reads empty. Nondeterministic in both directions — it passed on this tree 3/3 under the
`embed::` filter and passed on the re-run full suite (3901 lib passed, 0 failed). No edit_distance
surface touches `embed`.
