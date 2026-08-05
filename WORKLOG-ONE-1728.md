# ONE-1728 — P4a cutover (witness + retrieval through the session vault)

Lane `L1-STORAGE-SPINE` · branch `ONE-1728` · worktree `/Volumes/Cinema/w5-lt/l1-spine`
Blueprint: `/Users/olety/.claude-wave5/blueprints/L1-STORAGE-SPINE/ONE-1728.md` (re-cut 2026-08-05 under SPINE-ROOT reground)

## Segment map (relay)

**SEG 0 (this segment)** — the keystone spine skeleton every later sub-step and every
downstream ticket (1729/1730/1731/1732) copies from:

1. `error.rs` — two append-only typed variants (`OffRecordTaintedBaseWrite`,
   `OffRecordWitnessDoorRejected`) + `ErrorKind` arms.
2. `write_envelope.rs` — additive `ClaimCandidate::world()` accessor.
3. `session_overlay.rs` — K2/K3/K10: `JournalRole`, role-tagged `JournalEntry`
   (`learned_at` + `occurred` preserved), `stage_journal_entry`,
   `OverlaySnapshot::journal_entries`, `SessionOverlay::rearm` (Sealed→Live),
   mode-generation publication, `RouteTarget` + `SessionWriteRoute` +
   `revalidate`/`target`.
4. `off_record/promote.rs` — K1: `FloorWrites` definition MOVES here from
   lifecycle.rs; `commit_promote` stays as operation 3/3 marked for ONE-1730.
5. `off_record/mod.rs` — re-export `FloorWrites` (from promote), `OverlaySnapshot`
   + `SessionWriteRoute` (from session_overlay).
6. `off_record/lifecycle.rs` — K8 receipt-verb deletion; K10 flip-back rearm arm
   replacing the landed `OnRecord→*` `InvariantViolation`; arm `read_view()` /
   `overlay()` for production; add `write_route()`.

**SEG 1+** — `alloc_session_short_id` + session short-id namespace · batch.rs K4
(`BaseWriteOrigin`, `apply_ops_with_origin`, decode-point guard, `apply_ops_session`) ·
store.rs extract-parameterized writers + `impl SessionStoreView` · bm25/ppr/hnsw
parameterization · facade `witness_into_session` + K7 backstop · pipeline
`run_for_pack` registration routing · gate.rs threading · embed.rs pe: rule ·
claim.rs ScopedRead composition · context_pack.rs · oracle arming (7 stubs + seam
helpers) · tests.

**SEG 1 (done: 719b1db, 4e07b4e)** — batch.rs K4 (`BaseWriteOrigin` +
`PromoteMemberOf` + in-txn decode-point guard, `apply_ops_with_gate_mode` demoted
to the Ordinary wrapper over `apply_ops_with_origin`) · facade K7 witness-door
backstop + `owning_session_ref` + `FACADE_CODE_OFF_RECORD_SESSION_DOOR` ·
embed.rs K6 pe: routing rule. 8 new tests; full suite green (3157/0).

**SEG 2 (done: b8ab60e + this commit)** — the K11 write-target seam
(`ManifestDbs`) · bm25 `index_text`/`deindex_text` + hnsw insert/deindex
parameterized · batch.rs short-id family parameterized ·
`SessionOverlay::alloc_session_short_id` + the session short-id namespace.
4 new tests; see D9–D11.

**SEG 3 (done: 1deec97 + this commit)** — `apply_ops_session` (the executable
session seam) · the four extract-parameterized staging helpers
(`stage_entity_body_row`, `stage_entity_index_rows`, `stage_edge_rows`,
`stage_vector_row`) + `apply_phonetic`/`ensure_model_id_for_vector_write`
generalized · K5 `append_gate_decision_row_in_txn` · facade
`witness_into_session` + the room/continuation shell pair · `JournalScope`
accessors. 6 new tests; see D12–D15.

**SEG 4+ (remaining)** — pipeline `run_for_pack` registration routing ·
store.rs session-side retrieval-run/finalize/delete variants +
`OffRecordSession::vault_meta_put`/`vault_meta_get` · ppr reader
generalization · `SessionVault::search_text` · claim.rs ScopedRead ·
context_pack.rs · K8 receipt-verb deletion + the pre-close census ·
oracle arming (7 stubs + seam helpers).

## Decisions

- **D5 — K4 does NOT judge a Put/ClaimCandidate's own materialized id
  (door partition).** Found by a red test (`entity_put_guard_rejects_live_overlay_membership`),
  not by inspection. That id already reaches `guard_off_record_entity_put` inside
  `apply_put` — the landed entity-materialization chokepoint — which rejects the
  identical condition (live-overlay membership) with the settled
  `OffRecordFencedTurnWriteRejected`, and additionally covers durable fence state
  K4 knows nothing about, so it is strictly stronger on that ref. Minting a second
  error identity for one condition is a REGRESSION, not a hardening:
  `sync/window.rs:1478` and `sync/quarantine.rs` classify on that typed identity to
  quarantine-and-continue a replicated window, and an unrecognized reason there
  fails the window closed. K4 therefore owns exactly the refs that materialize
  nothing and so structurally cannot reach the entity door: edge endpoints, claim
  body subject/world, candidate world/subject/actor, hint source/keep, and the
  vector/text/phonetic/delete ids. Blueprint fidelity is preserved — the guard's
  enumeration still covers every listed ref; only the id that has a stronger
  landed judge is delegated rather than double-judged.
- **D6 — undecodable CLAIM bodies fail closed WITH a live-membership
  precondition.** The guard returns early when the registry holds zero live
  overlay entities, so an undecodable body then reaches `apply_put`'s precise
  `InvalidClaimBody` verdict instead of being relabelled taint. This is not a
  weakening: with zero overlay entities there is no id the body could reference,
  so "fail closed" and "fall through" reject identically and the more precise
  error survives. It also keeps the canonical path from decoding every claim body
  twice.
- **D7 — K6 is a `debug_assert!` tripwire, not a filter.** The blueprint says
  "routing, not filtering"; a production filter on `enqueue_pending_embedding_jobs`
  would silently absorb a routing bug rather than surface it. The assert names the
  invariant and dies loudly in dev; production correctness rests on the session
  path never calling the verb.
- **D8 — K7 gets its own facade code, not `FORBIDDEN`.** `FORBIDDEN` is the gate
  family ("your write was refused; change actor/scope/consent"). A witness-door
  refusal is categorically different — nothing was judged, the room is simply not
  reachable through this door — so a client that retries with different credentials
  is chasing the wrong remedy. `FACADE_CODE_OFF_RECORD_SESSION_DOOR` says "use the
  session handle".

- **D1 — stale-route refusal reuses `OffRecordOverlayLeaseClosed`.** The blueprint
  pins error.rs at exactly TWO new variants and describes the stale-route refusal as
  "the typed stale-route refusal family (`OffRecordOverlayLeaseClosed`-style typed
  error)". Adding a third variant would break the pinned two-variant claim, so
  `SessionWriteRoute::revalidate` refuses with `Error::OffRecordOverlayLeaseClosed
  { generation: <the route's recorded mode generation> }`. Variant-level
  discrimination survives; the recorded generation names the stale route.
- **D2 — mode generation lives on `SessionOverlay`.** K10 says `revalidate` is
  implemented in `session_overlay.rs` "against freshly published state under the
  state lock internal to this module (no field access crosses the module
  boundary)". The only state lock internal to that module is the overlay's
  `lifecycle` mutex, so the published `mode_generation` is an overlay-owned counter
  bumped under that lock by `seal_writes` (Live→Sealed) and `rearm` (Sealed→Live).
  `SessionWriteRoute` therefore carries `Arc<SessionOverlay>` + target + the
  generation recorded at mint. No session-entry type appears in the signature, and
  batch.rs never reads a field.
  Minting is atomic against a concurrent flip because `OffRecordSession::write_route`
  reads the record mode under `entry.state` — the same lock
  `set_off_record_session_mode` holds across `seal_writes`/`rearm` + republication.
- **D3 — one journal staging surface.** `stage_journal(scope, op)` is REPLACED by
  `stage_journal_entry(entry: JournalEntry)` rather than kept alongside it
  (deletion-bias; two staging surfaces would let an untagged op in). The four
  existing callers (2 in `branch_store_oracle::seam`, 2 in `session_overlay` tests)
  are updated to build a `JournalEntry`.

- **D4 — `off_record_orphaned_context_receipt_is_swept_on_reopen` is DELETED, not
  rewritten.** That test's entire subject was the K8 machinery this ticket removes:
  it called `note_off_record_context_receipt` (deleted verb) and asserted that
  `Vault::open`'s `sweep_orphaned_off_record_receipts` leg (deleted sweep) evaporated
  a crash-orphaned DURABLE retrieval-run row. Under P4a a session's retrieval-run
  receipts never reach a durable row at all — they are written into the session's own
  overlay `VaultMeta` keyspace — so there is no orphan to sweep and nothing left to
  assert. The crash contract it guarded does not disappear: it migrates to the
  `crash_evaporation_leaves_zero_base_residue` oracle stub (:984) this ticket arms,
  which proves the stronger property (zero base residue at all, not "the sweep
  cleaned up the residue afterwards"). Deleting the verb without deleting this test
  is what the blueprint means by "deleting the assertion and call together where the
  deleted verb is the test's subject".

## Cheap gate — seg 0

- `cargo check -p oneiron --all-targets --all-features` clean; `cargo fmt --check`
  clean; `cargo clippy --all-features --all-targets` clean (no errors, no unused).
- `cargo test -p oneiron --all-features`: **3148 passed / 1 failed**, and the failure
  ROTATES between runs across three different tests in files this diff never
  touches — `embed::tests::partial_remote_completion_is_logged_when_local_batch_fails`,
  `batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`,
  `attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`.
  Each passes in isolation (`--lib <name>`).
- **BASE-RED, charged to no lane (flake guard applied).** Stashed the whole diff and
  ran the suite twice on clean base `e9d9e9a`: run 1 green, run 2 FAILED on the
  attempt_queue test. So the class pre-exists this lane. All three failures are
  `tracing` subscriber-capture tests (`with_default` / span-record capture) that lose
  records under full-suite parallel load — a global-subscriber race, not a storage
  defect. Not this lane's to fix; flagged for the wave so a verify leg does not
  mis-attribute it. Everything this segment touches is green.

## Cheap gate — seg 1

`cargo fmt --check` clean; `cargo clippy --all-targets --all-features` clean;
`cargo clippy --all-targets --features sync` clean (K6's assert is sync-gated);
`cargo test -p oneiron --all-features`: **3157 passed / 0 failed**. The seg-0
rotating tracing-subscriber flake did not recur this run — it remains a
pre-existing parallel-load class charged to no lane (see seg-0 note above).

## Cheap gate — seg 2

`cargo fmt` clean; `cargo clippy --all-targets --all-features` clean;
`cargo clippy --all-targets --features sync` clean. Warning inventory is
**identical to the pre-seg-2 baseline** (14 lib warnings, all pre-existing
`dead_code` on seg-0/seg-1 surfaces awaiting their consuming step) — verified by
stashing the diff and diffing the warning list, so this segment adds no lint
debt. `bm25::` 61/61 and `hnsw::` 37/37 green (the byte-identical-base gate for
the parameterization); `session_overlay::` 17/17 green.

`cargo test -p oneiron --all-features`: **3159 passed / 0 failed** (plus all
integration targets green). The first run of this gate hit
`attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`
— ONE of the three tracing-subscriber tests named in the seg-0 BASE-RED note.
Flake guard applied: it passes in isolation, this segment's code diff has ZERO
hits for `attempt_queue`/`tracing`/`subscriber` (the only grep hit in the whole
diff is this worklog's own prose), and the re-run is fully green. Pre-existing
parallel-load class, charged to no lane — unchanged from seg 0.

## Seg-2 decisions

- **D9 — the write target is an ACCESSOR BUNDLE, not a branch, and the trait is
  macro-generated from one list.** The blueprint calls for
  "extract-parameterized writers … byte-identical base behavior … never
  copy-paste of private formats". The landed substrate already made that nearly
  free: `Store` and `SessionStoreView` carry the SAME 28 accessor names with the
  same types (`OverlayDb`/`OverlayStrDb`), and `OverlayDb` already decides
  base-vs-overlay INTERNALLY. So the parameter is just "which bundle of
  accessors", and no writer needs a target branch at all — `store.rs`'s
  `manifest_dbs!` macro emits `trait ManifestDbs` plus both impls from ONE list
  of the manifest databases. Byte-identical base behavior is then not a claim to
  be tested but a consequence: it is literally the same function body reaching
  the same accessors. A database renamed in either struct and not in the trait
  list fails to compile, so the seam cannot drift the way a hand-written
  28-method trait would. Measured surface: bm25 and hnsw touch ONLY accessors on
  `store` (verified by grep — zero `Store::` associated calls, zero non-DB field
  reads), which is why they parameterize cleanly; batch.rs does NOT (it calls
  `store.mark_pending_embedding`, `validate_entity_type`, `short_id_prefix`, …),
  which is why its op loop needs the seg-3 treatment rather than a signature
  swap.
- **D10 — the hnsw legacy-rebuild arm stays base-only BY SIGNATURE, not by
  convention.** The blueprint requires the overlay target to "never schedule or
  run a base graph rebuild". Rather than guard that at runtime,
  `hnsw_insert`/`hnsw_insert_probed`/`run_pending_legacy_rebuild`/
  `rebuild_hnsw_from_current_snapshot` keep `store: &Store` while the
  insert/deindex core takes `&impl ManifestDbs`. A session target therefore
  cannot reach the rebuild path — it does not typecheck. This is the cheapest
  possible enforcement of that law and needs no test to stay true.
- **D11 — session short ids are minted OUTSIDE the base grammar (`s<n>`), not as
  a parallel counter inside it.** The blueprint says the namespace is
  session-scoped and that in-room ids are "temporary presentation aliases". The
  hazard it does not name: base aliases are `<two lowercase letters><digits>`,
  and BOTH short-ref parsers (`api/core.rs::parse_short_ref_parts`,
  `mcp.rs::validate_short_ref_parts`) accept exactly that shape. A session alias
  minted in the same space (e.g. `tu1`) would be indistinguishable from a
  durable one and — because session reads compose overlay ∪ base — would MASK a
  real base entity's alias for the life of the room. The `s` sigil is not a legal
  base prefix (base prefixes are always two letters), so a room alias cannot
  collide with or shadow a durable one, and a session alias that leaks to a base
  door gets a clean parse rejection instead of a silent hit on the wrong entity.
  A dedicated test asserts the alias never parses as a base short id. The
  content-hash byte still uses the base scheme (`xxh32(data,0) % 256`) so
  `hydrate_short_id`'s pairing behaves identically in-session. The room counter
  is the live reverse-row count read from the same snapshot the allocation
  stages into (reverse rows are one-per-entity and are never deleted mid-room),
  so a second allocation in the same segment cannot reuse an ordinal. Base
  `sid_counter:` rows and base short-id tables are neither read nor written.

## Seg-3 decisions

- **D12 — `apply_ops_session` is a SIBLING of the base apply, not a target flag
  on it.** The blueprint says the Overlay session path "never enters the base
  apply". The tempting reading is "thread the target through
  `apply_ops_with_origin` and branch"; I rejected it. That body is base-shaped
  in four independent places a room has no answer for — it publishes gate
  decisions to the durable ledger, enqueues `pe:` embed jobs, runs the
  identity-topology fold across the whole ledger, and schedules legacy HNSW
  rebuilds off the base `vectors` DB. Threading a target puts a live
  `if session { skip }` in front of each: four chances for a later edit to leak
  a room into base, each individually reasonable-looking. The sibling has NO
  `&Store` in scope, so there is no base row it *could* write — the isolation
  is a type fact, not a reviewed invariant. What the two share is exactly what
  must not drift: the row STAGING, through the same `ManifestDbs` accessors.
  That is why promote can be a replay of bytes rather than a re-derivation.
- **D13 — the session apply takes `JournalEntry` values, not `BatchOp`s.** The
  blueprint requires every staged op to carry its role tag and preserved
  timestamps, and forbids inferring roles from index keys. A `Vec<BatchOp>`
  parameter plus a "remember to journal each one" rule would make that a
  discipline; taking `Vec<JournalEntry>` makes staging-a-row and
  journaling-it one act that cannot be half-performed. The entry's own
  `occurred`/`learned_at` — not the op's — feed the row and the edge
  `created_at`, so a promoted turn lands in the month window it happened in
  (ARCH-0052 D4) rather than the one it was promoted in.
- **D14 — the on-record continuation shell is a SECOND shell, and the two are
  structurally separate.** K10 says post-flip witness runs "under the session's
  on-record continuation shell … carrying zero references to overlay ids". The
  cheap implementation reuses the room's conversation id for both modes. That
  would write a BASE row whose conversation is a live overlay member — exactly
  the taint K4 exists to reject — and would make the private room reachable
  from base by following the edge, defeating "pre-flip turns remain
  base-invisible". So the registry record holds `overlay_shell` and
  `continuation_shell` as distinct in-memory fields, and
  `on_record_continuation_shell()` refuses while off record. Both live only in
  memory (no durable session row), so they evaporate with the room.
  `overlay_shell_staged` is separate from `overlay_shell` because allocating
  the id and staging its `Put` happen at different moments — the id is minted
  before the write txn opens — so a second witness must reuse the shell rather
  than re-put it.
- **D15 — session puts keep the public entity-type gate.** A room is not a
  place where unknown or engine-authored type bytes become writable: promote
  replays these rows into base through the ordinary doors, so a byte that would
  be rejected there must be rejected at witness time, not discovered at promote
  when the user has already consented. The base ENTITY DOOR
  (`guard_off_record_entity_put`) is deliberately NOT run — it rejects
  live-overlay membership and would refuse the room's own writes — but that is
  a door about WHERE a write lands, not about what a type byte means.

## Cheap gate — seg 3

`cargo fmt --check` clean; `cargo clippy --all-targets --all-features` clean.
Two warnings remain, both pre-existing seg-0/seg-2 surfaces awaiting their
seg-4 consumers (`RetrievalRunId::from_bytes`, the six unconsumed `ManifestDbs`
accessors) — the seg-2 inventory is otherwise unchanged, so this segment adds no
lint debt. `cargo clippy --all-targets --features sync` clean.
`cargo test -p oneiron --all-features --lib`: **3165 passed / 0 failed**
(3159 at seg-2 + the 6 new tests); the full suite incl. integration targets was
green at 1deec97. No flake recurrence this segment.

**Mutation-checked, not just green.** Two deliberate defects were injected and
the suite re-run: (a) post-flip witness reusing the OVERLAY shell instead of the
continuation shell → `post_flip_session_witness_lands_in_base_under_a_fresh_shell`
FAILS, as it must; (b) deleting the `route.revalidate()?` call from
`apply_ops_session` → every facade test still PASSED. That second result is why
`session_apply_refuses_a_route_minted_before_a_mode_flip` exists in
`batch/tests.rs`: `SessionWriteRoute::revalidate` being correct in isolation is
not evidence that the apply entry CALLS it, and the facade tests never mint a
route across a flip. A guard with no test that fails when it is deleted is not
a guarded invariant.

## Next-step INTENT

Seg 1 landed the three surfaces that had no dependency on the session apply
entry: K4 (batch.rs), K7 (facade door), K6 (embed rule). Seg 2 landed the
write-target seam they all route through, plus the short-id namespace.

**Seg 3 opens at `apply_ops_session`.** The seam is now in place, so the
remaining work is threading it, not inventing it:

1. `apply_ops_session(view, route, ...)` + op-loop write-target parameterization.
   Unlike bm25/hnsw, batch.rs's op loop also calls `impl Store` METHODS
   (`mark_pending_embedding`, `clear_pending_embedding`,
   `has_current_pending_embedding_in_txn`, `validate_entity_type`,
   `validate_public_entity_type`, `short_id_prefix`) and `store.off_record_sessions`
   / `store.env` — none of which live on `ManifestDbs`. Those are the real seam
   decisions for seg 3; the pure-accessor helpers (short-id family, already done)
   parameterize by signature alone. `route.revalidate()` runs before staging;
   batch.rs never reads a route field. The op-loop `mark_pending_embedding` call
   SKIPS for the overlay target (K6: skip, not redirect).
2. Then store.rs session-side writer variants + `impl SessionStoreView` composed
   read accessors, and only then facade `witness_into_session` (which needs 1+2)
   and the oracle arming (which needs all of it).

Retained watch item (unchanged from seg 2): the door-partition question D5
settled for K4 recurs for `apply_ops_session` — the session path must NOT re-run
`guard_off_record_entity_put`, which rejects live-overlay membership and would
refuse the session's own witness writes. The session path never enters the base
apply, so this is a structural consequence of that separation, not an extra guard.

Superseded seg-2 entry plan (kept for provenance):

1. `SessionOverlay::alloc_session_short_id` + the session short-id namespace
   (overlay `ShortIds`/`ShortIdsReverse` only; base `sid_counter:` untouched).
   `plan_short_id_update`/`apply_short_id_plan` (batch.rs ~4507/~4580) are the
   base shape to mirror — content hash is `xxh32(data, 0) % 256`.
2. `apply_ops_session(view, route, ...)` + op-loop write-target parameterization.
   The op loop touches 16 of the 28 accessors (`store.entities` ×15,
   `store.edges_out` ×11, `edges_in` ×9, `phonetic_index` ×7 … full census in the
   seg-2 notes); each becomes target-parameterized against `SessionStoreView`.
   `route.revalidate()` runs before staging; batch.rs never reads a route field.
   The op-loop `mark_pending_embedding` call (batch.rs, CLAIM arm) SKIPS for the
   overlay target (K6: skip, not redirect — no overlay `pe:` keyspace exists).
3. Then store.rs extract-parameterized writers, and only then facade
   `witness_into_session` (which needs 1+2) and the oracle arming (which needs 3).

Watch item for seg 2: the same door-partition question D5 settled for K4 will
recur for `apply_ops_session` — the session path must NOT re-run
`guard_off_record_entity_put`, which rejects live-overlay membership and would
refuse the session's own witness writes. The session path never enters the base
apply, so this is a structural consequence of that separation, not an extra guard.

Seg-0 leaves the route/journal/rearm surfaces `dead_code`-warning-free but
UNCONSUMED by design — `SessionWriteRoute`, `JournalRole`'s six variants,
`stage_journal_entry`, `write_route`, and `ClaimCandidate::world()` get their first
lib-target callers in seg 1 (batch.rs) and seg 2 (facade witness). The allow-reasons
name the consuming ticket in each case.
