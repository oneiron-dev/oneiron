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

**SEG 2+ (remaining)** — `alloc_session_short_id` + session short-id namespace ·
`apply_ops_session` + op-loop write-target parameterization · store.rs
extract-parameterized writers + `impl SessionStoreView` · bm25/ppr/hnsw
parameterization · facade `witness_into_session` · pipeline `run_for_pack`
registration routing · gate.rs threading · claim.rs ScopedRead · context_pack.rs ·
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

## Next-step INTENT

Seg 1 landed the three surfaces that had no dependency on the session apply
entry: K4 (batch.rs), K7 (facade door), K6 (embed rule). Everything remaining is
downstream of `apply_ops_session`, so seg 2 opens there:

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
