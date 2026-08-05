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

## Decisions

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

## Next-step INTENT

After seg-0 cheap gate + commit: seg 1 opens with batch.rs K4
(`BaseWriteOrigin` / `apply_ops_with_origin` / in-txn decode-point taint guard),
because facade `witness_into_session` and the oracle arming both sit downstream of
the session apply entry.

Seg-0 leaves the route/journal/rearm surfaces `dead_code`-warning-free but
UNCONSUMED by design — `SessionWriteRoute`, `JournalRole`'s six variants,
`stage_journal_entry`, `write_route`, and `ClaimCandidate::world()` get their first
lib-target callers in seg 1 (batch.rs) and seg 2 (facade witness). The allow-reasons
name the consuming ticket in each case.
