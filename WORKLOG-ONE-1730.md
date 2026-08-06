# WORKLOG — ONE-1730 [L1-SPINE S1-L2] typed-journal one-transaction promote

Branch `ONE-1730`, cut from `origin/main` 8c4ed0753 (ONE-1728/P4a merged).
Blueprint: `/Users/olety/.claude-wave5/blueprints/L1-STORAGE-SPINE/ONE-1730.md`.

## Result

- `cargo test -p oneiron --all-features` — **4443 passed, 0 failed** (incl. all six
  unignored promote oracles). `cargo test -p oneiron` (default features) green.
- `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-features
  --all-targets` clean (only the pre-existing `oneiron-seal` sha2 deprecation,
  present on main).
- `Cargo.toml` / `Cargo.lock` / `STORAGE_ABI_VERSION` untouched (0 diff lines).

## Hard laws, grep-verified

| law | evidence |
|---|---|
| `Vault::promote_off_record_turn` deleted, zero refs | `rg -c promote_off_record_turn crates/` → 0 files |
| `FloorWrites::commit_promote` REPLACED, no third op | `rg -c commit_promote crates/` → 0 files; `FloorWrites` now has exactly `append_egress_gate_decision`, `append_redaction_audit`, `promote` |
| no ABI bump / no migration | `git diff base -- store.rs` → 0 lines |
| `Cargo.lock` never committed | 0 diff lines; restored after every gate run |

## Shape landed

- `session_overlay.rs` — `PromotePlan` + `OverlaySnapshot::plan_promotion` (closure
  cut from typed journal metadata ONLY: role tag + scope; the shell is selected by
  `ConversationShell` role against the turn's own conversation, so a sibling turn
  never promotes a dangling `BelongsTo`), `promotion_replay_op` (rebuilds each op
  on the ENTRY's `occurred`/`learned_at`; `Edge` → `PublicEdgeWithCreatedAt` so the
  gated timestamped arm carries the journaled `created_at` instead of restamping at
  apply time), and `SessionOverlay::retire_promoted_closure`.
- `off_record/promote.rs` — production `PromoteOutcome` (pinned two fields,
  `Debug/Clone/PartialEq/Eq` + serde via an `EntityId`-bytes helper, since
  `EntityId` carries no serde impls and `entity_id.rs` is not this lane's),
  `PromoteReplayGrant` (minted only here, out of the closure this txn replays),
  reshaped `OffRecordPromoteReceipt` carrying the full outcome, and
  `FloorWrites::promote`.
- `off_record/lifecycle.rs` — `OffRecordSession::promote_turn`; the entity write
  door `guard_off_record_entity_put` gained the same `PromoteMemberOf` exemption
  channel the K4 decode-point guard already read.
- `batch.rs` — `TxnBatchBuilder::promotion_replay` (the only non-`Ordinary`-origin
  constructor) terminating at `apply_recording_gate_decisions`; `apply_put` threads
  `promote_member_of` to the entity door.
- `branch_store_oracle.rs` — six oracles unignored; the seam's twin `PromoteOutcome`
  replaced by the production type; `full_db_census` length is now
  `DB_MANIFEST.len()`, not the literal 28.

## Blueprint deviations — DECLARED, not absorbed

**DEVIATION-1 (needs adjudication): `promote_attribution_edge_set_is_exact` asserts
FOUR attribution edges, not the ratified three.**
The blueprint and the relay both pin "the exact 3-edge attribution set"
(`PartOf(message→turn)`, `DerivedFrom(summary→turn)`, `BelongsTo(message→shell)`).
But ONE-1728's `witness_into_session` also journals `AuthoredBy(message→actor)` for
every non-`System` author (`facade.rs`, `JournalRole::AttributionEdge`), and the
ratified fixture is a `WitnessAuthor::User` turn. Promotion replays the closure the
journal actually holds, so the set is four. The two options were:
(a) drop `AuthoredBy` from the closure to reach three — silently strips authorship
provenance from every promoted message, and contradicts ARCH-0052 §D4's unqualified
"attribution edges";
(b) assert what happens, with all four endpoint pairs pinned.
Took (b): it keeps the oracle's own stated claim ("the FULL attribution-edge set,
every edge with exact endpoints — and nothing else") and strengthens it by one
pinned edge rather than weakening anything. The blueprint's "exactly four replayed
entity ids" is unaffected — `AuthoredBy` adds no entity. **If the adjudicator prefers
three, the fix is a fixture change (System-authored message), not a closure change —
do not resolve it by dropping the edge.**

**DEVIATION-2: promote no longer authenticates a `ConsentActorIdentity`.**
The pinned keystone `OffRecordSession::promote_turn(&self, turn: &EntityId)` has no
actor parameter, and the ratified oracles call it with one argument, so the fence-era
`ConsentActorIdentity::authenticates_principal` check and the receipt's
`initiator_ref` / `initiator_kind` fields have no source and were removed. Consent is
now expressed by holding a live session handle. `Error::OffRecordPromoteUnauthenticated`
survives unused (P6/ONE-1731 owns dead fence-era error removal).
**Banked for owner/wave-4 (ONE-1645 owns consent hardening): if promote must keep an
authenticated initiator, the public signature has to grow one and the oracles with it.**

**DEVIATION-3: the promote-replay binding follows P4a's LANDED shape, not the
CLAIMS RESIDUAL-1 text.** RESIDUAL-1 says
`apply_ops_with_gate_mode(..., origin: BaseWriteOrigin<'_>)` with
`BaseWriteOrigin::PromoteReplay(&grant)`. P4a landed a fieldless `BaseWriteOrigin`
plus a separate `PromoteMemberOf` channel on `apply_ops_with_origin`, and documented
why. Followed the landed guard (relay: never revert P4a's guards); `PromoteReplayGrant`
still exists and is still mintable only inside `promote.rs`, supplying that channel.
Semantically identical, syntactically different from the ruling's wording.

**DEVIATION-4: overlay retirement is scoped and best-effort.**
Retirement removes the closure's `Entities`, `TypeIndex`, `Temporal*`, `ShortIds`/
`ShortIdsReverse`, `EdgesOut`/`EdgesIn` rows and its journal entries. It deliberately
does NOT retire BM25 (`TextPostings`/`TextMeta`/`TextForward`/stats) or vector/HNSW
rows: those keys and duplicate identities are byte-identical to what the replay just
wrote to base, so a composed read returns one row either way, and the accumulator
halves (`total_docs`, per-field lengths) are room-scoped counts that must keep
answering for the room until close. Removing them via the overlay `OverlayDb::delete`
path would compute `base_backed = true` (base now HAS the row) and leave a TOMBSTONE
masking the promoted base row — the room would lose sight of the turn it just
published. Retirement failure is logged, not returned: the subgraph and receipt are
already durable, and reporting a failed promote for content that IS published is the
wrong-direction lie under consent semantics.

## PACKET_AMEND candidates (all inside CLAIMS.md, outside the relay's PACKET line)

1. `crates/oneiron/src/off_record/tests.rs` — forced by deleting
   `Vault::promote_off_record_turn`. CLAIMS.md owns it explicitly
   (`off_record/{mod.rs,lifecycle.rs,promote.rs,tests.rs}`).
2. `crates/oneiron/src/error.rs` — appended `Error::OffRecordTurnNotInJournal` +
   its `ErrorKind` arm. CLAIMS.md: "new typed variants... append-only, merge-safe".
3. `crates/oneiron/src/sync/window/tests.rs` — forced by the same deletion.
   CLAIMS.md owns `sync/{window.rs,...} + their tests`. Production `sync/window.rs`
   untouched (read-only contract honoured: `WindowKey::from_timestamp`, `pm:` format).

## Test surface changes

**Deleted (fence-era promote, the operation no longer exists):**
`off_record_promote_writes_exactly_one_turn`,
`off_record_close_and_promote_are_serialized_by_registry_lock`,
`promote_without_entity_keeps_guard_active_for_late_write`,
`promote_requires_authenticated_actor`,
`promote_receipt_records_authenticated_initiator`, and the two sync-window
fence-lift catch-up tests (`off_record_promotion_catches_up_an_already_open_window`,
`off_record_promotion_refreshes_cross_window_source_edges`).
`promote_without_entity_...`'s live half (the closed-fence marker keeps the write
door shut after close) is already covered by
`off_record_close_rejects_late_write_for_missing_turn_without_audit_artifacts`.

**Trimmed:** `off_record_fence_defers_window_packing_until_only_the_promoted_turn_releases`
→ `..._for_every_fenced_turn`. Its deferral half is still-live behavior and is kept
(now asserting deferral is a standing predicate across repeated packing passes); its
release half needed a fence lift that P5 removes.

**Ported to the new surface:** `off_record_closing_flag_freezes_record_against_mutators`
(promote arm now goes through the session handle — the closing check runs before the
journal is read, so it still rejects on the seam);
`tag_rejects_re_fencing_a_durably_promoted_turn_in_a_later_session` (receipt now
minted by a real witness+promote via the new `witness_and_promote` helper);
`off_record_session_ref_bounds_are_enforced_everywhere` (promote arm dropped — the
verb takes no session ref, so the bound is enforced upstream at `enter`).

**Added:** `promote_replay_refuses_another_live_rooms_overlay_id_and_rolls_back` —
a second live room holds the ACTOR the promoted message is attributed to. That id is
referenced by the closure but not part of it, so the K4 guard refuses at the
`AuthoredBy` edge, several ops AFTER the shell/turn/message puts have staged rows.
It therefore proves three things at once with no test-only production seam: the grant
exempts only the granting session's closure; an in-transaction failure yields zero
base delta (the single-transaction contract's pre-commit half); and a failed promote
leaves the journal/overlay closure intact and promotable.

## Bug found and fixed in landed P4a code (not a ONE-1730 regression)

`branch_store_oracle.rs::witness_turn_shape` read the SUMMARY id off an `edges_in`
prefix scan as the parser's FIRST element. An `edges_in` key is
`(TARGET ‖ kind ‖ SOURCE)`, so the first element is the turn the scan was already
prefixed on — the helper handed each turn its own id back as its summary, which every
caller then silently aliased through `summary.unwrap_or(turn)`. No armed P4a oracle
asserted on the returned summary id, so it was invisible until the promote-closure
oracle compared it against the replayed set. Fixed to read the PEER element.

## Known holes / bank

- **In-transaction fault injection beyond the taint path.** The one added rollback
  test induces a real in-txn failure (see above). A *generic* mid-transaction fault
  (e.g. fail after N staged ops) would need a test-only injection seam in production
  code; not built. Banked.
- **Live-window catch-up after promote has no direct test.** The two sync-window
  tests that covered it were fence-lift-driven and were deleted with the operation.
  `refresh_promoted_turn_in_live_window` is still called post-commit and is
  best-effort by contract; `promote_crash_post_commit_leaves_pm_pickup_marker` covers
  the `pm:` marker half. Banked as a coverage gap for whoever owns session sync next.
- **`bm25::tests::bm25_diagnostics_increment_for_targeted_search_corruption` is a
  pre-existing cross-test flake**, charged to no lane. It and
  `deindex_self_heals_missing_postings_and_records_diagnostics` both call
  `reset_bm25_diagnostics()` on PROCESS-GLOBAL counters and assert `before + 1`
  deltas, so one test's reset can clobber the other's baseline under parallel
  execution. Observed red once, green on the flake-guard re-run and on every
  subsequent full-suite run. Not touched (outside this lane's packet).

## K3 SIMPLIFY pass (post-impl)

Three deletions, no additions; public API, test assertions/fixtures, the
one-transaction law, typed-journal-only selection, receipt-first retry, and
grant scoping all untouched.

1. **`off_record/promote.rs`** — deleted the `#[cfg(not(feature = "sync"))]`
   no-op stub of `write_promote_pickup_markers` and gated the CALL site instead,
   matching the file's own `refresh_promoted_turn_in_live_window` pattern. The
   stub was a second function existing only to be ignored.
2. **`off_record/lifecycle.rs`** — deleted the defensive
   `if !promoted_turns.contains(...)` guard around the post-commit push. The
   receipt-first early return makes a second reach of that line impossible
   (receipt is written in the same txn as the replay; the per-session state
   lock is held across both), so the branch could never be taken and misled the
   reader into expecting duplicates.
3. **`session_overlay.rs`** — collapsed `promotion_replay_op`'s `Text`/`Vector`
   arms from field-by-field rebuilds to `entry.op.clone()`. Only `Put`
   re-stamps the journaled time range and only `Edge` re-arms; the other two
   ride unchanged, and the explicit arm list keeps the staging whitelist.

Gates after the pass: `cargo fmt --check` clean · `cargo check` default AND
`--all-features` clean (same two pre-existing warnings as before the pass: the
non-sync `source_learned_at` dead-read the old stub never suppressed, and the
unrelated `facet_of_endpoints_provably_off_table`) · `cargo clippy -p oneiron
--all-features --all-targets` clean · **`cargo test -p oneiron --all-features`:
4443 passed, 0 failed** — identical count to the impl leg, six promote oracles
included. `Cargo.lock` drift from the gate runs restored, never committed.
