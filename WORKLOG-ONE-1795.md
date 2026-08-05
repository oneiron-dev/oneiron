# WORKLOG — ONE-1795 (SPINE-COMM)

Retries are new ATTEMPT rows: one synced TASK owns N node-local tries; a retry
never mutates a failed try back into a ready one.

Worktree: `/Volumes/Cinema/w5-lt/spine-comm` · branch `ONE-1795`
(cut from `dcf8010`, the ONE-1792 lane head)
Blueprint: `/Users/olety/.claude-wave5/blueprints/SPINE-COMM/ONE-1795.md`

## Shape landed

### 1. `AttemptState::Scheduled` (append-only)
Appended AFTER `Cancelled`; no existing variant reordered, so persisted rows
(encoded by variant index) decode unchanged and `ATTEMPT_RECORD_VERSION` stays
`2`. `as_str()` → `"scheduled"`. `is_pending()` includes it (a scheduled retry
still owns its advisory dedupe entry). New private
`AttemptState::is_ready_indexed()` = `Queued | Scheduled` replaces the three
`state != Queued` guards in the ready-scan paths.

### 2. `AttemptRecord` additive fields
`scheduled_at: Option<u64>` and `retry_of: Option<AttemptId>`, both
`#[serde(default)]`. `backoff_until` retained as **legacy read compatibility
only**. `ready_at()` is now
`scheduled_at.or(backoff_until).unwrap_or(0)` — a legacy `Queued +
backoff_until` row keeps its exact original readiness instant, with no bulk
rewrite anywhere.

### 3. `AttemptQueue::retry` — one transaction, two rows
Validates the leased source under the existing owner + `attempt_count` fence,
then in a single LMDB write txn:
- finalizes the source as `Failed` (lease/backoff cleared, retry reason
  stamped, `updated_at` bumped, payload/provenance/`claimed_at` retained);
- mints `AttemptId::now()` copying `kind`/`payload`/`task_ref`/`run_id`/
  `dedupe_key`, with `retry_of = Some(source.id)`, `state = Scheduled`,
  `scheduled_at = input.backoff_until`, `attempt_count = 0`, no lease,
  `created_at = updated_at = input.now`;
- puts only the NEW row in the ready index (the leased source held none), adds
  it to the run index, and moves the advisory dedupe entry (both blake3 and
  legacy spellings deleted off the source, blake3 re-pointed at the new row);
- returns `RetryOutcome::Retried(next)` — the existing shape, so no caller
  rewrite. The source stays point-readable by its old id and can never be
  claimed again.

A retry reason is required to finalize the source as `Failed`, so an omitted
`last_error` normalizes to the stable token `RETRY_REASON_UNSPECIFIED = "retry"`
rather than failing the call.

### 4. Claim / cleanup / intervention alignment
- `lease_claimed_record()` extracted (the lease mutation was duplicated across
  three claim paths); it clears BOTH readiness spellings on lease.
- `cleanup_leases` counts `Scheduled` as pending, and `waiting_on_backoff()`
  (either spelling) drives the `RetryBackoff` reason. Lease-timeout reclaim
  still requeues the SAME row as `Queued` — that is a lease-generation reset
  within one try, not a logical retry, so it mints nothing.
- `intervene`: `Scheduled` accepted for Interrupt / Pause / Cancel (cancel also
  clears `scheduled_at`), and `AlreadyResumed` for Resume. Pause keeps
  `scheduled_at` so Resume restores `Scheduled` (not `Queued`) when the row is
  still deferred — restoring it as `Queued` would render deferred work as
  runnable-now on every read surface, which is the readiness-honesty bug this
  ticket exists to close.
- `decode_record` gained `Scheduled` invariants (no lease owner; must carry a
  scheduled instant) and the leased/terminal backoff checks now cover both
  spellings.

### 5. Run tree (observe surface)
`retry_of` resolves `parent_id` BEFORE the Dreamer payload fallback, on all
three metadata paths (dreamer-ok, dreamer-malformed, bare kind), so a retry
renders as a child of the try it replaces. `AttemptState::Scheduled` maps to the
existing `RunTreeStatus::Paused` — which `context_board.rs:242-253` already
projects as the existing `TaskBoardStatus::Scheduled` token. **No new
`RunTreeStatus` variant, no `RunTreeNode` readiness/backoff field, no
`context_board.rs` edit, no server adapter remap.** `status_event_kind` returns
`None` for `Scheduled` (a scheduled try has only `Created`; it was not paused by
an operator).

### 6. The three pinned additive arms
- `facade.rs` `attempt_state_str` → `"scheduled"`.
- `agent_dispatch.rs` intervention → `Cancel`, like `Queued`.
- `dreamer_runner.rs` `publish_progress` → pre-lease arm with
  `Queued | Leased`, so live progress stays on the existing `created` token.

No surrounding match was redesigned.

## Deviations from the blueprint

### DEV-1 — `task_verb.rs` cancel path (PACKET_AMEND, correctness)
**Not in the blueprint's claims or in `CLAIMS.md`; edited anyway.** Two
`matches!(attempt_state, Queued | Paused)` guards in the `tasks.cancel` path
(`task_verb.rs:532-543`) are not exhaustive matches, so they compile fine — and
silently break. Failure trace: a connector-send TASK whose attempt is retried
now holds `[source Failed, next Scheduled]`. With `Scheduled` absent from the
guard, the "nothing cancelable" branch returns early with
`terminal_attempt_status(...) == Some(Failed)` — the verb reports the task
terminally failed, cancels nothing, and the scheduled retry still runs and
sends. That is a send-after-cancel hole introduced by this ticket.

Fix is narrow and additive: one private `is_cancelable_attempt_state()`
(`Queued | Paused | Scheduled`) used at both sites. Flagging for the deviation
board; `terminal_attempt_status` itself is unchanged.

### DEV-2 — `companion/tests.rs`, `dreamer_runner/tests.rs` (PACKET_AMEND, fixture-sync)
**Not in claims.** Four tests used `queue.retry` as a "put this leased row back
in the ready index" fixture and asserted the SAME id came back — the exact
contract this ticket inverts.
- `companion/tests.rs`: rebound to the new row and moved the retryable-reason
  assertion onto the now-`Failed` source (assertions strengthened, not weakened
  — it now checks both rows).
- `dreamer_runner/tests.rs` (2 of 3): switched to
  `cleanup_leases`. Those tests exercise per-attempt budget-reservation top-up,
  which is keyed by `(budget_id, attempt_id)`; a lease-timeout reclaim is the
  mechanism that genuinely preserves row identity, and their reason strings were
  already literally `"lease_timeout"`. This makes the fixture mean what the test
  means.
- `dreamer_runner/tests.rs` (`..._after_ready_repairs`): kept `retry`, rebound
  to the minted ids. The stale-ready-key structure is preserved exactly.

### DEV-3 — blueprint claims vs `CLAIMS.md`
The blueprint's Claims list includes `facade.rs`, `agent_dispatch.rs`, and
`dreamer_runner.rs`; `CLAIMS.md`'s ONE-1795 block does not. The three arms are
compile-forced (`#[non_exhaustive]` does not apply within the defining crate),
so the crate cannot build without them. Followed the blueprint. Each is a
one-arm addition; the `facade.rs` seam note (after ONE-1767/1768) is respected —
nothing else in that file is touched.

## Files changed

In `CLAIMS.md` for ONE-1795:
- `crates/oneiron/src/attempt_queue.rs`
- `crates/oneiron/src/attempt_queue/tests.rs`
- `crates/oneiron/src/run_tree.rs`
- `crates/oneiron/src/run_tree/tests.rs`
- `crates/oneiron/src/outbound/tests.rs`
- `crates/oneiron/tests/effect_spine_oracle.rs`

In the blueprint's claims but not `CLAIMS.md` (DEV-3):
- `crates/oneiron/src/facade.rs`, `agent_dispatch.rs`, `dreamer_runner.rs`

PACKET_AMEND (DEV-1 / DEV-2):
- `crates/oneiron/src/task_verb.rs`
- `crates/oneiron/src/companion/tests.rs`
- `crates/oneiron/src/dreamer_runner/tests.rs`

`crates/oneiron/src/outbound.rs` is claimed but needed **no edit** — the
executor already calls `queue.retry` and gets the new contract for free, and its
`backoff_until: now.saturating_add(1)` keeps the loop terminating (the fresh
scheduled row is not claimable at `now`). `store.rs`, `context_board.rs`, server
adapters, sync modules, and `Cargo.lock` untouched, as specified.

## Tests

New/rewritten (all in claimed files unless noted):
- `attempt_queue_retry_mints_a_new_row_and_leaves_the_source_terminal` —
  distinct id, `retry_of`, `attempt_count == 0`, source terminal + unreclaimable,
  dedupe index transfer, claimable at exactly `scheduled_at` and not one second
  early.
- `attempt_queue_retry_chain_keeps_every_try_independently_queryable` — three
  retries → four distinct rows, unambiguous parent chain, all four in the run
  index in `(created_at, id)` order.
- `attempt_queue_retry_omitting_a_reason_stamps_a_stable_token`.
- `attempt_queue_retry_of_a_missing_lease_writes_nothing` — atomicity: a
  rejected retry leaves neither a half-finalized source nor an orphan row.
- `legacy_backoff_row_decodes_and_keeps_its_readiness_instant` — version-2 row
  with no `scheduled_at`/`retry_of`, decode + `ready_at` + round-trip.
- `legacy_backoff_row_stays_claimable_at_its_original_instant` — planted legacy
  row claims at its own instant, not before.
- `dedupe_hash_domain_stays_pinned` — `oneiron.job_queue.dedupe.v1\0`.
- `run_tree_attaches_a_scheduled_retry_under_its_failed_source` (replaces
  `run_tree_omits_retry_last_error_until_terminal_failure`) — failed root with
  its scheduled child, child status `Paused`, events `[Created]`.
- `connector_task_retry_mints_a_fresh_attempt_under_one_task`
  (`outbound/tests.rs`) — a Held dispatch produces one TASK + two ATTEMPT rows,
  the retry is not claimable early, and the logical send is charged once.
- `es02_one_task_owns_many_attempt_ids_with_per_try_terminal_history` (oracle).
- `es02_attempt_retry_churn_is_device_local_while_the_task_is_authoritative`
  (oracle) — two vaults, disjoint attempt-id sets, one TASK each, and no attempt
  id is an entity on either device (the synced surface is entities/edges).

### PR #509 wire/storage compatibility
Already pinned by existing tests that this diff leaves green, so they are the
proof rather than duplicated:
- `crates/oneiron/src/tests.rs:5320-5324, 5391-5393` — `job_records`,
  `job_ready`, `job_dedupe` DB manifest names.
- `crates/oneiron/src/batch/export/tests.rs:165` — export-manifest group
  spelling (`"group": "Jobs"`) byte-for-byte, at `db_manifest_version: 2`.
- `crates/oneiron/src/attempt_queue/tests.rs:1544` — `job_records key/id
  mismatch` error text.
- `run_tree.rs` `#[serde(rename = "job_id")]` wire keys unchanged.
- New: dedupe hash domain + version-2 legacy decode fixture (above).

## Gates

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | clean |
| `cargo clippy -p oneiron -p oneiron-driver --all-targets --all-features -D warnings` | clean |
| `cargo clippy --workspace --all-targets --all-features -D warnings` | one PRE-EXISTING error, see below |
| `cargo check --workspace --all-targets --all-features` | clean |
| `cargo test -p oneiron --all-features -- --test-threads=1` | **30 suites, 3431 passed, 0 failed, 25 ignored** (lib alone: 3173 passed, 1372s) |

### Pre-existing workspace clippy error (NOT from this lane)
`crates/oneiron-seal/src/native/verify.rs:1280` — `sha1::Sha1::digest(key).as_slice()`
trips the `generic-array` deprecation, which `-D warnings` turns into an error.
Reproduced on the stashed base tree (`git stash` → same single error), and this
diff touches no file in `oneiron-seal`. The ONE-1792 worklog already recorded it
as a pre-existing warning; a toolchain/dep bump has since promoted it to an
error. Charged to no lane.

### Pre-existing parallel flake (NOT from this lane)
Carried forward from ONE-1792: parallel full-suite runs intermittently fail one
tracing-capture test (`tracing::subscriber::with_default` is thread-local, so
parallel span-emitting tests pollute each other's captures).
`attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`
is one of the named victims and appeared in the first parallel run here; it does
not call `retry` and passes in isolation and under `--test-threads=1`.

## Notes for downstream lanes

- **ONE-1879** (exponential Pending backoff over the retry chain): the chain is
  `retry_of`; compute over it and write the result into `scheduled_at`. Do not
  reintroduce `backoff_until` writes.
- **CMT/ONE-1876** (actor axis on the live-schedule dedupe key): the advisory
  dedupe index now moves to the newest pending member inside `retry`'s
  transaction — rebase the key derivation onto that, not onto a fixed row id.
- **RUNTIME/ONE-1887**: must consume the new-row contract; in-place retry is
  gone.

## Banked (known holes, for the deviation board)

1. **`oneiron-driver` deadline source skips scheduled rows.**
   `crates/oneiron-driver/src/tick.rs:259` filters `state != Queued`, and `:268`
   reads only `backoff_until`. A `Scheduled` dreamer-consolidation row therefore
   never wakes the deadline timer. Exposure today is ZERO — no production caller
   retries a dreamer-kind attempt (`retry`'s only production call sites are
   `outbound.rs:2049` and `companion.rs:1234`), and lease-timeout reclaim still
   yields `Queued`. Not fixed here: `oneiron-driver` is a different crate and
   outside every claim list. One-line fix when someone owns that file:
   `matches!(attempt.state, Queued | Scheduled)` plus
   `scheduled_at.or(backoff_until)`.
2. **Per-attempt Dreamer budget reservations are stranded by a retry.**
   `budget_reservation_key(budget_id, attempt_id)` binds a reservation to a row
   id; when a retry mints a new row, the source's reservation is left behind and
   the new try starts fresh. Same zero-exposure argument as (1). If dreamer
   attempts ever become retryable in production, the reservation needs to follow
   `retry_of` or be released when the source is finalized.
