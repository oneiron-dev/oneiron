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

## K3 simplify pass (post-implementation)

Verdict: **no edit warranted.** Read the full production diff
(`attempt_queue.rs`, `run_tree.rs`, `agent_dispatch.rs`,
`dreamer_runner.rs`, `facade.rs`, `task_verb.rs`) against the blueprint.

- Duplication was already factored by the implementer: `lease_claimed_record`
  (two lease-mutation copies collapsed), `waiting_on_backoff` (three
  report/validation sites), `is_ready_indexed` (four ready-scan guards),
  `is_cancelable_attempt_state` (two cancel guards in `task_verb.rs`).
- The new `retry` is one flat transaction body with no speculative layers;
  the merged `Queued | Paused | Scheduled` report arms are already
  deletion-shaped.
- The only defensive-looking lines (`source.scheduled_at/backoff_until = None`
  in `retry`, unreachable on a decode-validated `Leased` row) spell out the
  blueprint's "clear lease/backoff" finalize step verbatim — kept as
  blueprint-faithful, costless.
- No fixture, test assertion, or public API touched. No gate re-run needed
  (tree unchanged from the green full-suite run above).

## FINDER-FIX (Sol-max round, adjudicated on `2eea280`)

Three findings the chain verdict leg never received (script defect — the
finder's output never reached it). Adjudicated here; all three REAL, all three
fixed at the chokepoint with mutation-verified tests. DEV-1 (the `matches!`
cancel guard) was a DIFFERENT site and was already closed by the impl leg.

The shared root: **ONE-1795 turned one row per TASK into a retry CHAIN, and
three surfaces still read the set as if the rows were peers.** F1 and F2 are
the same defect at the write door and the read door.

### F1 — `task-cancel-membership-toctou` (P1) → **REAL, fixed**

`task_verb.rs:489` re-read only the SNAPSHOTTED attempt ids inside the write
txn. Trace: `tasks.cancel` snapshots `[(A, Leased)]`; the connector executor's
`retry` wins the writer lock and commits `A → Failed` plus a fresh
`B{state: Scheduled, task_ref: same}`; the cancel's txn opens, re-reads `A`,
sees `Failed`, finds nothing cancelable, and returns
`effected: false, status: Some(Failed)` — the verb reports the task terminally
failed, cancels nothing, and **B still runs and sends**. Same send-after-cancel
class as DEV-1, one window later.

Lane-introduced: before this ticket `retry` mutated the row in place, so
membership could not change between snapshot and txn — only STATE could, which
the existing P1-b re-read already covered. The deferred-work comment at the old
`:484` named this exactly ("when multi-attempt-per-task ships, this in-txn
re-read must re-enumerate the realizing SET"); this ticket is what ships it.

Fix: a TASK target re-DERIVES its realizing set inside the write txn
(`AttemptQueue::list_task_in_write_txn`, a sibling of the existing
`get_in_write_txn`), reduced to chain heads. A Spawn target has no TASK
backlink to re-derive membership from, so its single row keeps the by-id
re-read — including the terminal-snapshot preservation arm, now unconditional
inside that branch instead of re-testing `task_ref.is_none()`.

Head reduction is load-bearing here, not decoration: without it the failed
source survives as `terminal_status = Failed`, `preserved_terminal_status` keeps
the TASK visible, `cancel_task_in_txn` never runs — and once F2 drops the
superseded source from the board, the cancelled task renders as *queued*
forever. With it, the cancel is honest: `effected: true`, `status: Cancelled`,
TASK withdrawn, `B` cancelled, `A` still point-readable as `Failed`.

Test `cancel_reaches_a_retry_minted_between_snapshot_and_write_txn`.
**Mutation-verified**: reverting to the by-id re-read leaves the successor
`Scheduled` (`left: Scheduled, right: Cancelled`) — the live send survives.

### F2 — `retry-chain-head-reduction` (P1) → **REAL, fixed**

`task_presence` flattened every chain node into `jobs`, and
`fold_up_status`'s any-row precedence (Running > Failed > Scheduled > Queued >
Done) then picked the worst row rather than the live one. A held retry folds up
as `Failed` instead of `Scheduled`; worse, **a chain that ultimately SUCCEEDED
still folds up as `Failed` forever**, because the terminal source outranks the
`Done` head permanently.

Fix at the chokepoint: only chain HEADS reach the board. One `continue` in the
node loop of `task_presence`, keyed on the same `superseded_attempt_ids` rule
F1 uses. This is the existing precedent, not a new axis — `JobPresence::
from_run_tree_node` already drops `Cancelled` rows because "the axis has no
token for withdrawn work"; a superseded try is withdrawn work whose successor
owns the realization. The run tree keeps every try, nested under the one it
replaces, as the forensic surface (`tasks.expand` is unchanged).

`fold_up_status` itself is untouched: its precedence order is L0-ruled and
correct for a set of PEERS. The defect was feeding it a chain.

Test `board_reads_a_retry_chain_off_its_head_not_a_superseded_try` — 2-retry
chain, head `Scheduled` → board `Scheduled` with `folded_job_count == 1`; head
then completes → board `Done`. **Mutation-verified**: without the skip the board
reads `Failed` (`left: Failed, right: Scheduled`).

### F3 — `legacy-readiness-projection` (P2) → **REAL, fixed**

`run_tree.rs:455` projected the bare enum. A version-2 row decodes as
`Queued` with only `backoff_until`; `ready_at()` preserves that claim instant,
so the claim loop defers it — but `flat_node` rendered `Queued`, which
`context_board.rs:247` maps to `TaskBoardStatus::Queued` and the facade attempt
view spells `queued`. The read surfaces said runnable-now while the queue
refused to hand the row out.

Not gold-plating on a dead path: this ticket deliberately kept version-2
readability (`backoff_until` retained, two legacy-decode tests pinned), so those
rows are a ratified design premise. And the asymmetry is lane-introduced —
before this ticket every deferred row rendered `Queued` uniformly; after it, a
new deferred row renders `Paused`/Scheduled while an identically-deferred legacy
row still renders `Queued`.

Fix: `run_tree_status(record)` derives the token from the readiness instant in
either spelling instead of the bare enum. **No clock is introduced** — the
projection stays pure and deterministic. It does not need one: a `Scheduled`
row renders `Paused` whether or not its instant has passed, so the honest
parallel is "carries a readiness instant at all", which is exactly
`ready_at`'s own predicate. Blast radius is zero for live rows: `claim`
(`lease_claimed_record`) and lease-timeout requeue (`cleanup_leases`) each clear
BOTH spellings, so no row queued by this build carries an instant. The public
`From<AttemptState> for RunTreeStatus` impl is unchanged.

Test `legacy_backoff_row_projects_deferred_not_runnable_now` (planted version-2
row with a future `backoff_until` → `Paused`, events still `[Created]` since it
was not paused by an operator; a sibling with no instant stays `Queued`).
**Mutation-verified**: dropping the arm yields `left: Queued, right: Paused`.

### Scope note (fix-brief bound exceeded, deliberately)

The brief bounded the diff to `task_verb.rs` + `run_tree.rs` + tests. F1's fix
needed an in-write-txn enumeration of rows by `task_ref`; `AttemptQueue` had
`get_in_write_txn` but no list sibling. The alternatives were both worse than a
12-line additive method: hand-rolling LMDB iteration and `decode_record` from a
verb module (punching through the queue's encapsulation and duplicating
`list()`), or opening a nested `RoTxn` inside the write txn (correct only via a
subtle appeal to LMDB's single-writer property — not something to bury in a
cancel path). `list_task_in_write_txn` follows the module's established
`_in_txn` family. **No PACKET_AMEND is owed**: `attempt_queue.rs` is already in
`CLAIMS.md` for ONE-1795, so there is no collision surface — only the
fix-brief's narrower bound is exceeded, flagged here.

### Reasoned-rejects

None. All three findings carried a reproducible trace and all three survived it.

### Gates (per commit)

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | clean, both commits |
| `cargo clippy -p oneiron --lib --all-features --all-targets -D warnings` | clean, both commits |
| `cargo test -p oneiron --lib` — `attempt_queue` / `run_tree` / `task_verb` | 46 / 15 / 26 passed, 0 failed |
| consumer suites (`context_board`, `outbound`, `companion`, `facade`, `inbox`, `agent_dispatch`, `dreamer_runner`) | 316 passed, 0 failed |
| `cargo test -p oneiron --lib` (full, final tree) | **2762 passed, 0 failed, 24 ignored** (105s, parallel; no tracing flake this run) |

No `Cargo.toml` / `Cargo.lock` change. Commits: `af37e17` (F3),
`98cee36` (F1 + F2 — one shared chokepoint rule, so one commit).
