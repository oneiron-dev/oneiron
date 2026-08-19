# WORKLOG — ONE-1375 [L1-ENTITY E1-L2] deterministic Habit streak recompute

Branch `ONE-1375` off `origin/main` 233d8bc34 (ONE-1924 #628 merged).
Blueprint: `/Users/olety/.claude-wave5/blueprints/L1-ENTITY/ONE-1375.md`.

## Shape as built

`currentStreak` / `longestStreak` are DERIVED fields on a Habit-role TASK.
Nothing outside `habit.rs` may supply them; every transaction that can change
what they are worth ends with one recompute pass over the FINAL state it left
behind.

* `crates/oneiron/src/habit.rs` — the whole derived-field surface:
  `STREAK_DAY_SECS = 86_400` (private), `HabitStreak`, the pure reducer
  `streak_from_checkin_days`, the txn helper `recompute_habit_streak_in_txn`,
  the body codec `rewrite_habit_streak_fields` (private), and the public-door
  guard `reject_public_streak_fields`. A single `task_body_entries` decoder now
  backs the role read, the rewrite, and the rejection — three users, one
  strictness contract (invalid MessagePack / trailing bytes / non-map root /
  non-string keys), and the four error literals `task_role_from_body_bytes`
  already emitted are preserved verbatim.
* `crates/oneiron/src/batch.rs` — the declared seam insertion only: one
  candidate-collection line beside the existing `ChildOfBatchOverlay::from_ops`
  call, one tail call after the op loop, one `ENTITY_TYPE_TASK` arm in
  `validate_public_raw_put`, one `ChildOfBatchOverlay` accessor, two private
  habit-family fns, and `child_of_prefix` widened to `pub(crate)`.

Hard laws, and where each is discharged:

| Law | Where |
|---|---|
| pure, order-independent reducer (day buckets, dedupe, sort asc) | `habit.rs::streak_from_checkin_days` — input is a BAG, sorted+deduped inside |
| never reads clock / insertion order / `learned_at` / replica id / body-map order / stored counters | the reducer's only input is `Vec<u64>` day buckets built from `occurred_start` |
| checked conversion, overflow ABORTS the txn | `checked_add` → `Error::ArithmeticOverflow("habit streak run length")`, propagated by `?` through the tail into the caller's `with_write_txn` |
| recompute rides the SAME `RwTxn` as the ChildOf commit | the tail runs inside `apply_ops_with_origin`, before the txn commits; every failure path is a `?`, so the check-in entity, the `ChildOf` edge and the habit body are one all-or-nothing write |
| children qualify only as `ENTITY_TYPE_TASK` + `HabitCheckin`, from final `edges_in` | `recompute_habit_streak_in_txn` iterates `edges_in` under the `ChildOf` prefix at the tail |
| rewrite ONLY the two keys, deterministic map bytes, header preserved | `rewrite_habit_streak_fields` filters + re-appends in fixed order; header bytes are copied, and an unchanged result stages NO write at all |
| public TASK puts carrying either key reject `InvalidTaskBody`, row unchanged | `validate_public_raw_put` → both `BatchBuilder::put` and `TxnBatchBuilder::put` reject before staging |
| `replicated_put_op` discards peer counters and replaces from the local reducer | the replicated door does not run the public reject (by design); the TASK-put candidate family makes the tail overwrite the inbound pair from local children |
| helper stays private/`pub(crate)`; no `set_streak`, no generic body patch, no facade verb; `Vault::put_habit_checkin` remains the public door | no public API added anywhere |
| non-Habit TASK and HabitCheckin bodies never gain streak keys | the tail's role filter is `== Some(TaskRole::Habit)`; asserted in `batch/tests.rs` |
| no new LMDB database/index/sidecar/entity/writable API | one existing row rewritten in place |

## Deviations from the blueprint (declared, not absorbed)

1. **`streak_from_checkin_days` returns `Result<HabitStreak>`, not `HabitStreak`.**
   The ratified skeleton is infallible, but the ratified arithmetic law says an
   overflow must ABORT THE TRANSACTION and must never wrap or saturate. An
   infallible signature can express neither: it would have to saturate (banned)
   or panic. The `Result` is the smallest change that keeps both laws — purity
   and order-independence are untouched, and the only `Err` is
   `ArithmeticOverflow`. The named test calls it with `.expect(...)`; the
   ratified test name and helper name are unchanged.
2. **`reject_public_streak_fields` is `pub(crate)`, not private.** Its only
   caller is `validate_public_raw_put`, which lives in `batch.rs` — the public
   put door is not in `habit.rs`. `rewrite_habit_streak_fields` did stay
   private, as ratified.
3. **`STREAK_DAY_SECS` is private** (blueprint spells it with no visibility
   modifier, so this is fidelity, not deviation — noted because the recompute
   helper landed in `habit.rs` alongside it rather than in `batch.rs`).
4. **The recompute candidate set is `{ChildOf-touched parents} ∪ {TASK puts}`,
   wider than "parents touched by ChildOf add/delete".** This is forced by the
   ticket's own laws, not preference:
   * `replicated_put_op` must "DISCARD inbound peer counter values and REPLACE
     from the local reducer". A replicated Habit body arrives as a `Put` op
     with no edge op beside it; without the put family there is nothing to
     replace it with, and stripping instead of replacing would DIVERGE the
     replicas (the peer keeps its counters, the local row loses them).
   * A legal local Habit body edit (a rename) carries no counters, because the
     public door forbids them. Without the put family that edit silently wipes
     a live streak until the next check-in.
   It remains ONE tail pass over a deterministically-ordered `BTreeSet`, and
   the role filter reads stored final state, so a non-Habit TASK put costs one
   lookup and nothing else.

## PACKET_AMEND candidate (needs ruling)

* **`crates/oneiron/src/tests.rs`** — outside this ticket's declared PACKET
  (`habit.rs` + `batch.rs` + `batch/tests.rs` + `tests/sync_convergence_props.rs`),
  inside the L1-ENTITY lane claim (CLAIMS.md line 16). `tests::each_role_validates`
  asserted a byte-exact round-trip for every TASK role; a Habit row now carries
  the two derived counters, so the Habit arm asserts `role + (0, 0)` against a
  LITERAL `rmpv_map_bytes` expectation and the other four roles keep the exact
  round-trip. 14 lines, one test, no collision with 1924's edge tables
  (`tests.rs:562` / `:6227`) or with spine 1754's entity-type prefixes.

## Known holes (banked, not fixed)

* **Hard-deleting a check-in entity does not recompute its parent.**
  `BatchOp::Delete` removes the child's `ChildOf` edges through `deindex_entity`
  without appearing in the ChildOf edge-op family, so the parent's counters go
  stale. Check-ins are append-only and immutable by contract, and the ticket
  scopes the trigger to "ChildOf add/delete"; closing it means reading the
  deleted child's parents before deindex. Deliberately out of scope — bank it.
* **Short-id content hash.** `plan_short_id_update` hashes the body the PUT
  carried; the tail rewrite changes the stored body afterwards, so a Habit's
  `short_ids` content hash lags its row until `maintain.rs`'s existing repair
  pass refreshes it. Not corrected here on purpose: refreshing it inside a
  derived recompute would mint index churn (and, on a missing reverse row, a
  short-id counter bump) for a field the user never authored. Existing refs
  keep resolving; the repair is already someone's job.
* **Sync ordering, checked not assumed.** A `ChildOf` edge whose endpoint row
  has not materialized is DEFERRED by `sync/window.rs` (`EdgeRematOutcome::Deferred`,
  endpoint-existence gate) rather than written, so the "edge lands before the
  child row" staleness window does not exist on the forward-remat path; the
  deferred edge recomputes when it is finally written.
* **Session overlay.** `apply_ops_session` is the overlay path and does not
  recompute; a session's closure replays into base through the ordinary
  `apply_ops` at promote, which does. Consistent with the ticket's
  "both eventually use `apply_ops`".

## Tests

* `habit::tests::streak_from_children_deterministic` (ratified name) — exercises
  `streak_from_checkin_days` over ALL 120 permutations of a 5-day fixture
  (exhaustive, not sampled, so order-independence is proven rather than
  spot-checked) plus duplicates, gaps, a lone day, the empty bag, a uniform
  time shift (proving no clock input), and repeated reduction. The fixture is
  chosen so `current` (2) ≠ `longest` (3): swapping the two counters or
  returning "today's run" cannot pass.
* `habit::tests::streak_fields_are_rewritten_in_place_and_rejected_on_public_puts`
  — rewrite preserves unrelated fields, is byte-stable on re-run, REPLACES a
  stale pair rather than appending a second one, and the public guard rejects.
* `batch::tests::habit_streak_is_derived_from_checkin_children` — end-to-end
  through `Vault::put_habit_checkin`: empty habit is `(0,0)`, days 10/11/11/14
  give `(1,2)`, all four children survive as separate entities, no check-in
  body gains a counter, and an identical re-put leaves the habit row
  byte-identical.
* `batch::tests::habit_body_edit_keeps_the_derived_streak_and_a_non_habit_task_never_gains_one`
* `batch::tests::public_task_put_carrying_streak_fields_is_rejected` — both keys,
  both public builders, stored row unchanged each time.
* `two_replicas_same_streak` (ratified name, `tests/sync_convergence_props.rs`)
  — offline check-ins on BOTH replicas, one day authored twice as two distinct
  entities, a gap so `current` (1) ≠ `longest` (3), plus a peer Habit envelope
  carrying forged `(99, 99)` counters stamped to win LWW. After merge both
  replicas hold 5 separate children, both derive `(1, 3)`, the parent rows are
  byte-equal, and `assert_converged` passes. The forged pair is the
  "a peer can never mint a streak" leg.
* The four named pre-existing tests stay green: `checkin_on_non_habit_rejected`,
  `checkin_immutable`,
  `checkin_same_role_mutation_rejected_and_identical_reput_idempotent`,
  `habit_with_checkins_cannot_change_role`.

## Simplify pass (K3, 2026-08-07)

NO EDIT WARRANTED. Reviewed the full lane diff against the deletion-biased
mandate: the `task_body_entries` decoder already backs all three users (role
read, rewrite, public-door reject) with one strictness contract; `is_streak_key`
is shared by the rewrite filter and the reject; every helper matches the
ratified keystone skeleton; no dead code, duplicated helpers, defensive
branches, or speculative generality found. The only candidates weighed —
inlining `recompute_touched_habit_streaks_in_txn` or dropping the single-use
`ChildOfBatchOverlay::child_of_edge_parents` accessor — were rejected: both
would churn the live-shared `batch.rs` seam (1730 in flight) for zero net
deletion, and the accessor matches the adjacent `affected_children` idiom.
Tests, public API, reducer purity, same-txn law, peer-cannot-mint law, and the
public-put rejection verified intact. Gates re-run at tip `88cf6fa`:
`cargo fmt -p oneiron -- --check` clean; `cargo clippy -p oneiron
--all-features --all-targets` clean; `cargo test -p oneiron --all-features --
streak checkin habit each_role_validates` green (both ratified named tests +
the four pre-existing checkin/habit tests + the amended `each_role_validates`).

## Gates

* `cargo fmt -p oneiron -- --check` — clean.
* `cargo clippy -p oneiron --all-features --all-targets` — clean, zero warnings.
* `cargo check --workspace --all-features` — clean.
* `cargo test -p oneiron --all-features` — **51 test binaries, 0 failed**
  (lib: 3956 passed / 0 failed / 17 ignored).

`Cargo.lock` was refreshed by cargo during the build and is deliberately NOT
staged or committed. `serialize.rs` and `vault.rs` were not touched (the field
names already exist in `FieldProfile::Full`; the Vault wrapper lives in
`habit.rs`). ONE-1924's `BlockedBy` arms are untouched — none of them are in
`batch.rs`, and the one `tests.rs` edit is ~5600 lines away from 1924's pinned
edge tables.

## VERDICT-FIX (Opus fix leg, 2026-08-07, on tip `bc9c92a`)

Finder + verdict legs returned two CONFIRMED P1s and one CONFIRMED P2. Both
P1s fixed at their chokepoint, each mutation-verified red-before / green-after.
Nothing relitigated; nothing banked.

### P1 · `replicated-counter-trust` (batch.rs) — FIXED

The sync door builds its op through `replicated_put_op`, which deliberately
skips `validate_public_raw_put` — the only place `reject_public_streak_fields`
ran. So a peer envelope reached `apply_put` still naming `currentStreak` /
`longestStreak`. The tail reducer visits rows whose STORED role is `Habit`, so
a `Habit` row was in fact repaired; the hole was every other role. A peer
shipping `{role: HabitCheckin | Task | Goal, currentStreak: 99}` had those keys
committed verbatim and never overwritten — permanently, since
`validate_task_checkin_immutable` then froze the check-in row. That breaks
blueprint acceptance line 62 ("Non-Habit TASK bodies never gain streak keys;
HabitCheckin bodies never gain streak keys") outright.

Fix: `crate::habit::strip_streak_fields` DISCARDS the two keys (the brief's
verb — rejecting a peer row would strand it and diverge the replicas), and it
is called from `apply_put`'s single TASK arm, so it covers every door and every
role rather than only the sync door and only `Habit`. It returns `None` when the
body named no counter, so the common path stores the peer's bytes untouched and
only a forged body is re-encoded. The sanitized body is rebound BEFORE short-id
planning hashes it and before the old-record `body_changed` comparison, mirroring
the adjacent ONE-1892 skill-escalation rebinding for the same reason.

MUTATION: with the rebinding neutralized,
`replicated_task_put_cannot_mint_streak_counters` fails
`a peer cannot mint a counter on a Task row: left: Some(99), right: None`.

### P1 · `incomplete-derived-invalidation` (batch.rs) — FIXED

`habit_streak_recompute_candidates` drew only from explicit `ChildOf` edge ops
and TASK put ids. Two ways a Habit's qualifying child set moves without either:

* `vault.batch().delete(checkin)` → `deindex_entity` → `delete_related_edges`
  tears the `ChildOf` rows down with no `DeleteEdge` op. A Habit with check-ins
  on days 10 and 11 stayed `(2,2)` after the day-11 child was deleted.
* A `ChildOf` edge may PRE-EXIST its child (the parent-role validator admits an
  edge whose child does not exist yet — the ordinary sync-replay ordering). The
  put that materializes the check-in names no edge, and the candidate is the
  CHILD id, which the Habit-only tail skips.

Both are convergent-but-wrong (every replica goes stale identically), so they
are correctness bugs, not divergence: the stored counters stopped being a
function of the persisted children, which is the lane's whole invariant.

Fix: collection now also unions the PRE-state `ChildOf` parents of every deleted
row and of every TASK put. Pre-state deliberately — an edge this batch removes
is unreachable at the tail. Over-collecting costs one idempotent recompute;
under-collecting strands a stale counter forever. The function takes the txn and
returns `Result` accordingly.

MUTATION: with the pre-state scan neutralized,
`deleting_a_checkin_recomputes_the_habit_streak` fails `left: (2,2), right:
(1,1)` and `checkin_materializing_under_an_existing_edge_recomputes_the_habit_streak`
fails `left: (0,0), right: (1,1)` — exactly the verdict's derivations.

### P2 · `packet-scope` (tests.rs:12179) — PACKET_AMEND REQUESTED, no revert

Per the verdict's explicit disposition: this is bookkeeping, not code. The hunk
is the minimal forced fixture-sync update to `each_role_validates` (a Habit put
now stores derived `(0,0)`, so the old byte-exact round-trip assertion would be
red without it). `crates/oneiron/src/tests.rs` is already lane-claimed for stack
E1 in `L1-ENTITY/CLAIMS.md:16`, so there is no cross-lane collision; owner ruling
R-20260807-01 covered ONE-1924's `context_pack.rs` / `code_run.rs` arms only and
does not reach this file. **Open for orchestrator/Fable: one-line PACKET_AMEND
adding `crates/oneiron/src/tests.rs` to ONE-1375's frozen 4-file packet.**
Reverting was rejected — it would red a ratified test to satisfy a manifest.

### New tests (all in `batch/tests.rs`, packet-internal)

* `deleting_a_checkin_recomputes_the_habit_streak` — public batch delete of a
  check-in moves `(2,2) → (1,1)`, and emptying the child set gives `(0,0)`
  rather than a frozen high-water mark.
* `checkin_materializing_under_an_existing_edge_recomputes_the_habit_streak` —
  edge first (parent stays `(0,0)` while the child row does not exist), child
  row second in its own txn carrying no edge, parent recomputes to `(1,1)`.
* `replicated_task_put_cannot_mint_streak_counters` (`cfg(feature = "sync")`) —
  a peer `Habit` envelope carrying `(99,99)` still yields the local `(1,1)`;
  peer `Task` / `Goal` / `HabitCheckin` rows store NO streak key while the rest
  of the peer's body (`title`) survives the discard byte-for-byte; the replayed
  forged check-in still counts toward the parent's arithmetic `(2,2)`.

### Gates

* `cargo fmt -p oneiron` — clean.
* `cargo clippy -p oneiron --all-features --all-targets` — clean, zero warnings.
* `cargo test -p oneiron --all-features` (lib target, both fixes applied) —
  **3957 passed / 2 failed**; both failures
  (`batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`,
  `embed::tests::partial_remote_completion_is_logged_when_local_batch_fails`)
  are pre-existing parallel-execution flakes on paths this lane does not touch
  (clock read + global log capture) and both pass in isolation.

### ⚠ BOX BLOCKER — final `--all-features` gate could not be completed

Mid-leg the MacBook stopped being able to open LMDB vaults:
`open vault: Storage(Io(Os { code: 28, kind: StorageFull, message: "No space
left on device" }))`, at `Vault::open`, before any test logic. It is NOT disk
and NOT this lane:

* `/System/Volumes/Data` holds 270Gi free and 290GB APFS container free, flat
  throughout a run; the test config's `map_size` is 16 MiB.
* Reproduces identically with `TMPDIR` pointed at `/Volumes/Cinema` (3.5Ti free).
* Failure count grew monotonically across identical runs — 2 → 19 → 1131 → 1888
  → 2350 — independent of what code was compiled.

Root cause, measured: macOS POSIX **named-semaphore namespace exhaustion**.
LMDB on macOS backs its reader/writer locks with `sem_open`, which returns
`ENOSPC` (28) when the kernel namespace is full; heed surfaces that as
`StorageFull`. A freshly compiled probe (`/tmp/semprobe.c`) can currently open
only **1–3** named semaphores before `sem_open` fails. LMDB needs 2 per env, so
the box now supports roughly ONE concurrent vault — which is why 2 test threads
worked for one probe run and nothing works now. `lsof | grep PSXSEM` shows only
48 held by live processes (`plugin_host`, `sublime_text`) — the remainder are
leaked with no holder. Names are stored in each vault's `lock.mdb`, and those
tempdirs are gone, so they cannot be `sem_unlink`ed.

**Remedy is machine-level: reboot the MacBook.** This will red the verify leg of
EVERY lane on this box with a misleading "No space left on device", not just
ONE-1375. Re-run `cargo test -p oneiron --all-features` after the reboot; the
integration target `tests/sync_convergence_props.rs` (`two_replicas_same_streak`)
is the one leg this fix leg could not re-confirm — it fails at
`sync_harness/mod.rs:255` on vault open, never on an assertion.

`Cargo.lock` was refreshed by cargo and is deliberately NOT staged or committed.
Diff stays inside the packet: `habit.rs`, `batch.rs`, `batch/tests.rs` (plus the
pre-existing `tests.rs` hunk awaiting the amendment above).

### Salvaged verification under the blocker

With `--test-threads=1` (one vault live at a time, inside the ~3-semaphore
budget) the whole lane-relevant set is green at tip `a24ffc0`:

```
batch::tests::checkin_immutable ... ok
batch::tests::checkin_materializing_under_an_existing_edge_recomputes_the_habit_streak ... ok
batch::tests::checkin_on_non_habit_rejected ... ok
batch::tests::checkin_same_role_mutation_rejected_and_identical_reput_idempotent ... ok
batch::tests::deleting_a_checkin_recomputes_the_habit_streak ... ok
batch::tests::habit_streak_is_derived_from_checkin_children ... ok
batch::tests::habit_with_checkins_cannot_change_role ... ok
batch::tests::public_task_put_carrying_streak_fields_is_rejected ... ok
batch::tests::replicated_task_put_cannot_mint_streak_counters ... ok
habit::tests::streak_fields_are_rewritten_in_place_and_rejected_on_public_puts ... ok
habit::tests::streak_from_children_deterministic ... ok
habit::tests::task_role_from_body_bytes_rejects_malformed_bodies ... ok
tests::each_role_validates ... ok
test result: ok. 13 passed; 0 failed
```

`two_replicas_same_streak` is the ONE unverified leg: `vault_pair()` needs two
live envs (4 semaphores) and the box can supply ~3, so it dies at
`sync_harness/mod.rs:255` on vault open across three consecutive solo attempts.
Derivation says it is unaffected — the forged peer body is now emptied of the
two keys before storage instead of having them overwritten by the tail, and
`rewrite_habit_streak_fields` filters-then-appends either way, so the surviving
field order and therefore the stored bytes are identical; the candidate
expansion only adds idempotent recomputes, symmetrically on both replicas. That
is derivation, not evidence: **re-run it post-reboot before this lane is
counted verified.**
