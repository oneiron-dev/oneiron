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
