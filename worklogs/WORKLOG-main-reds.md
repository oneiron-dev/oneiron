# WORKLOG — main base-reds (mech-fix)

Three reds that live on `main` itself and therefore fail the full-verify stage
of every lane cut from it. A fourth of the same class was found while
reproducing R2 and is folded in (see PACKET note at the end).

Worktree: `/Volumes/Cinema/w5-lt/mech-reds` · branch `w5/main-reds`
(cut from `f5fce021d` = `origin/main` at ONE-1791 / #591; rebased onto
`929b7ba73` = ONE-1436 / #592 after that landed mid-run — no conflicts, the two
file sets are disjoint, and #592 adds no fmt or clippy red of its own)

## R1 — `cargo fmt --check` red · `crates/oneiron/src/surface_event/tests.rs`

`surface_event_retry_mints_a_fresh_attempt` carried a 105-column assertion
line from #589:

```rust
assert_eq!(row.retry_of.map(|id| SurfaceEventAttemptRef::from_attempt_id(id)), Some(ack.attempt_ref));
```

The same line is also a `clippy::redundant_closure` red under `-D warnings`
(surfaced by the R2 run), so both are one defect: the closure is a bare
forwarding wrapper. Passing the associated function directly removes the
closure and shortens the line enough that rustfmt's own wrapping is stable:

```rust
assert_eq!(
    row.retry_of.map(SurfaceEventAttemptRef::from_attempt_id),
    Some(ack.attempt_ref)
);
```

No assertion semantics changed — `from_attempt_id` takes `AttemptId` by value,
so `Option::map` calls exactly what the closure called.

## R2 — `clippy::redundant_clone` red · `crates/oneiron/src/identity_topology/tests.rs`

`applied_counts_are_bounded_by_the_map_and_the_consent_axis` cloned `residue`
at its LAST use (the `assign` arm below it is what continues on), which
`redundant_clone` is `deny`-level for in `[workspace.lints.clippy]`. The clone
is dropped and `residue` is moved; rustfmt then collapses the call to one line.

## R3 — flake · `attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`

Symptom: intermittent `cleanup span records=[]` — the `TelemetryCapture`
subscriber recorded **nothing at all**, not a span with wrong fields.
Reproduced at **3/30** on `--lib attempt_queue` alone (56 passed / 1 failed),
matching the report.

### Mechanism (tracing 0.1.44 / tracing-core 0.1.36)

`tracing` caches one `Interest` per callsite **process-globally**, but
`tracing::subscriber::with_default` installs a subscriber on **one thread**.
The two do not compose:

- `tracing_core::callsite::DefaultCallsite::register` (`callsite.rs`) computes
  the cached `Interest` via `rebuild_callsite_interest(self, &DISPATCHERS.rebuilder())`.
- `Dispatchers::rebuilder()` returns `Rebuilder::JustOne` while at most one
  `Dispatch` has ever been registered — which is the case in this test binary,
  since this test is the only `Dispatch::new` in the crate.
- `Rebuilder::JustOne::for_each` resolves the subscriber with
  `dispatcher::get_default(f)` — **the registering thread's thread-local
  default**, not the global registrar list.

So the first thread to reach the `attempt_queue_cleanup` callsite decides its
interest for the whole process. `AttemptQueue::cleanup_leases` calls
`emit_attempt_queue_cleanup_span` unconditionally and is exercised by several
other tests running in parallel with no subscriber attached; when one of them
wins, `NoSubscriber` yields `Interest::never()`, the callsite is pinned to
never, and this test's emission is discarded before the subscriber is ever
consulted. Registration-order dependent, hence intermittent.

(Before this test's `Dispatch::new` nothing can register at all: `MAX_LEVEL`
starts at `OFF`, so `level_enabled!` short-circuits every macro. The race
window is exactly `Dispatch::new` → this test's own emission, which is one
`cleanup_leases` call wide.)

### Fix (registration-order independent, no serialization, no retry)

Inside the `with_default` scope, before the call under test:

1. `emit_attempt_queue_cleanup_span(...)` once with a default report — forces
   both callsites (span + event) to the terminal `REGISTERED` state no matter
   which thread wins the race. `DefaultCallsite::register` is one-shot
   (`interest()` only calls it while the cache is the `0xFF` sentinel), so
   after this **no other thread can ever write these callsites' interest again**.
2. `tracing::callsite::rebuild_interest_cache()` — recomputes every registered
   callsite's `Interest` on *this* thread, i.e. against *this* subscriber, so a
   callsite already poisoned to `never` by step 0 is repaired.
3. Clear the captured records so the assertions still see only the real call.

Neither step depends on ordering: (1) makes the state terminal, (2) makes it
correct. The six-caller serialization alternative was rejected — it is a lock
every future `cleanup_leases` test must remember, and it does not remove the
mechanism.

The warm-up touches no queue state (it calls the emitter directly with
`AttemptQueueCleanupReport::default()`), so the assertions still describe the
one real `cleanup_leases(now: 40, lease_timeout_secs: 10)` call.

### Evidence

| tree | run | result |
|---|---|---|
| pre-fix (base `f5fce021d`) | `--lib attempt_queue` ×30 | **3 failed** (`records=[]`), 27 ok |
| post-fix (base `f5fce021d`) | `--lib attempt_queue` ×30 | **0 failed** |
| post-fix (base `f5fce021d`) | full `--lib` ×2 | 3445 passed, 0 failed, 17 ignored |
| post-rebase (base `929b7ba73`) | `--lib attempt_queue` ×5 | **0 failed** |
| post-rebase (base `929b7ba73`) | full `--lib` ×2 | 3451 passed, 0 failed, 17 ignored |

The pre-fix failure is the same binary rebuilt with only this test's body
reverted, so the 3/30 → 0/35 delta is attributable to the fix alone.

## Gates (on the final rebased tree)

- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean
  (zero warnings, zero errors).
- `cargo test -p oneiron --all-features` — exit 0, 42 targets,
  **3778 passed, 0 failed, 71 ignored**, no `FAILED` / `failures:` marker in the
  log. Lib target alone: 3451 passed, 0 failed, 17 ignored.

No `Cargo.toml` or `Cargo.lock` change. Nothing pushed — the branch is held
locally at `w5/main-reds`.

## PACKET note — one file outside the assigned three

`crates/oneiron/tests/campaign_claim_gate_oracle.rs:87` is a fourth base-red of
the same class: `clippy::needless_borrows_for_generic_args` on
`&format!("outbound:{intent_ref}")`, introduced by #587 (ONE-1772). It is an
`error` under `-D warnings` and it aborts the clippy build **before** the lib
target is reached, so the clippy gate cannot be shown green without it. Fixed
by dropping the `&` (one character); flagged here as a `PACKET_AMEND` request
rather than left red.
