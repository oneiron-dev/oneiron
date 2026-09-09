//! Loop, panic-containment, shutdown, and redrive acceptance tests.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::tick::{PushTick, Tick, WakeSignal};
use oneiron::attempt_queue::AttemptState;
use oneiron::{
    BudgetGuard, DREAMER_EXECUTOR_ERROR_PARK_REASON, DreamerAdmittedAttempt,
    DreamerAttemptExecution, DreamerAttemptExecutor, DreamerConsolidationScope, DreamerRunnerStore,
    Result, WakeAttemptContext, WakeTrigger,
};

#[test]
fn hint_ticks_map_to_least_privileged_pass_shape() {
    let (scope, trigger) = pass_shape(&Tick::Hint(crate::tick::HintSignal::default()));
    assert_eq!(scope, DreamerConsolidationScope::Micro);
    assert_eq!(trigger, WakeTrigger::Event);
}

#[test]
fn session_hint_ticks_carry_no_pass_shaping_authority() {
    // H-S4 (ONE-1685): a lifecycle fact on a hint never escalates the
    // pass it provokes — even "explicit end" maps least-privileged
    // here; the Meso consolidation on close is driver policy (a
    // DURABLE queue attempt), not producer authority.
    for hint in [
        crate::SessionHint::AppOpen,
        crate::SessionHint::Activity,
        crate::SessionHint::ExplicitEnd,
    ] {
        let (scope, trigger) = pass_shape(&Tick::Hint(crate::tick::HintSignal {
            session: Some(hint),
        }));
        assert_eq!(scope, DreamerConsolidationScope::Micro);
        assert_eq!(trigger, WakeTrigger::Event);
    }
}

#[tokio::test]
async fn supervisor_pumps_one_pass_per_wake_then_stops_when_exhausted() {
    let (_dir, vault) = open_vault();
    enqueue_micro(&vault, "driver-smoke", 10);

    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    drop(wake);
    drop(hint);

    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        factory_errors_left: 0,
        completed_units: 40,
    };
    let supervisor = WakeSupervisor::new(&vault, push, factory, test_config());
    let report = supervisor.run().await;

    assert_eq!(report.passes_completed, 1);
    assert_eq!(report.attempts_completed, 1);
    assert_eq!(report.passes_panicked, 0);
    assert_eq!(report.passes_failed, 0);

    // The pass settled its budget through the engine, not this crate.
    // Pass index 0 → durable id `{base}:p0`.
    let budget = DreamerRunnerStore::new(&vault)
        .budget("driver-budget:p0")
        .expect("budget read")
        .expect("budget row");
    assert_eq!(budget.reserved_units, 0);
    assert_eq!(budget.remaining_units, 10_000 - 40);
}

#[tokio::test(start_paused = true)]
async fn panicking_executor_parks_attempt_and_supervisor_continues() {
    // ONE-1683: an executor panic after admission used to unwind past
    // the driver's park/refund code — the supervisor's catch converted
    // it to Panicked by resolving before that bookkeeping ran, leaving
    // the attempt leased and the reservation held until external cleanup.
    // The engine now contains the panic at the attempt boundary: the attempt is
    // parked, the reservation refunded, and the pass surfaces as a
    // FAILED pass the supervisor backs off from and re-drives (same
    // consumed wake drains remaining backlog without a second push).
    let (_dir, vault) = open_vault();
    let first = enqueue_micro(&vault, "panics", 10);
    let second = enqueue_micro(&vault, "completes", 11);

    let wake = Tick::Wake(WakeSignal {
        trigger: WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
    });
    // Single wake: Failed redrives; attempt 2 completes on the redrive.
    let ticks = ScriptedTicks { ticks: vec![wake] };
    let factory = TestExecFactory {
        panics_left: 1,
        factory_panics_left: 0,
        factory_errors_left: 0,
        completed_units: 40,
    };
    let mut config = test_config();
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };
    let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
    let report = supervisor.run().await;

    assert_eq!(
        report.passes_failed, 1,
        "the contained panic surfaces as a failed pass"
    );
    assert_eq!(report.passes_panicked, 0, "nothing unwound past the driver");
    assert_eq!(
        report.passes_completed, 1,
        "redrive after backoff ran the completing pass"
    );
    assert_eq!(report.attempts_completed, 1);

    // The panicked attempt is parked under the executor-error reason, its
    // reservation refunded; the second attempt settled normally.
    let store = DreamerRunnerStore::new(&vault);
    let parked = store
        .parked_attempt(first)
        .expect("parked read")
        .expect("parked row");
    assert!(
        parked
            .reason
            .starts_with(DREAMER_EXECUTOR_ERROR_PARK_REASON),
        "park reason carries the executor-error class: {}",
        parked.reason
    );
    assert!(
        parked.reason.contains("panicked"),
        "park reason names the panic: {}",
        parked.reason
    );
    // Completing pass was pass index 1 (`:p1`); the failed pass spent
    // nothing durable after the park+refund.
    let budget = store
        .budget("driver-budget:p1")
        .expect("budget read")
        .expect("budget row");
    assert_eq!(budget.reserved_units, 0, "no reservation leaked");
    assert_eq!(budget.remaining_units, 10_000 - 40);
    let status = store.status(second).expect("status read").expect("status");
    assert_eq!(status.attempt.state, AttemptState::Completed);
}

#[tokio::test(start_paused = true)]
async fn pass_panic_outside_the_attempt_boundary_restarts_with_backoff() {
    // The supervisor-level catch stays as the backstop for panics the
    // engine cannot contain — anywhere outside exec.execute, here the
    // executor factory. Nothing is leased at that point; Panicked
    // redrives the consumed tick after backoff.
    let (_dir, vault) = open_vault();
    enqueue_micro(&vault, "factory-panics-once", 10);

    let wake = Tick::Wake(WakeSignal {
        trigger: WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
    });
    let ticks = ScriptedTicks { ticks: vec![wake] };
    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 1,
        factory_errors_left: 0,
        completed_units: 40,
    };
    let mut config = test_config();
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };
    let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
    let report = supervisor.run().await;

    assert_eq!(report.passes_panicked, 1, "the backstop caught the panic");
    assert_eq!(
        report.passes_completed, 1,
        "redrive after backoff ran the completing pass"
    );
    assert_eq!(report.attempts_completed, 1);
}

/// Completes attempts synchronously and requests supervisor shutdown from
/// inside the first execution — without an attempt-boundary yield the whole
/// backlog would drain in a single poll before the biased select! ever
/// saw the request.
struct ShutdownRequestingExec {
    handle: ShutdownHandle,
}

impl DreamerAttemptExecutor for ShutdownRequestingExec {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        self.handle.shutdown();
        Ok(DreamerAttemptExecution::Completed {
            completed_units: 40,
        })
    }
}

struct ShutdownRequestingFactory {
    handle: Arc<Mutex<Option<ShutdownHandle>>>,
}

impl PassExecutorFactory for ShutdownRequestingFactory {
    type Exec<'p> = ShutdownRequestingExec;

    fn executor<'p>(&'p mut self, _guard: &'p BudgetGuard) -> Result<ShutdownRequestingExec> {
        let handle = self
            .handle
            .lock()
            .expect("handle slot")
            .clone()
            .expect("handle wired before run");
        Ok(ShutdownRequestingExec { handle })
    }
}

#[tokio::test]
async fn shutdown_during_synchronous_pass_stops_at_the_next_attempt_boundary() {
    // ONE-1683: run_wake_pass yields once per attempt boundary, so a
    // shutdown requested while a synchronously-completing pass is
    // running raises the cancellation flag after the in-flight attempt —
    // the pass stops cooperatively instead of draining the whole queue.
    let (_dir, vault) = open_vault();
    enqueue_micro(&vault, "first", 10);
    let second = enqueue_micro(&vault, "second", 11);
    let third = enqueue_micro(&vault, "third", 12);

    let wake = Tick::Wake(WakeSignal {
        trigger: WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
    });
    let ticks = ScriptedTicks {
        ticks: vec![wake, wake],
    };
    let slot = Arc::new(Mutex::new(None));
    let factory = ShutdownRequestingFactory {
        handle: Arc::clone(&slot),
    };
    let supervisor = WakeSupervisor::new(&vault, ticks, factory, test_config());
    *slot.lock().expect("handle slot") = Some(supervisor.shutdown_handle());
    let report = supervisor.run().await;

    assert_eq!(report.passes_completed, 1);
    assert_eq!(
        report.attempts_completed, 1,
        "the pass stopped at the first attempt boundary after the request"
    );

    // The rest of the queue is untouched, ready for the next run.
    let store = DreamerRunnerStore::new(&vault);
    for id in [second, third] {
        let status = store.status(id).expect("status read").expect("status");
        assert_eq!(status.attempt.state, AttemptState::Queued, "never claimed");
    }
}

#[tokio::test]
async fn shutdown_between_passes_stops_the_loop() {
    let (_dir, vault) = open_vault();
    let (push, _wake, _hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        factory_errors_left: 0,
        completed_units: 0,
    };
    let supervisor = WakeSupervisor::new(&vault, push, factory, test_config());
    let handle = supervisor.shutdown_handle();
    handle.shutdown();
    let report = supervisor.run().await;
    assert_eq!(report.passes_completed, 0);
    assert_eq!(report.passes_failed, 0);
    assert_eq!(report.passes_panicked, 0);
    assert_eq!(report.attempts_completed, 0);
    assert_eq!(report.attempts_parked, 0);
    assert_eq!(report.attempts_landed, 0);
}

#[tokio::test]
async fn second_pass_runs_attempts_after_first_pass_budget_exhausts() {
    // P1 (codex): a static config.budget_id was shared across passes, so
    // DreamerRunnerStore's init-if-absent left pass 2 stuck on a spent
    // row. Per-pass durable ids (`{base}:p{n}`) give each pass a fresh
    // budget so remaining work drains.
    let (_dir, vault) = open_vault();
    let first = enqueue_micro(&vault, "exhaust-first", 10);
    let second = enqueue_micro(&vault, "needs-fresh-budget", 11);

    let wake = Tick::Wake(WakeSignal {
        trigger: WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
    });
    let ticks = ScriptedTicks {
        // Two passes: first exhausts after one attempt; second must still
        // be able to admit the remaining attempt.
        ticks: vec![wake, wake],
    };
    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        factory_errors_left: 0,
        // Spend 100 of the 150-unit grant so the second reservation in
        // the same pass is denied (remaining 50 < reserve 100).
        completed_units: 100,
    };
    let mut config = test_config();
    config.budget_total_units = 150;
    config.reserve_units = 100;
    // Keep default backoff for any zero-progress path; this test expects
    // productive BudgetExhausted then a fresh second pass.
    let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
    let report = supervisor.run().await;

    assert_eq!(
        report.passes_completed, 2,
        "both passes complete (first BudgetExhausted, second drains)"
    );
    assert_eq!(
        report.attempts_completed, 2,
        "second pass must admit under a fresh durable budget row"
    );
    assert_eq!(report.passes_failed, 0);
    assert_eq!(report.passes_panicked, 0);

    let store = DreamerRunnerStore::new(&vault);
    for (id, pass_id, spent) in [
        (first, "driver-budget:p0", 100u64),
        (second, "driver-budget:p1", 100u64),
    ] {
        let status = store.status(id).expect("status read").expect("status");
        assert_eq!(
            status.attempt.state,
            AttemptState::Completed,
            "attempt under {pass_id}"
        );
        let budget = store
            .budget(pass_id)
            .expect("budget read")
            .expect("per-pass budget row");
        assert_eq!(budget.reserved_units, 0);
        assert_eq!(budget.remaining_units, 150 - spent);
        assert_eq!(budget.total_units, 150);
    }
    // The static base id must NOT have been written as a shared row —
    // that was the spin root cause.
    assert!(
        store
            .budget("driver-budget")
            .expect("base budget read")
            .is_none(),
        "base budget_id is only a prefix; rows live at :p{{n}}"
    );
}

#[tokio::test(start_paused = true)]
async fn budget_exhausted_with_due_deadline_does_not_busy_loop() {
    // Regression: HybridTick re-surfaces an already-due deadline on
    // every cycle. With a shared spent budget that spun forever (hot
    // BudgetExhausted passes, zero progress). Per-pass ids let work
    // drain; zero-progress BudgetExhausted backs off so a permanently
    // un-admittable grant cannot hot-loop either.
    let (_dir, vault) = open_vault();
    let attempt_a = enqueue_micro(&vault, "due-a", 10);
    let attempt_b = enqueue_micro(&vault, "due-b", 11);

    // Attempts are due at created_at * 1000 ms; clock is far past that so
    // HybridTick short-circuits to Deadline every cycle until empty.
    let now_ms: crate::tick::NowMillis = Arc::new(|| 1_000_000);
    let timer = crate::TimerTick::with_clock(
        crate::AttemptQueueDeadlines::new(&vault, 1),
        Arc::clone(&now_ms),
    );
    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    // No push producers: once the queue is empty the hybrid source
    // exhausts and the supervisor must stop.
    drop(wake);
    drop(hint);
    let hybrid = crate::HybridTick::new(timer, push);

    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        factory_errors_left: 0,
        completed_units: 100,
    };
    let mut config = test_config();
    config.budget_total_units = 150;
    config.reserve_units = 100;
    // Tiny backoff so the zero-progress arm (if hit) is still bounded
    // under the paused clock without making the happy path wait.
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(1),
        max: Duration::from_millis(1),
    };

    let supervisor = WakeSupervisor::new(&vault, hybrid, factory, config);
    // Under the pre-fix shared-budget spin this would never resolve.
    // Bound wall-polls via a generous virtual-time cap: productive
    // draining finishes in a handful of passes.
    let report = tokio::time::timeout(Duration::from_secs(5), supervisor.run())
        .await
        .expect("supervisor must not busy-loop on due HybridTick redelivery");

    assert_eq!(
        report.attempts_completed, 2,
        "due work must drain across per-pass budgets"
    );
    // Exactly two productive passes (one attempt each under the 150-unit
    // grant) — not an unbounded series of empty BudgetExhausted polls.
    assert_eq!(report.passes_completed, 2);
    assert_eq!(report.passes_failed, 0);
    assert_eq!(report.passes_panicked, 0);

    let store = DreamerRunnerStore::new(&vault);
    for id in [attempt_a, attempt_b] {
        let status = store.status(id).expect("status read").expect("status");
        assert_eq!(
            status.attempt.state,
            AttemptState::Completed,
            "queue fully drained"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn zero_progress_budget_exhausted_backs_off_instead_of_hot_looping() {
    // Permanently un-admittable grant (total < reserve): every pass
    // hits BudgetExhausted with admitted == 0. Zero-progress backs off
    // and redrives the same tick (permanent failure = capped-backoff
    // retry forever, same contract as HybridTick redelivery). Shutdown
    // during backoff ends the loop without a hot spin.
    let (_dir, vault) = open_vault();
    let stuck = enqueue_micro(&vault, "stuck-due", 10);

    let wake = Tick::Wake(WakeSignal {
        trigger: WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
    });
    let ticks = ScriptedTicks { ticks: vec![wake] };
    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        factory_errors_left: 0,
        completed_units: 0,
    };
    let mut config = test_config();
    config.budget_total_units = 50;
    config.reserve_units = 100;
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };

    let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
    let handle = supervisor.shutdown_handle();
    // Enough virtual time for several empty redrive+backoff cycles.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(55)).await;
        handle.shutdown();
    });
    let report = supervisor.run().await;

    assert!(
        report.passes_completed >= 3,
        "multiple empty redrives before shutdown, got {}",
        report.passes_completed
    );
    assert_eq!(report.attempts_completed, 0, "nothing was admittable");
    assert_eq!(report.passes_failed, 0);
    assert_eq!(report.passes_panicked, 0);
    // Attempt remains queued — BudgetExhausted before reserve does not
    // claim or park, so the due work is still waiting for a usable grant.
    let status = DreamerRunnerStore::new(&vault)
        .status(stuck)
        .expect("status read")
        .expect("status");
    assert_eq!(status.attempt.state, AttemptState::Queued);
}
