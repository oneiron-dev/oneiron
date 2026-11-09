//! Durable budget-id, index-scan, and config-validation tests.
use std::time::Duration;

use super::*;
use crate::tick::{PushTick, Tick, WakeSignal};
use oneiron::attempt_queue::{AttemptLandingReserve, AttemptState, LANDING_RESERVE_PERCENT};
use oneiron::{
    DREAMER_GRACEFUL_WRAP_WINDOW_MS, DreamerConsolidationScope, DreamerRunnerStore, WakeTrigger,
};

#[test]
fn durable_pass_budget_id_is_deterministic_per_index() {
    assert_eq!(durable_pass_budget_id("wake", 0), "wake:p0");
    assert_eq!(durable_pass_budget_id("wake", 1), "wake:p1");
    assert_eq!(
        durable_pass_budget_id("driver-budget", 42),
        "driver-budget:p42"
    );
}

#[tokio::test]
async fn restart_resumes_pass_budget_index_after_existing_rows() {
    // P1 (codex r3/r4): pass_index was in-memory only and reset to 0 on
    // every WakeSupervisor::run, so a process restart re-minted :p0
    // against a spent row (DreamerRunnerStore reuses existing budgets).
    // Startup scan must resume at highest-occupied + 1 (here :p2).
    let (_dir, vault) = open_vault();
    let first = enqueue_micro(&vault, "restart-p0", 10);
    let second = enqueue_micro(&vault, "restart-p1", 11);

    let wake = Tick::Wake(WakeSignal {
        trigger: WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
    });
    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        factory_errors_left: 0,
        completed_units: 100,
    };
    let mut config = test_config();
    config.budget_total_units = 150;
    config.reserve_units = 100;

    // First supervisor "run" (pre-restart): exhausts :p0 and :p1.
    let ticks = ScriptedTicks {
        ticks: vec![wake, wake],
    };
    let report = WakeSupervisor::new(&vault, ticks, factory, config.clone())
        .run()
        .await;
    assert_eq!(report.passes_completed, 2);
    assert_eq!(report.attempts_completed, 2);

    let store = DreamerRunnerStore::new(&vault);
    assert!(
        store.budget("driver-budget:p0").expect("p0").is_some(),
        "first run wrote :p0"
    );
    assert!(
        store.budget("driver-budget:p1").expect("p1").is_some(),
        "first run wrote :p1"
    );
    assert!(
        store.budget("driver-budget:p2").expect("p2").is_none(),
        "first run must not have touched :p2"
    );
    for id in [first, second] {
        let status = store.status(id).expect("status").expect("row");
        assert_eq!(status.attempt.state, AttemptState::Completed);
    }

    // Simulated restart: new supervisor instance, same base budget_id,
    // one queued attempt — must mint :p2 (not walk :p0/:p1 spent rows).
    let third = enqueue_micro(&vault, "restart-p2", 12);
    let ticks = ScriptedTicks { ticks: vec![wake] };
    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        factory_errors_left: 0,
        completed_units: 40,
    };
    // Fresh grant large enough for one attempt under the restarted pass.
    let mut restart_config = config;
    restart_config.budget_total_units = 10_000;
    let report = WakeSupervisor::new(&vault, ticks, factory, restart_config)
        .run()
        .await;

    assert_eq!(report.passes_completed, 1);
    assert_eq!(
        report.attempts_completed, 1,
        "restarted supervisor must drain under a fresh :p2 row"
    );
    assert_eq!(report.passes_failed, 0);
    assert_eq!(report.passes_panicked, 0);

    let status = store.status(third).expect("status").expect("row");
    assert_eq!(status.attempt.state, AttemptState::Completed);
    let budget = store
        .budget("driver-budget:p2")
        .expect("p2 read")
        .expect("restart must write driver-budget:p2");
    assert_eq!(budget.reserved_units, 0);
    assert_eq!(budget.remaining_units, 10_000 - 40);
    assert_eq!(budget.total_units, 10_000);
    // Spent pre-restart rows must not have been rewritten as the
    // restart pass's working counter (still the 150-unit grant).
    let p0 = store
        .budget("driver-budget:p0")
        .expect("p0")
        .expect("p0 still present");
    assert_eq!(p0.total_units, 150);
    assert_eq!(p0.remaining_units, 50);
}

#[test]
fn pass_budget_index_scan_is_bounded_and_falls_back() {
    // Highest-occupied + 1: dense-scan [0, bound). When every index in
    // [0, bound) already has a durable row and :p{bound} is free, the
    // scan returns `bound` (first free past the dense window). Production
    // uses PASS_BUDGET_INDEX_SCAN_BOUND; tests pin a tiny bound.
    const BOUND: u64 = 4;

    let (_dir, vault) = open_vault();
    let base = "scan-bound-budget";

    assert_eq!(
        next_pass_budget_index_with_bound(&vault, base, BOUND),
        0,
        "empty vault starts at p0"
    );

    for n in 0..BOUND {
        seed_budget_row(&vault, &durable_pass_budget_id(base, n));
    }
    assert_eq!(
        next_pass_budget_index_with_bound(&vault, base, BOUND),
        BOUND,
        "full [0, bound) with free :p{{bound}} resumes at bound"
    );

    // Empty :p0 (hole) with only :p1 occupied — the r4 collision:
    // first-absent would return 0 and later collide with stale :p1;
    // highest-occupied + 1 resumes at p2.
    let (_dir_hole, vault_hole) = open_vault();
    seed_budget_row(&vault_hole, &durable_pass_budget_id(base, 1));
    assert_eq!(
        next_pass_budget_index_with_bound(&vault_hole, base, BOUND),
        2,
        "hole at p0 with occupied p1 → start at p2, not p0/p1"
    );

    // Hole at p1 while p0 and p2 exist: skip the hole, resume after max.
    let (_dir2, vault2) = open_vault();
    seed_budget_row(&vault2, &durable_pass_budget_id(base, 0));
    seed_budget_row(&vault2, &durable_pass_budget_id(base, 2));
    assert_eq!(
        next_pass_budget_index_with_bound(&vault2, base, BOUND),
        3,
        "hole at p1 with occupied p2 → start at p3 (highest+1), not p1"
    );

    // Production bound is the large fixed constant (inspectable).
    assert_eq!(PASS_BUDGET_INDEX_SCAN_BOUND, 65_536);
}

#[tokio::test]
async fn zero_local_node_id_refuses_to_run_instead_of_ticking() {
    let (_dir, vault) = open_vault();
    enqueue_micro(&vault, "never-touched", 10);
    let (push, wake, hint) = PushTick::channel(crate::TEST_SESSION_IDLE_FLOOR_SECS * 1_000);
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
    let config = WakeSupervisorConfig::new("driver-budget", "driver-worker", 0, 10_000);
    let supervisor = WakeSupervisor::new(&vault, push, factory, config);
    let report = supervisor.run().await;
    assert_eq!(
        report,
        WakeSupervisorReport::default(),
        "invalid local_node_id must fail-fast with no pass"
    );
}

