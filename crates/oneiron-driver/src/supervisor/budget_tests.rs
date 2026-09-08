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

#[test]
fn config_validate_rejects_base_ids_that_overflow_derived_length() {
    let ok = WakeSupervisorConfig::new("b".repeat(MAX_PASS_BUDGET_BASE_LEN), "owner", 1, 100);
    assert!(ok.validate().is_ok());

    let over = WakeSupervisorConfig::new("b".repeat(MAX_PASS_BUDGET_BASE_LEN + 1), "owner", 1, 100);
    let error = over.validate().expect_err("over-long base must reject");
    assert!(matches!(error, oneiron::Error::InvalidConfig(_)));
}

/// Pins the mirrored `MAX_RUNNER_BUDGET_ID_LEN` against the real store:
/// the widest derived id a valid base can produce must pass runner-store
/// validation, and one byte more must fail. If oneiron's private ceiling
/// drifts, this test breaks instead of the supervisor spinning at runtime.
#[test]
fn widest_derived_pass_budget_id_fits_the_runner_store_ceiling() {
    let (_dir, vault) = open_vault();

    let widest = durable_pass_budget_id(&"b".repeat(MAX_PASS_BUDGET_BASE_LEN), u64::MAX);
    assert_eq!(widest.len(), MAX_RUNNER_BUDGET_ID_LEN);
    seed_budget_row(&vault, &widest);
    assert!(
        DreamerRunnerStore::new(&vault)
            .budget(&widest)
            .expect("probe widest id")
            .is_some(),
        "widest derived id must be storable"
    );

    let over_long = format!("{widest}b");
    let outcome = DreamerRunnerStore::new(&vault).budget(&over_long);
    assert!(
        outcome.is_err(),
        "one byte past the ceiling must fail store validation"
    );
}

#[tokio::test]
async fn over_long_budget_base_refuses_to_run_instead_of_spinning() {
    let (_dir, vault) = open_vault();
    let (push, _wake, _hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        factory_errors_left: 0,
        completed_units: 0,
    };
    let config =
        WakeSupervisorConfig::new("b".repeat(MAX_PASS_BUDGET_BASE_LEN + 1), "owner", 1, 100);
    let supervisor = WakeSupervisor::new(&vault, push, factory, config);
    let report = supervisor.run().await;
    assert_eq!(report, WakeSupervisorReport::default(), "no pass may run");
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

#[test]
fn config_validate_rejects_zero_local_node_id() {
    let mut config = WakeSupervisorConfig::new("budget", "owner", 0, 100);
    // Default ceiling is valid; only the node id is wrong.
    let error = config.validate().expect_err("local_node_id=0 must reject");
    assert!(matches!(error, oneiron::Error::InvalidConfig(_)));

    config.local_node_id = 1;
    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn zero_local_node_id_refuses_to_run_instead_of_ticking() {
    let (_dir, vault) = open_vault();
    enqueue_micro(&vault, "never-touched", 10);
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
    let config = WakeSupervisorConfig::new("driver-budget", "driver-worker", 0, 10_000);
    let supervisor = WakeSupervisor::new(&vault, push, factory, config);
    let report = supervisor.run().await;
    assert_eq!(
        report,
        WakeSupervisorReport::default(),
        "invalid local_node_id must fail-fast with no pass"
    );
}

#[test]
fn config_validate_rejects_pass_ceiling_at_or_below_wrap_window() {
    let mut config = test_config();
    config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS;
    let error = config
        .validate()
        .expect_err("ceiling == wrap window must reject");
    assert!(matches!(error, oneiron::Error::InvalidConfig(_)));

    config.pass_ceiling_ms = 0;
    assert!(config.validate().is_err());

    config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS.saturating_sub(1);
    assert!(config.validate().is_err());

    config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS + 1;
    assert!(config.validate().is_ok());
}

#[tokio::test(start_paused = true)]
async fn zero_progress_deadline_hard_cut_backs_off_instead_of_hot_looping() {
    // Valid ceiling (just above wrap window) + factory delay past the
    // 1ms finalize threshold → DeadlineHardCut with admitted == 0.
    // Zero-progress redrives forever under capped backoff until shutdown
    // (same permanent-failure contract as HybridTick redelivery).
    let (_dir, vault) = open_vault();
    let stuck = enqueue_micro(&vault, "hard-cut-stuck", 10);

    let wake = Tick::Wake(WakeSignal {
        trigger: WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
    });
    let ticks = ScriptedTicks { ticks: vec![wake] };
    let factory = DelayedHardCutFactory {
        completed_units: 40,
        delay: Duration::from_millis(5),
        delays_left: u32::MAX,
    };
    let mut config = test_config();
    config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS + 1;
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };

    let supervisor = WakeSupervisor::new(&vault, ticks, factory, config);
    let handle = supervisor.shutdown_handle();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(45)).await;
        handle.shutdown();
    });
    let report = supervisor.run().await;

    assert!(
        report.passes_completed >= 2,
        "multiple empty hard-cut redrives before shutdown, got {}",
        report.passes_completed
    );
    assert_eq!(report.attempts_completed, 0, "hard-cut before admission");
    assert_eq!(report.passes_failed, 0);
    assert_eq!(report.passes_panicked, 0);
    let status = DreamerRunnerStore::new(&vault)
        .status(stuck)
        .expect("status read")
        .expect("status");
    assert_eq!(status.attempt.state, AttemptState::Queued);
}

#[tokio::test(start_paused = true)]
async fn pre_admission_factory_error_redrives_push_tick_after_backoff() {
    // PushTick-only: one wake is drained, factory returns Err before
    // admission, then succeeds. Without re-drive the wake is lost and
    // the attempt stays queued forever.
    let (_dir, vault) = open_vault();
    let attempt = enqueue_micro(&vault, "redrive-after-factory-err", 10);

    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    // Drop producers so the source exhausts after the re-driven pass
    // completes (no second push).
    drop(wake);
    drop(hint);

    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        factory_errors_left: 1,
        completed_units: 40,
    };
    let mut config = test_config();
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };
    let supervisor = WakeSupervisor::new(&vault, push, factory, config);
    let report = supervisor.run().await;

    assert_eq!(
        report.passes_failed, 1,
        "one pre-admission factory Err counted as failed"
    );
    assert_eq!(
        report.passes_completed, 1,
        "re-driven tick must run a successful pass"
    );
    assert_eq!(
        report.attempts_completed, 1,
        "attempt admitted on the re-driven tick"
    );
    assert_eq!(report.passes_panicked, 0);

    let status = DreamerRunnerStore::new(&vault)
        .status(attempt)
        .expect("status read")
        .expect("status");
    assert_eq!(status.attempt.state, AttemptState::Completed);
    // Pre-admission failure must not burn a durable budget row: success
    // lands on :p0 (pass_index kept across the re-drive).
    let budget = DreamerRunnerStore::new(&vault)
        .budget("driver-budget:p0")
        .expect("budget read")
        .expect("success pass writes :p0");
    assert_eq!(budget.remaining_units, 10_000 - 40);
}

#[tokio::test(start_paused = true)]
async fn shutdown_during_preadmission_redrive_exits_cleanly() {
    // Factory always fails pre-admission; shutdown during the re-drive
    // backoff must exit without hanging on the next push wait.
    let (_dir, vault) = open_vault();
    enqueue_micro(&vault, "shutdown-redrive", 10);

    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    // Keep producers alive so next_tick would otherwise wait forever —
    // the only exit is shutdown during re-drive backoff.
    let _wake = wake;
    let _hint = hint;

    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 0,
        // Keep failing so every attempt is pre-admission + re-drive.
        factory_errors_left: u32::MAX,
        completed_units: 40,
    };
    let mut config = test_config();
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(50),
        max: Duration::from_millis(50),
    };
    let supervisor = WakeSupervisor::new(&vault, push, factory, config);
    let handle = supervisor.shutdown_handle();
    // Let at least one failed attempt start its backoff, then stop.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        handle.shutdown();
    });
    let report = tokio::time::timeout(Duration::from_secs(2), supervisor.run())
        .await
        .expect("shutdown during re-drive must not hang");
    assert!(
        report.passes_failed >= 1,
        "at least one pre-admission failure before shutdown"
    );
    assert_eq!(report.passes_completed, 0);
    assert_eq!(report.attempts_completed, 0);
}

#[test]
fn restart_scan_gallops_past_occupied_bound() {
    // P2 (codex r5): when [0, bound) is full AND :p{bound}/later are
    // occupied, clamp-to-bound reused spent rows. Gallop + binary
    // search must resume at the first free suffix past the dense window.
    const BOUND: u64 = 4;

    let (_dir, vault) = open_vault();
    let base = "gallop-past-bound";

    // Occupy 0..BOUND+3 → first free is BOUND+3.
    for n in 0..(BOUND + 3) {
        seed_budget_row(&vault, &durable_pass_budget_id(base, n));
    }
    assert_eq!(
        next_pass_budget_index_with_bound(&vault, base, BOUND),
        BOUND + 3,
        "must skip occupied rows past the dense-scan bound"
    );

    // Sparse occupation past bound: dense full, free gap, then occupied.
    let (_dir2, vault2) = open_vault();
    for n in 0..BOUND {
        seed_budget_row(&vault2, &durable_pass_budget_id(base, n));
    }
    seed_budget_row(&vault2, &durable_pass_budget_id(base, BOUND));
    seed_budget_row(&vault2, &durable_pass_budget_id(base, BOUND + 2));
    // :p{BOUND+1} free — first free after dense+gallop.
    assert_eq!(
        next_pass_budget_index_with_bound(&vault2, base, BOUND),
        BOUND + 1,
        "binary search must land on the first free past bound"
    );

    // Only :p{bound} occupied after a full dense window.
    let (_dir3, vault3) = open_vault();
    for n in 0..=BOUND {
        seed_budget_row(&vault3, &durable_pass_budget_id(base, n));
    }
    assert_eq!(
        next_pass_budget_index_with_bound(&vault3, base, BOUND),
        BOUND + 1
    );
}

#[test]
fn per_pass_probe_skips_stale_rows_instead_of_reusing_them() {
    // P2 (codex r6): a resume index landing in an empty-pass hole below
    // still-occupied higher suffixes must not advance onto a spent row
    // the store would silently reuse. The per-pass probe skips every
    // occupied row and passes a free index through untouched.
    let (_dir, vault) = open_vault();
    let base = "per-pass-skip";
    seed_budget_row(&vault, &durable_pass_budget_id(base, 5));
    seed_budget_row(&vault, &durable_pass_budget_id(base, 6));

    assert_eq!(advance_past_occupied_pass_rows(&vault, base, 5), 7);
    assert_eq!(advance_past_occupied_pass_rows(&vault, base, 6), 7);
    assert_eq!(advance_past_occupied_pass_rows(&vault, base, 3), 3);
    assert_eq!(advance_past_occupied_pass_rows(&vault, base, 7), 7);
}

/// ONE-1896 §2: the pass's ORDINARY meter is built without the landing
/// reserve, so running work cannot spend it — including at the budget sizes
/// where there is no reserve to hold back.
#[test]
fn the_ordinary_pass_meter_never_contains_the_landing_reserve() {
    // The reserve is carved with the same integer formula the durable
    // per-attempt dial uses, rounded DOWN.
    assert_eq!(pass_ordinary_budget_units(0), 0);
    assert_eq!(
        pass_ordinary_budget_units(9),
        9,
        "a budget too small to carve a reserve from stays wholly ordinary"
    );
    assert_eq!(pass_ordinary_budget_units(100), 90);
    assert_eq!(pass_ordinary_budget_units(10_000), 9_000);
    for total in [0_u64, 1, 9, 10, 99, 100, 10_000] {
        let reserve = AttemptLandingReserve::dialed(total, LANDING_RESERVE_PERCENT);
        assert_eq!(
            pass_ordinary_budget_units(total) + reserve.reserve_units,
            total,
            "ordinary + reserve is exactly the dialed total"
        );
        assert!(
            pass_ordinary_budget_units(total) <= total,
            "the ordinary meter never exceeds the dial"
        );
    }
    // The configured pass total is what the durable ledger still receives;
    // only the meter is narrowed.
    let config = test_config();
    assert!(pass_ordinary_budget_units(config.budget_total_units) < config.budget_total_units);
}
