//! FIX 21927: in one Meso wake window, a slot whose extraction prefix ended
//! finishes at once and lands, while its slow sibling's prefix still runs
//! into the finalize window.
//!
//! Run on a build host:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test dreamer_window_finish_order`
#![cfg(oneiron_test_support)]

use oneiron::test_doors::dreamer_partition_window;

#[test]
fn meso_window_lands_ready_slot_before_slow_sibling_prefix_ends() {
    let run = oneiron::test_doors::dreamer_partition_window::meso_window_finish()
        .expect("the two-partition Meso wake pass ends");
    assert_eq!(
        run.labels,
        ["parked:checkpoint", "landed"],
        "model calls: {:?}",
        run.calls
    );
}

#[test]
fn meso_window_stop_drops_early_finish_conflict_rows() {
    let run = dreamer_partition_window::meso_window_stop_drops_early_finish_conflict_rows()
        .expect("the stopped Meso window returns its durable readings");
    assert!(run.judge_answered, "model calls: {:?}", run.calls);
    assert!(run.executor_panicked, "model calls: {:?}", run.calls);
    assert_eq!(
        run.labels[1], "parked:retry",
        "model calls: {:?}",
        run.calls
    );
    assert_eq!(
        run.second_park_reason.as_deref(),
        Some("partition window stopped after an executor panic"),
        "model calls: {:?}",
        run.calls
    );
    assert_eq!(run.open_conflict_markers, 0, "model calls: {:?}", run.calls);
    assert_eq!(run.contradiction_gaps, 0, "model calls: {:?}", run.calls);
}

#[test]
fn meso_window_publishes_early_finish_conflict_rows_at_settle() {
    let run =
        dreamer_partition_window::meso_window_publishes_early_finish_conflict_rows_at_settle()
            .expect("the Meso window publishes its ready slot's conflict rows");
    assert!(run.judge_answered, "model calls: {:?}", run.calls);
    assert!(!run.executor_panicked, "model calls: {:?}", run.calls);
    assert_eq!(
        run.labels,
        ["parked:checkpoint", "completed-empty"],
        "model calls: {:?}",
        run.calls
    );
    assert_eq!(run.second_park_reason, None, "model calls: {:?}", run.calls);
    assert_eq!(run.open_conflict_markers, 1, "model calls: {:?}", run.calls);
    assert_eq!(run.contradiction_gaps, 1, "model calls: {:?}", run.calls);
}
