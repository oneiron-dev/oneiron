//! FIX 21927: in one Meso wake window, a slot whose extraction prefix ended
//! finishes at once and lands, while its slow sibling's prefix still runs
//! into the finalize window.
//!
//! Run on a build host:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test dreamer_window_finish_order`
#![cfg(oneiron_test_support)]

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
