#![cfg(oneiron_test_support)]
// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! L7-41: an own device's burst its home held lands by the home's own drain
//! once the device's rate is back at its baseline, with no human step
//! (arch-0023b `#decision-federation-26`: "Defer replays the burst later";
//! "It never pauses for a human"). Its batch then reads Imported, and the
//! drain does not hand it back again.
//!
//! A held burst whose delta builds on the home's own window operations names
//! the rows the home's admission read it as inserting, so a hard erase of
//! one of them scrubs its held bytes (#9226 review round 2).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support
//! --no-fail-fast --test device_burst_replay`.

#[path = "support/device_burst_home.rs"]
mod device_burst_home;
#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use device_burst_home::{
    BURST_ROWS, Device, Home, WINDOW, eventually, held_answer, operations, send_update,
};
use engine_stack::run_on_engine_stack;
use oneiron::DeleteReason;
use oneiron::sync::WindowKey;
use oneiron::sync::federation_burst::{
    DeviceBurstAdmission, DevicePeer, FederationBurstDisposition, FederationBurstWorkState,
    admit_device_window_update,
};
use oneiron_server::test_doors::device_burst_drain::drain_device_bursts_once;

#[test]
fn a_held_device_burst_lands_by_its_homes_drain_without_a_human() {
    run_on_engine_stack("device-burst-replay", held_burst_lands_by_drain);
}

async fn held_burst_lands_by_drain() {
    let device = Device::new();
    let (trickle, trickle_rows) = device.rows_update(1);
    let (burst, burst_rows) = device.rows_update(BURST_ROWS);
    let home = Home::new(DevicePeer::Unproven, operations(&trickle)).await;
    let mut socket = home.connect_root().await;
    send_update(&mut socket, &trickle).await;
    assert!(
        eventually(|| home.held_rows(&trickle_rows) == 1).await,
        "the trickle lands at the home"
    );
    send_update(&mut socket, &burst).await;
    assert!(
        held_answer(&mut socket).await,
        "the home answers the burst over the device's baseline as held"
    );
    assert_eq!(
        home.held_rows(&burst_rows),
        0,
        "the held burst lands nothing"
    );
    let key = WindowKey::try_new(WINDOW).unwrap();
    let batch_ref =
        match admit_device_window_update(&home.vault, &DevicePeer::Unproven, &key, &burst, &[])
            .unwrap()
        {
            DeviceBurstAdmission::Defer { batch_ref } => batch_ref,
            other => panic!("the retained burst is held: {other:?}"),
        };

    // In the burst's own second the device's rate is over its baseline: the
    // drain lands nothing.
    assert_eq!(drain_device_bursts_once(&home.server).await.unwrap(), 0);
    assert_eq!(
        home.held_rows(&burst_rows),
        0,
        "nothing is due in the burst's second"
    );

    // Two seconds on, its rate is back at its baseline: one pass lands the
    // whole burst, with no human step, and ends its batch Imported.
    home.clock.set(home.now + 2);
    assert_eq!(
        drain_device_bursts_once(&home.server).await.unwrap(),
        1,
        "the drain lands the held burst"
    );
    assert!(
        eventually(|| home.held_rows(&burst_rows) == BURST_ROWS).await,
        "every row of the held burst lands at the home: {} of {BURST_ROWS}",
        home.held_rows(&burst_rows)
    );
    let landed = home.receipt(DevicePeer::Unproven, &batch_ref);
    assert_eq!(landed.state, FederationBurstWorkState::Imported);
    assert_eq!(
        landed.disposition,
        FederationBurstDisposition::Defer {
            replay_ref: batch_ref.clone()
        }
    );
    assert_eq!(
        drain_device_bursts_once(&home.server).await.unwrap(),
        0,
        "a landed batch is not handed back again"
    );
}

/// Case 4 of BURST-REPLAY-ROUND2-TESTS (#9226 review round 2, P1 4): the
/// device's burst edits a row its trickle added and adds more, so its
/// operations build on the trickle's, which the home holds. The home names
/// the rows its admission read the burst as inserting on the home window as
/// the held bytes' rows, so the owner's hard erase of the edited row scrubs
/// them: the batch ends Erased, and the drain lands nothing of it. Red at
/// 9cc1dbcc293d, which named only the rows an import of the burst into an
/// empty document applies: none, as its operations wait on the trickle's.
#[test]
fn a_held_delta_over_the_homes_operations_is_scrubbed_by_a_hard_erase_of_its_row() {
    run_on_engine_stack("device-burst-erase", held_delta_scrubbed_by_erase);
}

async fn held_delta_scrubbed_by_erase() {
    let device = Device::new();
    let (trickle, trickle_rows) = device.rows_update(1);
    let edited = trickle_rows[0];
    let (burst, burst_rows) = device.edit_and_rows_update(edited, BURST_ROWS);
    let home = Home::new(DevicePeer::Unproven, operations(&trickle)).await;
    let mut socket = home.connect_root().await;
    send_update(&mut socket, &trickle).await;
    assert!(
        eventually(|| home.held_rows(&trickle_rows) == 1).await,
        "the trickle lands at the home"
    );
    send_update(&mut socket, &burst).await;
    assert!(
        held_answer(&mut socket).await,
        "the home answers the burst over the device's baseline as held"
    );
    let key = WindowKey::try_new(WINDOW).unwrap();
    let batch_ref =
        match admit_device_window_update(&home.vault, &DevicePeer::Unproven, &key, &burst, &[])
            .unwrap()
        {
            DeviceBurstAdmission::Defer { batch_ref } => batch_ref,
            other => panic!("the retained burst is held: {other:?}"),
        };
    assert_eq!(
        home.receipt(DevicePeer::Unproven, &batch_ref).state,
        FederationBurstWorkState::Pending
    );

    // The owner hard-erases the row the burst edits. A hard erase signs its
    // redaction receipt with this install's key.
    home.vault
        .install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let erased = home
        .vault
        .delete_entity_with_reason(&edited, DeleteReason::UserHardDelete)
        .unwrap();
    assert!(erased.existed, "the trickle's row is held at the home");
    assert_eq!(
        home.receipt(DevicePeer::Unproven, &batch_ref).state,
        FederationBurstWorkState::Erased,
        "the hard erase of a row the held burst edits scrubs the held bytes"
    );

    // Two seconds on, the device's rate is back at its baseline: the drain
    // has nothing of the scrubbed burst to land.
    home.clock.set(home.now + 2);
    assert_eq!(drain_device_bursts_once(&home.server).await.unwrap(), 0);
    assert_eq!(
        home.held_rows(&burst_rows),
        0,
        "no row of the scrubbed burst lands"
    );
}
