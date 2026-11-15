// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! L7-41: an own device's write burst meets, at its home, the relative burst
//! response a federated peer's does (arch-0023b `#decision-federation-26`):
//! the home's UPDATE arm asks the burst core before anything persists. A
//! trickle at the device's baseline lands. A burst over it is answered as
//! held and lands nothing, also when the device sends the same bytes again
//! before its rate is back at its baseline; its batch stays Pending.
//!
//! Run: `cargo test --locked -p oneiron-server --all-features --features
//! oneiron/test-support --no-fail-fast --test device_burst_response`.

#[path = "support/device_burst_home.rs"]
mod device_burst_home;
#[path = "support/engine_stack.rs"]
mod engine_stack;

use device_burst_home::{
    BURST_ROWS, Device, Home, WINDOW, eventually, held_answer, operations, send_update,
};
use engine_stack::run_on_engine_stack;
use oneiron::sync::WindowKey;
use oneiron::sync::federation_burst::{
    DeviceBurstAdmission, DevicePeer, FederationBurstPeerRef, FederationBurstWorkState,
    admit_device_window_update,
};

#[test]
fn a_device_write_burst_is_held_at_its_home_and_a_trickle_lands() {
    run_on_engine_stack("device-burst-held", burst_held_and_trickle_lands);
}

async fn burst_held_and_trickle_lands() {
    let device = Device::new();
    let (trickle, trickle_rows) = device.rows_update(1);
    let (burst, burst_rows) = device.rows_update(BURST_ROWS);
    let home = Home::new(DevicePeer::Unproven, operations(&trickle)).await;
    let mut socket = home.connect_root().await;

    // One trickle update at the device's baseline lands.
    send_update(&mut socket, &trickle).await;
    assert!(
        eventually(|| home.held_rows(&trickle_rows) == 1).await,
        "the trickle lands at the home"
    );

    // A burst over it in the same second is answered as held: none of its
    // rows lands.
    send_update(&mut socket, &burst).await;
    let answered = held_answer(&mut socket).await;
    assert_eq!(
        home.held_rows(&burst_rows),
        0,
        "the burst over the device's baseline lands nothing at the home (held answer: {answered})"
    );
    assert!(answered, "the home answers the held burst with its version");

    // The device sends the same bytes again before its rate is back at its
    // baseline: held again, not landed by the resend.
    send_update(&mut socket, &burst).await;
    assert!(
        held_answer(&mut socket).await,
        "the home answers the resent burst as held"
    );
    assert_eq!(
        home.held_rows(&burst_rows),
        0,
        "the resent burst lands nothing at the home"
    );

    // Its batch waits, Pending, as the device's own.
    let key = WindowKey::try_new(WINDOW).unwrap();
    let batch_ref =
        match admit_device_window_update(&home.vault, &DevicePeer::Unproven, &key, &burst, &[])
            .unwrap()
        {
            DeviceBurstAdmission::Defer { batch_ref } => batch_ref,
            other => panic!("the retained burst is held again: {other:?}"),
        };
    let held = home.receipt(DevicePeer::Unproven, &batch_ref);
    assert_eq!(held.peer(), Some(FederationBurstPeerRef::Unproven));
    assert_eq!(held.state, FederationBurstWorkState::Pending);
    assert!(
        held.baseline.rate_ratio > 1.0,
        "the burst's rate ratio is over the device's baseline: {}",
        held.baseline.rate_ratio
    );
}
