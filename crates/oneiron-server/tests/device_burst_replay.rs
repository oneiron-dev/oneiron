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
//! One batch has one landing at a time (FIX DEVICE-BURST-ALLOW-DRAIN-OVERLAP):
//! the drain leaves a batch whose landing a socket claimed. A send of bytes
//! whose batch another landing holds is answered by the batch's record at the
//! home (#9954 review round 1): as held while the batch is retained, by its
//! receipt once it settled, and with a Try Again Later close while nothing of
//! it is retained.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support
//! --no-fail-fast --test device_burst_replay`.

#[path = "support/device_burst_home.rs"]
mod device_burst_home;
#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;
use std::time::Duration;

use device_burst_home::{
    BURST_ROWS, Device, Home, WINDOW, WsStream, held_answer, operations, send_update,
};
use engine_stack::run_on_engine_stack;
use futures_util::StreamExt;
use oneiron::DeleteReason;
use oneiron::sync::WindowKey;
use oneiron::sync::federation_burst::{
    DeviceBurstAdmission, DevicePeer, FederationBurstDisposition, FederationBurstWorkState,
    admit_device_window_update, device_update_batch_ref,
};
use oneiron_server::test_doors::device_burst_drain::{
    claim_device_burst_landing, drain_device_bursts_once,
};
use tokio_tungstenite::tungstenite::Message;

/// RFC 6455 "Try Again Later": the close the home answers a send with while
/// another landing holds its batch and nothing of it is retained.
const TRY_AGAIN_LATER: u16 = 1013;

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
        home.until_committed(|| home.held_rows(&trickle_rows) == 1)
            .await,
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
        home.until_committed(|| home.held_rows(&burst_rows) == BURST_ROWS)
            .await,
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
        home.until_committed(|| home.held_rows(&trickle_rows) == 1)
            .await,
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

/// FIX DEVICE-BURST-ALLOW-DRAIN-OVERLAP, the drain's side. A batch the burst
/// core allowed stays retained, its receipt Pending, until the socket that
/// sent it ends it, and it is due to the drain once the device's rate is
/// ready. While the socket's claim on its landing stands, the drain leaves
/// it; once the socket gave up with the batch retained, the next pass lands
/// it. Red when the drain ignores the claim: it lands the batch the socket is
/// landing, so the same bytes persist twice.
#[test]
fn the_drain_leaves_a_batch_whose_socket_lands_it_and_lands_it_once_the_socket_gives_up() {
    run_on_engine_stack("device-burst-claim-drain", drain_leaves_claimed_batch);
}

async fn drain_leaves_claimed_batch() {
    let device = Device::new();
    let (trickle, trickle_rows) = device.rows_update(1);
    let home = Home::new(DevicePeer::Unproven, operations(&trickle)).await;
    let key = WindowKey::try_new(WINDOW).unwrap();
    // A socket's UPDATE arm claims the batch's landing, and the burst core
    // allows the trickle, which is at the device's baseline.
    let batch_ref = device_update_batch_ref(&DevicePeer::Unproven, &key, &trickle, false).unwrap();
    let claim = claim_device_burst_landing(&home.server, batch_ref.clone())
        .expect("no landing holds a batch nobody sent");
    let work =
        match admit_device_window_update(&home.vault, &DevicePeer::Unproven, &key, &trickle, &[])
            .unwrap()
        {
            DeviceBurstAdmission::Allow(work) => work,
            other => panic!("the trickle at the baseline is allowed: {other:?}"),
        };
    assert_eq!(work.batch_ref(), batch_ref, "the claim names the batch");
    assert!(
        claim_device_burst_landing(&home.server, batch_ref.clone()).is_none(),
        "a claimed batch has one landing"
    );

    // Two seconds on, the device's rate is ready and the batch is due, while
    // the socket still lands it: the drain leaves it.
    home.clock.set(home.now + 2);
    assert_eq!(
        drain_device_bursts_once(&home.server).await.unwrap(),
        0,
        "the drain leaves the batch its socket lands"
    );
    assert_eq!(
        home.held_rows(&trickle_rows),
        0,
        "the drain lands nothing of it"
    );
    assert_eq!(
        home.receipt(DevicePeer::Unproven, &batch_ref).state,
        FederationBurstWorkState::Pending,
        "the batch waits for its socket to end it"
    );

    // The socket gave up with the batch retained: the next pass lands it.
    drop(claim);
    assert_eq!(
        drain_device_bursts_once(&home.server).await.unwrap(),
        1,
        "the drain lands the batch its socket gave up"
    );
    assert!(
        home.until_committed(|| home.held_rows(&trickle_rows) == 1)
            .await,
        "the batch's row lands at the home"
    );
    assert_eq!(
        home.receipt(DevicePeer::Unproven, &batch_ref).state,
        FederationBurstWorkState::Imported
    );
}

/// FIX DEVICE-BURST-ALLOW-DRAIN-OVERLAP and #9954 review round 1, the
/// socket's side with nothing retained. While another landing holds a batch
/// that nothing at the home retains yet (that landing's admission has not
/// committed, or failed before it retained the bytes), the device's send of
/// the bytes is closed with Try Again Later, never answered as held: a held
/// answer names the bytes in the window's version, and a device that clears
/// its queue on it loses them. Nothing lands from that send. Once the other
/// landing ended, a new socket's send of the same bytes lands. Red when the
/// socket answers by the claim alone: it answers as held and stays open.
#[test]
fn a_send_of_an_unretained_batch_another_landing_holds_is_closed_to_be_sent_again() {
    run_on_engine_stack(
        "device-burst-claim-unretained",
        send_of_unretained_claimed_batch,
    );
}

async fn send_of_unretained_claimed_batch() {
    let device = Device::new();
    let (trickle, trickle_rows) = device.rows_update(1);
    let home = Home::new(DevicePeer::Unproven, operations(&trickle)).await;
    let key = WindowKey::try_new(WINDOW).unwrap();
    // The root socket is on the full-window lane, so its batch is not a
    // promoted window's.
    let batch_ref = device_update_batch_ref(&DevicePeer::Unproven, &key, &trickle, false).unwrap();
    let claim = claim_device_burst_landing(&home.server, batch_ref)
        .expect("no landing holds a batch nobody sent");
    let mut socket = home.connect_root().await;
    send_update(&mut socket, &trickle).await;
    assert_eq!(
        close_code(&mut socket).await,
        Some(TRY_AGAIN_LATER),
        "the home closes the send to be sent again while nothing of its batch is retained"
    );
    assert_eq!(
        home.held_rows(&trickle_rows),
        0,
        "nothing of the send lands"
    );

    // That landing ended: the device's next send of the bytes lands.
    drop(claim);
    let mut socket = home.connect_root().await;
    send_update(&mut socket, &trickle).await;
    assert!(
        home.until_committed(|| home.held_rows(&trickle_rows) == 1)
            .await,
        "the send lands once no other landing holds its batch"
    );
}

/// #9954 review round 1, the socket's side with the batch retained, then
/// settled. While another landing holds a batch the burst core retained
/// (its receipt Pending), the device's send of the bytes is answered as
/// held: the batch is durable, and that landing, or the drain after it,
/// lands it. Once the batch settled, a send while a landing holds it is
/// answered by its receipt: no held answer, and nothing lands twice. The
/// settled half is red when the socket answers by the claim alone.
#[test]
fn a_send_of_a_retained_or_settled_batch_another_landing_holds_is_answered_by_its_record() {
    run_on_engine_stack(
        "device-burst-claim-retained",
        send_of_retained_claimed_batch,
    );
}

async fn send_of_retained_claimed_batch() {
    let device = Device::new();
    let (trickle, trickle_rows) = device.rows_update(1);
    let home = Home::new(DevicePeer::Unproven, operations(&trickle)).await;
    let key = WindowKey::try_new(WINDOW).unwrap();
    let batch_ref = device_update_batch_ref(&DevicePeer::Unproven, &key, &trickle, false).unwrap();
    // Another landing claims the batch, and the burst core retains it.
    let claim = claim_device_burst_landing(&home.server, batch_ref.clone())
        .expect("no landing holds a batch nobody sent");
    match admit_device_window_update(&home.vault, &DevicePeer::Unproven, &key, &trickle, &[])
        .unwrap()
    {
        DeviceBurstAdmission::Allow(_) => {}
        other => panic!("the trickle at the baseline is allowed: {other:?}"),
    }
    let mut socket = home.connect_root().await;
    send_update(&mut socket, &trickle).await;
    assert!(
        held_answer(&mut socket).await,
        "the home answers the send of a retained batch as held"
    );
    assert_eq!(
        home.held_rows(&trickle_rows),
        0,
        "nothing of the send lands from the socket"
    );

    // That landing gave up with the batch retained: the drain lands it.
    drop(claim);
    home.clock.set(home.now + 2);
    assert_eq!(
        drain_device_bursts_once(&home.server).await.unwrap(),
        1,
        "the drain lands the retained batch"
    );
    assert!(
        home.until_committed(|| home.held_rows(&trickle_rows) == 1)
            .await,
        "the batch's row lands at the home"
    );
    assert_eq!(
        home.receipt(DevicePeer::Unproven, &batch_ref).state,
        FederationBurstWorkState::Imported
    );

    // Settled: a send while a landing holds the batch is answered by its
    // receipt.
    let _claim =
        claim_device_burst_landing(&home.server, batch_ref).expect("the drain's landing ended");
    send_update(&mut socket, &trickle).await;
    assert!(
        !held_answer(&mut socket).await,
        "a send of a settled batch gets no held answer"
    );
    assert_eq!(
        home.held_rows(&trickle_rows),
        1,
        "nothing of the batch lands twice"
    );
}

/// The code the home closes `ws` with within five seconds, past any frame
/// before it; `None` when no close comes by then.
async fn close_code(ws: &mut WsStream) -> Option<u16> {
    // testkit-lint: allow(wall-clock) hang guard for the close
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await.ok()?? {
            Ok(Message::Close(frame)) => return frame.map(|frame| u16::from(frame.code)),
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}
