//! A deposit's refund rules, each in the booking writer's commit: a
//! visitor's cancel or reschedule refunds by the terms the visitor paid
//! under, and a host's cancel gives the deposit back whole.

use super::super::claim::read_booking_facts_to_cancel;
use super::super::storage::{booking_writer, engine_failure, read_txn};
use super::super::types::BookingStatus;
use super::{DEPOSIT, DEPOSIT_BOOKING, DepositState, booking_key, enqueue_settle, put_deposit};
use crate::booking::BookingError;
use crate::{EntityId, Vault};

/// A visitor's cancel's deposit step, in the cancel's own commit: the
/// refund the terms grant for a cancel at `now_utc` of a booking starting at
/// `start_utc`. Before the capture ran, the capture shrinks by it (to a void
/// when nothing is kept); after, the refund is owed. A booking with no
/// deposit, or none captured or due, is untouched.
pub(in crate::booking::lifecycle) fn refund_on_visitor_cancel_in_writer(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    start_utc: u64,
    now_utc: u64,
) -> Result<(), BookingError> {
    let Some(link) = DEPOSIT_BOOKING
        .get(&vault.store, &*wtxn, &booking_key(event_ref))
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let Some(mut row) = DEPOSIT
        .get(&vault.store, &*wtxn, &link.deposit_key)
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let refund = row.terms.visitor_cancel_refund_minor(start_utc, now_utc);
    let refund = row.refund_cap_minor.map_or(refund, |cap| cap.min(refund));
    let next = match row.state {
        DepositState::CaptureDue { amount_minor } => {
            let kept = amount_minor.saturating_sub(refund);
            if kept == 0 {
                DepositState::VoidDue
            } else {
                DepositState::CaptureDue { amount_minor: kept }
            }
        }
        DepositState::Captured { amount_minor } if refund.min(amount_minor) > 0 => {
            DepositState::RefundDue {
                amount_minor: refund.min(amount_minor),
            }
        }
        _ => return Ok(()),
    };
    row.state = next;
    row.updated_at = now_utc;
    put_deposit(vault, wtxn, &link.deposit_key, &row)?;
    enqueue_settle(vault, wtxn, &link.deposit_key, "cancel", now_utc)
}

/// A visitor's reschedule's deposit step, in the move's own commit (RULING
/// DEPOSIT-RESCHEDULE-REFUND = A, 15 Nov 18:27): what a cancel at `now_utc`
/// would refund against the slot being left, which starts at
/// `left_start_utc`, caps every later visitor cancel's refund. A move made
/// with full notice keeps the full refund; a late move, or one after a
/// no-show, keeps only what the owner's rule granted then. Host moves set no
/// cap. A booking with no deposit is untouched.
pub(in crate::booking::lifecycle) fn cap_refund_on_visitor_reschedule_in_writer(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    left_start_utc: u64,
    now_utc: u64,
) -> Result<(), BookingError> {
    let Some(link) = DEPOSIT_BOOKING
        .get(&vault.store, &*wtxn, &booking_key(event_ref))
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let Some(mut row) = DEPOSIT
        .get(&vault.store, &*wtxn, &link.deposit_key)
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let refund = row
        .terms
        .visitor_cancel_refund_minor(left_start_utc, now_utc);
    let cap = row.refund_cap_minor.map_or(refund, |cap| cap.min(refund));
    if row.refund_cap_minor == Some(cap) {
        return Ok(());
    }
    row.refund_cap_minor = Some(cap);
    row.updated_at = now_utc;
    put_deposit(vault, wtxn, &link.deposit_key, &row)
}

/// The host cancelled a booking in their own calendar, an explicit imported
/// cancellation (FIX 22385): its deposit comes back whole, whatever the
/// visitor's refund rule (RULING DEPOSIT-HOST-CANCEL-REFUND = A, the lead 15
/// Nov 12:1x: not a setting; the visitor did nothing wrong). Before the
/// capture ran, the authorization is released; after, the whole capture is
/// owed back. A booking the visitor already cancelled keeps the refund its
/// own cancel decided, and a booking with no deposit is untouched.
///
/// Calendar ingest calls this before it records the cancellation's status,
/// outside any writer of its own, and again on every later sighting of the
/// same explicit cancellation: the refund is its own commit, so a stop before
/// it is repaired by the next read of the feed. A deposit that already
/// owes or has made its refund, or was voided, is left as it stands, and an
/// EVENT with no deposit costs one read.
///
/// `seen_at` is when ingest first saw the cancellation. One seen at or after
/// the booking's start (a held meeting or a no-show tidied from the
/// calendar) leaves the deposit as it stands; the owner can still refund by
/// hand (RULING DEPOSIT-HOST-CANCEL-AFTER-START = A, parity with CAL-07). A
/// repair poll after the start of a cancellation first seen before it still
/// refunds.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a store failure.
pub(crate) fn refund_deposit_on_host_cancel(
    vault: &Vault,
    event_ref: &EntityId,
    seen_at: u64,
    now_utc: u64,
) -> Result<(), BookingError> {
    if !host_cancel_may_owe_refund(vault, event_ref)? {
        return Ok(());
    }
    booking_writer(vault, |wtxn| {
        let booking = read_booking_facts_to_cancel(vault, &*wtxn, event_ref)?;
        if booking.status == BookingStatus::Cancelled || seen_at >= booking.slot.start {
            return Ok(());
        }
        refund_on_host_cancel_in_writer(vault, wtxn, event_ref, now_utc)
    })
}

/// A host cancel's deposit step inside a booking writer the caller holds:
/// the calendar's imported cancellation above, and the owner's BK-09
/// emergency cancel in its own commit (OPUS-SECREAD-A N2, 15 Nov). A deposit
/// still to capture is released (`VoidDue`), a captured one is owed back
/// whole (`RefundDue`), and its settle row is queued "host-cancel". A booking
/// with no deposit, or one already voided, refunded or owing a refund, is
/// untouched. The caller decides whether the booking was still live.
pub(in crate::booking::lifecycle) fn refund_on_host_cancel_in_writer(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    now_utc: u64,
) -> Result<(), BookingError> {
    let Some(link) = DEPOSIT_BOOKING
        .get(&vault.store, &*wtxn, &booking_key(event_ref))
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    let Some(mut row) = DEPOSIT
        .get(&vault.store, &*wtxn, &link.deposit_key)
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(());
    };
    row.state = match row.state {
        DepositState::CaptureDue { .. } => DepositState::VoidDue,
        DepositState::Captured { amount_minor } => DepositState::RefundDue { amount_minor },
        _ => return Ok(()),
    };
    row.updated_at = now_utc;
    put_deposit(vault, wtxn, &link.deposit_key, &row)?;
    enqueue_settle(vault, wtxn, &link.deposit_key, "host-cancel", now_utc)
}

/// Whether the booking `event_ref` has a deposit a host cancel would move:
/// one still to capture, or captured. A read, so the repeated sighting of a
/// cancellation opens no writer.
fn host_cancel_may_owe_refund(vault: &Vault, event_ref: &EntityId) -> Result<bool, BookingError> {
    let rtxn = read_txn(vault)?;
    let Some(link) = DEPOSIT_BOOKING
        .get(&vault.store, &rtxn, &booking_key(event_ref))
        .map_err(|error| engine_failure("meta read", error))?
    else {
        return Ok(false);
    };
    Ok(DEPOSIT
        .get(&vault.store, &rtxn, &link.deposit_key)
        .map_err(|error| engine_failure("meta read", error))?
        .is_some_and(|row| {
            matches!(
                row.state,
                DepositState::CaptureDue { .. } | DepositState::Captured { .. }
            )
        }))
}
