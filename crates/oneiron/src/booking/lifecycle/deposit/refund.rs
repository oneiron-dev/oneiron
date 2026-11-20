//! A deposit's refund rules, each in the booking writer's commit: a
//! visitor's cancel or reschedule refunds by the terms the visitor paid
//! under, and a host's cancel or the owner's refund gives the deposit back
//! whole.

use super::super::claim::read_booking_facts_to_cancel;
use super::super::storage::{booking_writer, engine_failure, read_txn};
use super::super::types::BookingStatus;
use super::held::{HeldDepositKind, held_of};
use super::{
    DEPOSIT, DEPOSIT_BOOKING, DepositRow, DepositState, booking_key, enqueue_settle, put_deposit,
};
use crate::booking::BookingError;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use crate::verbs::{BookingDepositRefundReceipt, BookingDepositRefundState};
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
            row.captured_minor = Some(amount_minor);
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
    let Some(next) = whole_return(row.state) else {
        return Ok(());
    };
    row.state = next;
    row.updated_at = now_utc;
    put_deposit(vault, wtxn, &link.deposit_key, &row)?;
    enqueue_settle(vault, wtxn, &link.deposit_key, "host-cancel", now_utc)
}

/// The move that gives a deposit in `state` back whole: a capture still due
/// is released (`VoidDue`), a captured amount is owed back (`RefundDue`).
/// `None` for a deposit already voided, refunded or owing either.
fn whole_return(state: DepositState) -> Option<DepositState> {
    match state {
        DepositState::CaptureDue { .. } => Some(DepositState::VoidDue),
        DepositState::Captured { amount_minor } => Some(DepositState::RefundDue { amount_minor }),
        _ => None,
    }
}

/// What the owner's return changed on a deposit row.
enum OwnerReturn {
    /// Nothing: the deposit owes or has made its whole return already.
    Nothing,
    /// A move is owed now; its settle row is to be queued.
    Queued,
    /// The refund owed now settles first, and its record owes the balance
    /// (its settle row is queued already).
    AfterOwedRefund,
}

/// The owner's return of `row`'s deposit, whole: a capture still due is
/// released and a captured amount owed back, as a host cancel does. A
/// refund for less than the capture (a visitor's late cancel, or the excess
/// of a capture a cancel overtook) gains the balance (review round 2 of
/// #9977): owed at once after that refund settled, or once it settles while
/// it is owed, so the provider refunds the earlier part once. A row
/// refunded before its capture was recorded gains nothing. What it moves is
/// what the owner's line shows held ([`held_of`]).
fn owner_return(row: &mut DepositRow) -> OwnerReturn {
    let Some((kind, amount_minor)) = held_of(row) else {
        return OwnerReturn::Nothing;
    };
    match kind {
        HeldDepositKind::CaptureDue => {
            row.state = DepositState::VoidDue;
            OwnerReturn::Queued
        }
        HeldDepositKind::Captured => {
            row.captured_minor = Some(amount_minor);
            row.state = DepositState::RefundDue { amount_minor };
            OwnerReturn::Queued
        }
        HeldDepositKind::BalanceAfterOwedRefund => {
            row.balance_owed_after_refund = true;
            OwnerReturn::AfterOwedRefund
        }
        HeldDepositKind::BalanceAfterRefund { refunded_minor } => {
            row.refunded_minor = refunded_minor;
            row.state = DepositState::RefundDue { amount_minor };
            OwnerReturn::Queued
        }
    }
}

/// `vault.booking.deposit.refund` (BK-DEPOSIT-OWNER-RETURN-ACT = A and
/// BK-DEPOSIT-OWNER-RETURN-SCOPE = A, Engine 21 Nov 02:56): the owner gives a
/// booking's held deposit back whole, in one booking writer. The proof is
/// the vault owner's own unattenuated, undelegated one, revalidated in this
/// writer; only a host selected at the booking's confirmation may use it,
/// once the booking is effectively cancelled (its own cancel or a calendar's)
/// or has started. It runs on the node that holds the deposit: the one whose
/// booking writer confirmed it, which keeps it, with its settle rows, after a
/// MACRO home move (a move carries no deposit row). A
/// capture still due is released and a captured deposit owed back whole, as
/// a host cancel does, with its settle row queued "owner-refund"; the
/// booking's status and revision stay as they are. After a refund of part of
/// the capture (a visitor's late cancel) the balance is owed: at once when
/// that refund has settled, and once it settles while it is owed. A deposit
/// that already owes or has settled its whole return is left as it stands,
/// so a retry queues nothing. The receipt's amount is the whole return:
/// what was refunded before and what is owed now.
///
/// # Errors
///
/// [`BookingError::Boundary`] for a proof that no longer holds or a caller
/// who was not a selected host; [`BookingError::InvalidConstraint`] for an
/// EVENT that is no booking; [`BookingError::InvalidConfig`] for a live
/// booking that has not started, or one this node holds no deposit for;
/// [`BookingError::SlotOracle`] on a store failure.
pub(crate) fn refund_booking_deposit_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    event_ref: &EntityId,
) -> Result<BookingDepositRefundReceipt, BookingError> {
    booking_writer(vault, |wtxn| {
        let actor = owner
            .owner_authored_write_in_txn(vault, &*wtxn)
            .map_err(|error| BookingError::Boundary(Box::new(MemoryError::from(error))))?
            .actor();
        let booking = read_booking_facts_to_cancel(vault, &*wtxn, event_ref)?;
        if !booking
            .context
            .as_ref()
            .is_some_and(|context| context.owner_refs.contains(&actor.to_hex()))
        {
            return Err(BookingError::Boundary(Box::new(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only a host selected when the booking was confirmed refunds its deposit",
                &["Call it as one of the booking's hosts."],
            ))));
        }
        let now_utc = vault.now_recorded_at();
        if booking.effective_status() != BookingStatus::Cancelled && now_utc < booking.slot.start {
            return Err(BookingError::InvalidConfig(
                "a live booking that has not started keeps its deposit: cancel it to refund"
                    .to_owned(),
            ));
        }
        let Some(link) = DEPOSIT_BOOKING
            .get(&vault.store, &*wtxn, &booking_key(event_ref))
            .map_err(|error| engine_failure("meta read", error))?
        else {
            return Err(BookingError::InvalidConfig(
                "this node holds no deposit for the booking".to_owned(),
            ));
        };
        let Some(mut row) = DEPOSIT
            .get(&vault.store, &*wtxn, &link.deposit_key)
            .map_err(|error| engine_failure("meta read", error))?
        else {
            return Err(BookingError::InvalidConfig(
                "this node holds no deposit for the booking".to_owned(),
            ));
        };
        let returned = owner_return(&mut row);
        if !matches!(returned, OwnerReturn::Nothing) {
            row.updated_at = now_utc;
            put_deposit(vault, wtxn, &link.deposit_key, &row)?;
        }
        if matches!(returned, OwnerReturn::Queued) {
            enqueue_settle(vault, wtxn, &link.deposit_key, "owner-refund", now_utc)?;
        }
        let queued = !matches!(returned, OwnerReturn::Nothing);
        let (state, amount_minor) = match row.state {
            DepositState::RefundDue { amount_minor } => {
                let refunded_after = row.refunded_minor.saturating_add(amount_minor);
                let whole = match row.captured_minor {
                    Some(captured) if row.balance_owed_after_refund => captured.max(refunded_after),
                    _ => refunded_after,
                };
                (BookingDepositRefundState::RefundDue, whole)
            }
            DepositState::VoidDue => (BookingDepositRefundState::VoidDue, 0),
            DepositState::Refunded { amount_minor } => {
                (BookingDepositRefundState::Refunded, amount_minor)
            }
            DepositState::Voided => (BookingDepositRefundState::Voided, 0),
            _ => {
                return Err(BookingError::InvalidConfig(
                    "the booking's deposit was never confirmed".to_owned(),
                ));
            }
        };
        Ok(BookingDepositRefundReceipt {
            event_ref: event_ref.to_hex(),
            state,
            amount_minor,
            currency: row.terms.currency.clone(),
            queued,
        })
    })
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
