//! What a booking's deposit still holds that its owner may give back
//! (BK-DEPOSIT-HOST-CANCEL-AFTER-START-OWNER-LINE, PR 2 of the owner's
//! return). The owner's return ([`super::refund_booking_deposit_as_owner`])
//! and the owner's line on the booking card read it from the one rule here
//! ([`held_of`]), so the line shows exactly when the return moves money.

use super::home_fence::settles_deposits_here;
use super::{DEPOSIT, DEPOSIT_BOOKING, DepositRow, DepositState, UnattributedCancel, booking_key};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// Which part of a deposit is still held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::booking::lifecycle) enum HeldDepositKind {
    /// Authorized, its capture still due: the owner's return releases it.
    CaptureDue,
    /// Captured: the owner's return owes it back whole.
    Captured,
    /// Captured, and a smaller refund (a visitor's late cancel) is owed: the
    /// owner's return owes the balance once that refund settles.
    BalanceAfterOwedRefund,
    /// Captured, and a smaller refund settled for `refunded_minor`: the
    /// owner's return owes the balance at once.
    BalanceAfterRefund { refunded_minor: u64 },
}

/// A booking's deposit as its owner's line reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::booking::lifecycle) struct HeldDeposit {
    pub(in crate::booking::lifecycle) kind: HeldDepositKind,
    /// What is still held, in the currency's smallest unit.
    pub(in crate::booking::lifecycle) amount_minor: u64,
    /// The terms' currency, ISO 4217 lowercase.
    pub(in crate::booking::lifecycle) currency: String,
    /// When a cancel Oneiron cannot attribute was first noted on it
    /// ([`unattributed_cancel_in_txn`]); `None` while none was.
    pub(in crate::booking::lifecycle) unattributed_cancel_at: Option<u64>,
}

/// What `row` still holds that the owner's return gives back, and how much;
/// `None` when the return would move nothing: a deposit never confirmed, or
/// one that owes or has made its whole return. A row refunded before its
/// capture was recorded holds no balance.
pub(super) fn held_of(row: &DepositRow) -> Option<(HeldDepositKind, u64)> {
    match row.state {
        DepositState::CaptureDue { amount_minor } => {
            Some((HeldDepositKind::CaptureDue, amount_minor))
        }
        DepositState::Captured { amount_minor } => Some((HeldDepositKind::Captured, amount_minor)),
        DepositState::RefundDue { amount_minor } if !row.balance_owed_after_refund => row
            .captured_minor
            .and_then(|captured| {
                captured.checked_sub(row.refunded_minor.saturating_add(amount_minor))
            })
            .filter(|&balance| balance > 0)
            .map(|balance| (HeldDepositKind::BalanceAfterOwedRefund, balance)),
        DepositState::Refunded { amount_minor } => row
            .captured_minor
            .and_then(|captured| captured.checked_sub(amount_minor))
            .filter(|&balance| balance > 0)
            .map(|balance| {
                (
                    HeldDepositKind::BalanceAfterRefund {
                        refunded_minor: amount_minor,
                    },
                    balance,
                )
            }),
        _ => None,
    }
}

/// What the deposit of the booking `event_ref` still holds, read in `rtxn`;
/// `None` for a booking this node holds no deposit for, or one that holds
/// nothing ([`held_of`]).
///
/// # Errors
///
/// Storage errors.
pub(in crate::booking::lifecycle) fn held_deposit_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Option<HeldDeposit>> {
    let Some(link) = DEPOSIT_BOOKING.get(&vault.store, rtxn, &booking_key(event_ref))? else {
        return Ok(None);
    };
    let Some(row) = DEPOSIT.get(&vault.store, rtxn, &link.deposit_key)? else {
        return Ok(None);
    };
    let Some((kind, amount_minor)) = held_of(&row) else {
        return Ok(None);
    };
    Ok(Some(HeldDeposit {
        kind,
        amount_minor,
        currency: row.terms.currency.clone(),
        unattributed_cancel_at: unattributed_cancel_in_txn(vault, rtxn, event_ref, &row)?
            .map(|noted| noted.noted_at),
    }))
}

/// The SEQUENCE of the replay proof that noted a cancel Oneiron cannot
/// attribute on the deposit of the booking `event_ref`
/// ([`unattributed_cancel_in_txn`]), read in `rtxn`; `None` for a booking
/// this node holds no deposit for, or one with no such note.
///
/// # Errors
///
/// Storage errors.
pub(in crate::booking::lifecycle) fn unattributed_cancel_sequence_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Option<u32>> {
    let Some(link) = DEPOSIT_BOOKING.get(&vault.store, rtxn, &booking_key(event_ref))? else {
        return Ok(None);
    };
    let Some(row) = DEPOSIT.get(&vault.store, rtxn, &link.deposit_key)? else {
        return Ok(None);
    };
    Ok(unattributed_cancel_in_txn(vault, rtxn, event_ref, &row)?.map(|noted| noted.sequence))
}

/// The first replay of the owner's cancelled write of the booking
/// `event_ref` that read a stored copy with no write marker as the owner's
/// own while `row`, its deposit, was held (BK-ECHO-UNMARKED-SAME-SHAPE-COPY
/// = C): the deposit stays as that write decides, and a host's cancel at
/// that SEQUENCE reads the same, so the owner's line asks the owner to refund
/// by hand, dated by the proof.
///
/// A row noted before the replay's evidence became a claim keeps its own
/// note (stored change: keep). Otherwise the seat's replay proof recorded it
/// as a synced claim on the EVENT (FIX [BK-REPLAY-NOTE-NOT-CARRIED-TO-NEW-HOME],
/// BK-REPLAY-NOTE-DELIVERY = A), read only where this node holds the live
/// deposit, so the note reaches the new home after a booking home move, and
/// only while a host cancel would move the deposit: a capture still due, or
/// captured. The booking names its deposit from its confirm on, in the
/// commit where its capture falls due, and a deposit's state only moves on
/// from there, so a deposit that stands so now stood so at the proof.
fn unattributed_cancel_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    row: &DepositRow,
) -> Result<Option<UnattributedCancel>> {
    if row.unattributed_cancel.is_some() {
        return Ok(row.unattributed_cancel);
    }
    if !matches!(
        row.state,
        DepositState::CaptureDue { .. } | DepositState::Captured { .. }
    ) || !settles_deposits_here(vault, rtxn)
        .map_err(|error| Error::InvalidConfig(error.to_string()))?
    {
        return Ok(None);
    }
    Ok(
        crate::calendar::connectors::replay_cancel_evidence_in_txn(vault, rtxn, event_ref)?.map(
            |evidence| UnattributedCancel {
                sequence: evidence.sequence,
                noted_at: evidence.proved_at,
            },
        ),
    )
}
