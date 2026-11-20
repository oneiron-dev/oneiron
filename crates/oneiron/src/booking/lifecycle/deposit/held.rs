//! What a booking's deposit still holds that its owner may give back
//! (BK-DEPOSIT-HOST-CANCEL-AFTER-START-OWNER-LINE, PR 2 of the owner's
//! return). The owner's return ([`super::refund_booking_deposit_as_owner`])
//! and the owner's line on the booking card read it from the one rule here
//! ([`held_of`]), so the line shows exactly when the return moves money.

use super::{
    DEPOSIT, DEPOSIT_BOOKING, DepositRow, DepositState, UnattributedCancel, booking_key,
    put_deposit,
};
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
    /// ([`note_unattributed_cancel_in_txn`]); `None` while none was.
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
    Ok(held_of(&row).map(|(kind, amount_minor)| HeldDeposit {
        kind,
        amount_minor,
        currency: row.terms.currency.clone(),
        unattributed_cancel_at: row.unattributed_cancel.map(|noted| noted.noted_at),
    }))
}

/// The SEQUENCE of the replay proof that noted a cancel Oneiron cannot
/// attribute on the deposit of the booking `event_ref`
/// ([`note_unattributed_cancel_in_txn`]), read in `rtxn`; `None` for a
/// booking this node holds no deposit for, or one with no such note.
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
    Ok(DEPOSIT
        .get(&vault.store, rtxn, &link.deposit_key)?
        .and_then(|row| row.unattributed_cancel)
        .map(|noted| noted.sequence))
}

/// Records, in the calendar writer `wtxn`, that a seat's replay of the
/// owner's cancelled write of the booking `event_ref` at `sequence` read a
/// stored copy with no write marker as the owner's own
/// (BK-ECHO-UNMARKED-SAME-SHAPE-COPY = C, lead 21 Nov 04:3x): the deposit
/// stays as that write decides, and a host's cancel at that SEQUENCE reads
/// the same, so the owner's line asks the owner to refund by hand, dated
/// `now`. Only a deposit a host cancel would move (a capture still due, or
/// captured) is marked, and only once; an EVENT with no deposit is left
/// alone.
///
/// The row is written through the deposits' one writer, so the home-move
/// fence holds here too (review round 2 of #10058, FIX
/// [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE]): a node that froze its
/// booking rows for a move writes no note on their history. It refuses, the
/// replay's proof writer drops whole, and the outbox keeps the proof owed, so
/// a later write or pull of the seat proves it again; it lands here once a
/// cancelled move gives the rows back.
///
/// # Errors
///
/// Storage errors; a refusal on a node that froze its booking rows.
pub(crate) fn note_unattributed_cancel_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    sequence: u32,
    now: u64,
) -> Result<()> {
    let Some(link) = DEPOSIT_BOOKING.get(&vault.store, &*wtxn, &booking_key(event_ref))? else {
        return Ok(());
    };
    let Some(mut row) = DEPOSIT.get(&vault.store, &*wtxn, &link.deposit_key)? else {
        return Ok(());
    };
    if row.unattributed_cancel.is_some()
        || !matches!(
            row.state,
            DepositState::CaptureDue { .. } | DepositState::Captured { .. }
        )
    {
        return Ok(());
    }
    row.unattributed_cancel = Some(UnattributedCancel {
        sequence,
        noted_at: now,
    });
    row.updated_at = now;
    put_deposit(vault, wtxn, &link.deposit_key, &row)
        .map_err(|error| Error::InvalidConfig(error.to_string()))
}
