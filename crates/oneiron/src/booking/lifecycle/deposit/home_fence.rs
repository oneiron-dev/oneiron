//! The home-move fence of the deposit writers (FIX [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE],
//! BK-HOME-MOVE-CARRIES-BOOKINGS = A, lead 21 Nov 06:2x: "Money follows the home"): which
//! deposit writes this node takes while a MACRO home move leaves or reaches it
//! (`sync::home_handoff::guard_in_txn`), and the one deposit row writer that asks it.

use super::super::storage::{engine_failure, read_txn, refused};
use super::{DEPOSIT, DepositRow};
use crate::Vault;
use crate::booking::BookingError;

/// FIX [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE] (BK-HOME-MOVE-CARRIES-BOOKINGS = A,
/// lead 21 Nov 06:2x: "Money follows the home"): whether this node still settles its
/// deposits, by the home-move fence (`sync::home_handoff::guard_in_txn`). A node that froze
/// its booking rows for a move does not: its deposit rows are history, the new home holds
/// them and owes their moves, so the old home moves no money. A node draining toward a move
/// still settles the deposits it admitted, so its settle rows can end before it freezes.
#[cfg(feature = "sync")]
pub(super) fn settles_deposits_here(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    crate::sync::home_handoff::takes_home_write_in_txn(
        vault,
        txn,
        crate::sync::home_handoff::HomeWrite::Settle,
    )
    .map_err(|error| engine_failure("home move fence read", error))
}

/// Without the home handoff no move ever freezes a deposit.
#[cfg(not(feature = "sync"))]
pub(super) fn settles_deposits_here(
    _vault: &Vault,
    _txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    Ok(true)
}

/// Where this node stands for its deposits' moves, by the home-move fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SettleStanding {
    /// It holds its booking rows and settles their deposits.
    Settles,
    /// It froze them for a home move its target has not acknowledged. The
    /// move can still be cancelled and the rows come back here (review round 2
    /// of #10058), so a settle row stays queued, dormant, and settles what is
    /// owed once they do.
    MoveUnacknowledged,
    /// It froze them for a move its target acknowledged: the new home holds
    /// the deposits and owes their moves for good.
    MovedAway,
}

/// [`SettleStanding`] in a caller's transaction.
#[cfg(feature = "sync")]
pub(super) fn settle_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<SettleStanding, BookingError> {
    if settles_deposits_here(vault, txn)? {
        return Ok(SettleStanding::Settles);
    }
    Ok(
        match crate::sync::home_handoff::frozen_move_acknowledged_in_txn(vault, txn)
            .map_err(|error| engine_failure("home move state read", error))?
        {
            Some(true) => SettleStanding::MovedAway,
            Some(false) | None => SettleStanding::MoveUnacknowledged,
        },
    )
}

/// Without the home handoff no move ever freezes a deposit.
#[cfg(not(feature = "sync"))]
pub(super) fn settle_standing_in_txn(
    _vault: &Vault,
    _txn: &heed::RoTxn<'_>,
) -> Result<SettleStanding, BookingError> {
    Ok(SettleStanding::Settles)
}

/// Whether this node admits a new deposit checkout, by the home-move fence: not while it
/// drains its booking rows toward a move, nor once it froze them, nor while it waits for the
/// move that carries them here. The visitor starts the checkout on the new home once it holds
/// them: a destination that opened one first would store the payment the old home opened under
/// the same provider key as a second row, and that row would refuse the carried one.
#[cfg(feature = "sync")]
pub(super) fn admits_deposits_here(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    Ok(crate::sync::home_handoff::takes_home_write_in_txn(
        vault,
        txn,
        crate::sync::home_handoff::HomeWrite::Admit,
    )
    .map_err(|error| engine_failure("home move fence read", error))?
        && !awaits_carried_deposits(vault, txn)?)
}

/// Without the home handoff no move ever drains a node.
#[cfg(not(feature = "sync"))]
pub(super) fn admits_deposits_here(
    _vault: &Vault,
    _txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    Ok(true)
}

/// Whether this node waits for a home move that carries its deposits here
/// (`sync::home_handoff::awaits_incoming_move_in_txn`): a payment it does not know may be one
/// that move carries.
#[cfg(feature = "sync")]
pub(super) fn awaits_carried_deposits(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    crate::sync::home_handoff::awaits_incoming_move_in_txn(vault, txn)
        .map_err(|error| engine_failure("home move state read", error))
}

/// Without the home handoff no move ever carries a deposit.
#[cfg(not(feature = "sync"))]
pub(super) fn awaits_carried_deposits(
    _vault: &Vault,
    _txn: &heed::RoTxn<'_>,
) -> Result<bool, BookingError> {
    Ok(false)
}

/// Whether this node opens a deposit checkout now, asked before the server
/// creates the provider's payment: a node that drains its booking rows
/// toward a home move, froze them, or waits for the move that carries them
/// here opens none (FIX [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE]), and
/// [`begin_deposit_checkout`](super::begin_deposit_checkout) asks the same
/// again in its writer.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] where this node opens no checkout
/// now; [`BookingError::SlotOracle`] on a store failure.
pub fn check_deposit_checkout_admitted(vault: &Vault) -> Result<(), BookingError> {
    if !admits_deposits_here(vault, &read_txn(vault)?)? {
        return Err(refused(CHECKOUT_MOVING));
    }
    Ok(())
}

/// The refusal of a checkout on a node a home move is leaving or reaching.
pub(super) const CHECKOUT_MOVING: &str =
    "this node is moving its booking rows to a new home: the checkout starts there";

/// Writes one deposit row. Every deposit write comes here, so it asks the
/// home-move fence first ([`settles_deposits_here`]): a node that froze its
/// booking rows for a home move writes no deposit, whichever writer asks.
pub(super) fn put_deposit(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    row: &DepositRow,
) -> Result<(), BookingError> {
    if !settles_deposits_here(vault, &*wtxn)? {
        return Err(refused(
            "this node froze its booking rows for a home move: the new home holds the deposit",
        ));
    }
    DEPOSIT
        .put(&vault.store, wtxn, key, row)
        .map_err(|error| engine_failure("meta write", error))
}
