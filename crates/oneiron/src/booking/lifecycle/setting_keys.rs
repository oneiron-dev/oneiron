//! The booking lifecycle's pack Setting key (owner ruling PACK-SETTINGS-ALL = B; Engine ANSWER
//! BOOKING-RESCHEDULE-AFTER-START = A as amended by the lead, 16 Nov 22:40): whether a visitor's
//! reschedule token still moves a booking once its start has come.
//!
//! The default is off: a token reschedule at or after the booking's start second is refused, so a
//! meeting in progress, a held meeting or a no-show stays where it happened, and the visitor books
//! again. Some hosts want "missed it? move it" for no-shows, so the host may turn it on.
//!
//! Direction: false is tighter. Turning it on is a loosening and needs the owner's device yes; an
//! agent's change waits on the owner's approval. With it on, the moved booking keeps its deposit
//! rules (the reschedule refund cap, DEPOSIT-RESCHEDULE-REFUND = A, applies as to any visitor
//! move).

use crate::Vault;
use crate::error::Result;
use crate::setting::{Kind, lower_is_tighter};

const fn refused_after_start() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let visitors reschedule after the start time (default false: a reschedule token presented
    /// at or after the booking's start second is refused, and the booking stays where it
    /// happened). true: the token moves a started, held or missed booking to an open slot like any
    /// other, under the same solver rules and deposit rules. false is tighter.
    pub(crate) BOOKING_RESCHEDULE_AFTER_START: bool = "booking.reschedule.after_start" {
        kind: Kind::new(refused_after_start)
            .strictest(refused_after_start)
            .tighter(lower_is_tighter::<bool>),
    };
}

/// Whether the host lets a visitor's token move a booking whose start has come, in `txn`, at the
/// vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn reschedule_after_start_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(BOOKING_RESCHEDULE_AFTER_START
        .read_in_txn(vault, txn, &[], None)?
        .value)
}
