//! A deposit refund the provider ended with nothing paid back
//! (FIX [BK-DEPOSIT-FAILED-REFUND-SURFACE]).
//!
//! Stripe can end a refund `failed` or `canceled` (a closed card, say): the
//! money stays owed to the visitor, and the deposit stays refund-due. Its
//! settle row asks again hourly under the same idempotency key, which finds
//! the same ended refund, so nothing moves it on but a hand refund in the
//! Stripe dashboard that covers what is owed. The settle row notes the ended
//! refund on the deposit ([`note_refund_ended_unpaid`]); the owner's card
//! says so, and Return deposit (`vault.booking.deposit.refund`) asks the
//! provider for the same refund again under the next retry count, which the
//! refund's idempotency key names, so the provider makes a new refund rather
//! than answering the ended one. The note goes once a refund of the deposit
//! settles.

use serde::{Deserialize, Serialize};

use super::super::storage::{booking_writer, engine_failure};
use super::home_fence::{SettleStanding, settle_standing_in_txn};
use super::{DEPOSIT, DepositState, put_deposit};
use crate::Vault;
use crate::booking::BookingError;

/// The refund a deposit owes now that the provider ended with nothing paid
/// back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefundEndedUnpaid {
    /// The deposit's retry count when the ended refund was asked: the owner
    /// may ask again only while it is still the deposit's own, so a second
    /// Return deposit before the new refund ends changes nothing.
    pub(super) retry: u32,
    /// When a settle row first found it ended.
    pub(super) noted_at: u64,
}

/// One refund a settle row asked the provider for: what the deposit owed,
/// what was refunded before it, and the retry count its key named.
#[derive(Debug, Clone, Copy)]
pub(super) struct AskedRefund {
    pub(super) amount_minor: u64,
    pub(super) refunded_before: u64,
    pub(super) retry: u32,
}

/// Whether a deposit's retry count is unset, so a row that never retried a
/// refund encodes as before. Serde's `skip_serializing_if` hands the field
/// by reference.
pub(super) const fn is_zero(retry: &u32) -> bool {
    *retry == 0
}

/// Notes, in its own booking writer, that the provider ended the refund
/// `asked` with nothing paid back: only while the deposit still owes exactly
/// that refund, after the same earlier refunds and under the same retry
/// count, so an answer that a later refund or a retry overtook notes
/// nothing. A note already standing at that retry count stays as it is,
/// dated by its first finding, so the hourly ask writes nothing. A node that
/// froze its booking rows for a home move notes nothing: the new home asks
/// the same refund and notes it there.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a store failure.
pub(super) fn note_refund_ended_unpaid(
    vault: &Vault,
    key: &[u8; 32],
    asked: AskedRefund,
    now_utc: u64,
) -> Result<(), BookingError> {
    booking_writer(vault, |wtxn| {
        if settle_standing_in_txn(vault, &*wtxn)? != SettleStanding::Settles {
            return Ok(());
        }
        let Some(mut row) = DEPOSIT
            .get(&vault.store, &*wtxn, key)
            .map_err(|error| engine_failure("meta read", error))?
        else {
            return Ok(());
        };
        let owes_it = row.state
            == (DepositState::RefundDue {
                amount_minor: asked.amount_minor,
            })
            && row.refunded_minor == asked.refunded_before
            && row.refund_retry == asked.retry;
        let noted = row
            .refund_ended_unpaid
            .is_some_and(|ended| ended.retry == asked.retry);
        if !owes_it || noted {
            return Ok(());
        }
        row.refund_ended_unpaid = Some(RefundEndedUnpaid {
            retry: asked.retry,
            noted_at: now_utc,
        });
        row.updated_at = now_utc;
        put_deposit(vault, wtxn, key, &row)
    })
}
