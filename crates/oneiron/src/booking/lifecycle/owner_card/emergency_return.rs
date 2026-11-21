//! The owner's note on a booking the visitor picked again from an emergency
//! cancel's proposals (BK-DEPOSIT-HOST-CANCEL-AFTER-START-OWNER-LINE, PR 3;
//! RULING DEPOSIT-PICK-AFTER-EMERGENCY-CANCEL = A, Engine 15 Nov 19:08).
//!
//! The owner's BK-09 emergency cancel gives the visitor's deposit back
//! whole in its own commit, and the pick that confirms the booking again
//! takes no new one. So the owner's card of that booking says no deposit is
//! held, and where the return of the deposit from before the emergency
//! cancel stands: a refund or release pending, or made. The line names no
//! owner: in a shared vault every live owner reads the card, and the
//! emergency cancel may be another owner's (review round 1 of #10073). Nor
//! does it say which act refunded or released the deposit, or when: the
//! settle takes a refund made by hand in the Stripe dashboard, before the
//! emergency cancel or after it, as the deposit's refund (review round 2 of
//! #10073). The note offers no act. Only the pick reopens an
//! emergency-cancelled booking, so the note stands while the booking stands
//! confirmed and its deposit row carries the emergency cancel's mark; it
//! reads committed facts each time and stores nothing.

use serde::{Deserialize, Serialize};

use super::super::deposit::EmergencyReturn;
use super::held_deposit::booking_label;

/// What the owner's emergency cancel gave back of a booking's deposit, on
/// the card of the booking the visitor picked again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingOwnerCardEmergencyReturn {
    /// Where the return stands.
    pub returned: BookingDepositReturned,
    /// The line the owner reads.
    pub line: String,
}

/// Where the whole return of an emergency cancel stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingDepositReturned {
    /// The captured deposit is owed back; the provider has not refunded it
    /// yet.
    RefundPending,
    /// The provider refunded the captured deposit.
    Refunded,
    /// The capture still due is to be released; the provider has not voided
    /// the authorization yet.
    ReleasePending,
    /// The provider voided the authorization: nothing was captured.
    Released,
}

/// The note on the card of a booking that starts at `start`, whose deposit
/// an emergency cancel gave back as `returned`. Times read in the owner's
/// `zone` (UTC when it does not resolve).
pub(super) fn emergency_return_note(
    returned: EmergencyReturn,
    start: u64,
    zone: Option<&str>,
) -> BookingOwnerCardEmergencyReturn {
    let booking = booking_label(start, zone);
    let (returned, line) = match returned {
        EmergencyReturn::RefundDue => (
            BookingDepositReturned::RefundPending,
            format!(
                "{booking}: no new deposit held; the refund of the deposit from before the \
                 emergency cancel is pending."
            ),
        ),
        EmergencyReturn::Refunded => (
            BookingDepositReturned::Refunded,
            format!(
                "{booking}: no deposit held; the deposit from before the emergency cancel is \
                 refunded."
            ),
        ),
        EmergencyReturn::VoidDue => (
            BookingDepositReturned::ReleasePending,
            format!(
                "{booking}: no new deposit held; the release of the deposit from before the \
                 emergency cancel is pending."
            ),
        ),
        EmergencyReturn::Voided => (
            BookingDepositReturned::Released,
            format!(
                "{booking}: no deposit held; the deposit from before the emergency cancel is \
                 released."
            ),
        ),
    };
    BookingOwnerCardEmergencyReturn { returned, line }
}
