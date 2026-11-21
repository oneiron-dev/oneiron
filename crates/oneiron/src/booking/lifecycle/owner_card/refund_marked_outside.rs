//! The owner's note on a booking whose deposit refund an owner marked
//! refunded outside Stripe (FIX [BK-DEPOSIT-FAILED-REFUND-MARK-PAID];
//! BK-DEPOSIT-MARK-PAID-CARD-WORDING = A, Engine 21 Nov 12:13).
//!
//! The card says the refund was made outside Stripe, as marked on the day
//! the mark was recorded in the owner's zone, with the amount marked. It
//! names no reader: every live owner reads the card, and the mark may be
//! another host's (review round 1 of #10073). Where Stripe paid a refund of
//! it after all, one asked before the mark or one made by hand in the
//! dashboard, the card says Stripe refunded it as well, so the visitor may
//! be paid twice (BK-DEPOSIT-MARK-PAID-STRIPE-HOLDS-REFUND = A). The note
//! offers no act; it reads the committed mark each time and stores nothing.

use serde::{Deserialize, Serialize};

use super::super::deposit::MarkedRefund;
use super::held_deposit::money;
use crate::calendar::utc_to_wall;

/// A refund of a booking's deposit that an owner marked refunded outside
/// Stripe, on the booking's card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingOwnerCardRefundMarkedOutside {
    /// The refund marked, in the currency's smallest unit (cents for `usd`).
    pub amount_minor: u64,
    /// The deposit terms' currency, ISO 4217, three lowercase letters.
    pub currency: String,
    /// When the mark was recorded, Unix seconds.
    pub marked_at: u64,
    /// Stripe paid a refund of it after all: the visitor may be paid twice.
    pub stripe_refunded: bool,
    /// The line the owner reads.
    pub line: String,
}

/// The note of `marked`, its day read in the owner's `zone` (UTC when it
/// does not resolve).
pub(super) fn refund_marked_outside_note(
    marked: MarkedRefund,
    zone: Option<&str>,
) -> BookingOwnerCardRefundMarkedOutside {
    let day = day_label(marked.marked_at, zone);
    let money = money(marked.amount_minor, &marked.currency);
    let line = if marked.provider_refunded {
        format!(
            "Marked refunded outside Stripe on {day}, and Stripe refunded it as well: {money} to \
             the visitor, who may be paid twice."
        )
    } else {
        format!("Refunded outside Stripe, as marked on {day}: {money} to the visitor.")
    };
    BookingOwnerCardRefundMarkedOutside {
        amount_minor: marked.amount_minor,
        currency: marked.currency,
        marked_at: marked.marked_at,
        stripe_refunded: marked.provider_refunded,
        line,
    }
}

/// `<year>-<month>-<day>` of `at` in `zone`, or in UTC when the zone does
/// not resolve.
fn day_label(at: u64, zone: Option<&str>) -> String {
    let wall = zone
        .and_then(|tz| utc_to_wall(at, tz).ok())
        .or_else(|| utc_to_wall(at, "UTC").ok());
    match wall {
        Some(wall) => format!("{:04}-{:02}-{:02}", wall.y, wall.mo, wall.d),
        None => format!("{at} (Unix seconds)"),
    }
}
