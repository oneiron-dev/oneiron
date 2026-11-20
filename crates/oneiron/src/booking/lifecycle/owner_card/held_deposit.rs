//! The owner's line for a booking's held deposit
//! (BK-DEPOSIT-HOST-CANCEL-AFTER-START-OWNER-LINE, PR 2 of the owner's
//! return; BK-DEPOSIT-OWNER-RETURN-ACT = A and BK-DEPOSIT-OWNER-RETURN-SCOPE
//! = A, Engine 21 Nov 02:56; BK-ECHO-UNMARKED-SAME-SHAPE-COPY = C, lead 21
//! Nov 04:3x).
//!
//! Once a booking is effectively cancelled or has started, the owner's card
//! says what its deposit still holds and offers Return deposit
//! (`vault.booking.deposit.refund`, body `{event_ref}`) to the hosts
//! selected at its confirmation. Nothing refunds by itself. Where a calendar
//! cancelled the booking without moving money (a cancel first seen at or
//! after the start, DEPOSIT-HOST-CANCEL-AFTER-START = A; one from a calendar
//! the booking was never written to, DEPOSIT-HOST-CANCEL-SOURCE = A; a host
//! delete held while the owner's cancelled write was unproven), or a cancel
//! Oneiron cannot attribute left it held, the line is also an INBOX row of
//! its own ([`super::BOOKING_HELD_DEPOSIT_ITEM_PREFIX`]); everywhere else it
//! is on the booking card only, a calendar's plain omission of the booking
//! included (review round 1 of #10028). The line reads committed facts each
//! time: it goes when the deposit no longer holds anything (a return owed
//! or made) and comes back with nothing stored.

use serde::{Deserialize, Serialize};

use super::super::deposit::{HeldDeposit, HeldDepositKind};
use super::super::types::BookingStatus;
use super::super::{BookingFacts, CalendarCancellation};
use crate::EntityId;
use crate::calendar::utc_to_wall;

/// What a booking's deposit still holds, on its owner's card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingOwnerCardDeposit {
    /// Which part of the deposit is held.
    pub held: BookingDepositHeld,
    /// What is still held, in the currency's smallest unit (cents for
    /// `usd`).
    pub amount_minor: u64,
    /// The deposit terms' currency, ISO 4217, three lowercase letters.
    pub currency: String,
    /// Why the deposit is still held.
    pub reason: BookingDepositHeldReason,
    /// The line the owner reads.
    pub line: String,
    /// Whether the reader may give the deposit back with Return deposit
    /// (`vault.booking.deposit.refund`, body `{event_ref}`): only a host
    /// selected when the booking was confirmed may.
    pub return_offered: bool,
}

/// Which part of a deposit is still held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingDepositHeld {
    /// The card is authorized and its capture still due: Return deposit
    /// releases it.
    CaptureDue,
    /// Captured: Return deposit refunds it whole.
    Captured,
    /// What a partial refund (a visitor's late cancel) that has been made
    /// left of the capture: Return deposit refunds the balance.
    BalanceAfterRefund,
    /// What a partial refund (a visitor's late cancel) that is owed and not
    /// yet made leaves of the capture: Return deposit refunds the balance
    /// once that refund is made.
    BalanceAfterOwedRefund,
}

/// Why a booking's deposit is still held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingDepositHeldReason {
    /// A calendar cancelled the booking and its cancel moved no money: one
    /// first seen at or after the start, one from a calendar the booking
    /// was never written to, or a host delete held while the owner's own
    /// cancelled write was unproven.
    CalendarCancel,
    /// Every calendar that listed the booking left it out of a complete
    /// listing, and no report of a cancel is held: the booking reads
    /// cancelled until a calendar lists it again, and the omission, which is
    /// no cancel, moved no money. On the booking card only.
    CalendarOmission,
    /// A seat stored a cancelled copy of the booking with no write marker,
    /// which reads as the owner's own cancelled write: a host's cancel at
    /// that version would read the same, so it moved no money
    /// (BK-ECHO-UNMARKED-SAME-SHAPE-COPY = C).
    UnattributedCancel,
    /// The booking's own cancel (the visitor's) left it, by the terms the
    /// visitor paid under.
    Cancelled,
    /// The booked slot has started (a no-show keeps the deposit).
    Started,
}

impl BookingDepositHeldReason {
    /// Whether the line is an INBOX row of its own as well as a note on the
    /// booking card: only where a calendar's cancel moved no money, or a
    /// cancel Oneiron cannot attribute did not.
    pub(super) const fn lists_on_inbox(self) -> bool {
        matches!(self, Self::CalendarCancel | Self::UnattributedCancel)
    }
}

/// The deposit note of the booking `facts` describe at `now`, for `reader`:
/// what `held` still holds, once the booking is effectively cancelled or
/// has started (the owner's return's own condition); `None` before then,
/// or with nothing held. `removal_report_held` says a calendar's report of
/// the booking removed waits on one of its passports, unsettled: with an
/// omission, that is the host delete held while the owner's cancelled write
/// was unproven. Times read in the owner's `zone` (UTC when it does not
/// resolve).
pub(super) fn deposit_note(
    facts: &BookingFacts,
    held: Option<HeldDeposit>,
    removal_report_held: bool,
    zone: Option<&str>,
    now: u64,
    reader: Option<EntityId>,
) -> Option<BookingOwnerCardDeposit> {
    let held = held?;
    let cancelled = facts.effective_status() == BookingStatus::Cancelled;
    if !cancelled && now < facts.slot.start {
        return None;
    }
    // The booking's own cancel (the visitor's) decides its deposit by the
    // terms; only a booking whose own status stands live reads a calendar's.
    let own_cancel = facts.status == BookingStatus::Cancelled;
    let reason = match facts.calendar_cancellation {
        _ if own_cancel => BookingDepositHeldReason::Cancelled,
        _ if held.unattributed_cancel_at.is_some() => BookingDepositHeldReason::UnattributedCancel,
        CalendarCancellation::Standing => BookingDepositHeldReason::CalendarCancel,
        CalendarCancellation::Omission if removal_report_held => {
            BookingDepositHeldReason::CalendarCancel
        }
        CalendarCancellation::Omission => BookingDepositHeldReason::CalendarOmission,
        CalendarCancellation::None => BookingDepositHeldReason::Started,
    };
    let held_part = match held.kind {
        HeldDepositKind::CaptureDue => BookingDepositHeld::CaptureDue,
        HeldDepositKind::Captured => BookingDepositHeld::Captured,
        HeldDepositKind::BalanceAfterRefund { .. } => BookingDepositHeld::BalanceAfterRefund,
        HeldDepositKind::BalanceAfterOwedRefund => BookingDepositHeld::BalanceAfterOwedRefund,
    };
    let return_offered = reader.is_some_and(|reader| {
        facts
            .context
            .as_ref()
            .is_some_and(|context| context.owner_refs.contains(&reader.to_hex()))
    });
    let line = owner_line(
        &booking_label(facts.slot.start, zone),
        reason,
        held_part,
        &money(held.amount_minor, &held.currency),
        return_offered,
    );
    Some(BookingOwnerCardDeposit {
        held: held_part,
        amount_minor: held.amount_minor,
        currency: held.currency,
        reason,
        line,
        return_offered,
    })
}

/// The owner's line: what happened to the booking, what its deposit still
/// holds, and the act.
fn owner_line(
    booking: &str,
    reason: BookingDepositHeldReason,
    held: BookingDepositHeld,
    money: &str,
    return_offered: bool,
) -> String {
    let what = match reason {
        BookingDepositHeldReason::CalendarCancel => {
            format!("{booking} was cancelled in a calendar.")
        }
        BookingDepositHeldReason::CalendarOmission => format!(
            "{booking} is missing from every calendar that listed it, so it reads as cancelled."
        ),
        BookingDepositHeldReason::UnattributedCancel => {
            format!("{booking}: a cancel we can't attribute: refund by hand?")
        }
        BookingDepositHeldReason::Cancelled => format!("{booking} was cancelled."),
        BookingDepositHeldReason::Started => format!("{booking} has started."),
    };
    let holds = match held {
        BookingDepositHeld::CaptureDue => {
            format!("Its deposit of {money} is still due for capture.")
        }
        BookingDepositHeld::Captured => format!("{money} is still held as its deposit."),
        BookingDepositHeld::BalanceAfterRefund => {
            format!("{money} of its deposit is still held after a partial refund.")
        }
        BookingDepositHeld::BalanceAfterOwedRefund => format!(
            "A partial refund of its deposit is owed and not yet made; {money} more is still held."
        ),
    };
    let act = match (return_offered, held) {
        (false, _) => "A host selected when it was confirmed can return it.",
        (true, BookingDepositHeld::CaptureDue) => "Choose Return deposit to release it.",
        (true, BookingDepositHeld::Captured) => "Choose Return deposit to refund it in full.",
        (true, BookingDepositHeld::BalanceAfterRefund) => {
            "Choose Return deposit to refund the balance."
        }
        (true, BookingDepositHeld::BalanceAfterOwedRefund) => {
            "Choose Return deposit to refund the balance once that refund is made."
        }
    };
    format!("{what} {holds} {act}")
}

/// `Booking at <date> <time> (<zone>)`, the slot's start in the owner's
/// zone, or in UTC when the booking froze none or its zone does not
/// resolve.
fn booking_label(start: u64, zone: Option<&str>) -> String {
    let wall = zone
        .and_then(|tz| utc_to_wall(start, tz).ok().map(|wall| (wall, tz)))
        .or_else(|| utc_to_wall(start, "UTC").ok().map(|wall| (wall, "UTC")));
    match wall {
        Some((wall, tz)) => format!(
            "Booking at {:04}-{:02}-{:02} {:02}:{:02} ({tz})",
            wall.y, wall.mo, wall.d, wall.h, wall.mi
        ),
        None => format!("Booking at {start} (Unix seconds)"),
    }
}

/// `amount_minor` of `currency` in its major unit, by the currency's ISO
/// 4217 exponent (`4000` `usd` reads `40.00 USD`); a code with no listed
/// exponent keeps the smallest unit and says so.
fn money(amount_minor: u64, currency: &str) -> String {
    let code = currency.to_ascii_uppercase();
    match crate::connector_key::iso_4217_exponent(&code) {
        Some(0) => format!("{amount_minor} {code}"),
        Some(exponent) => {
            let scale = 10_u64.pow(exponent);
            let width = exponent as usize;
            format!(
                "{}.{:0width$} {code}",
                amount_minor / scale,
                amount_minor % scale
            )
        }
        None => format!("{amount_minor} {code} (in its smallest unit)"),
    }
}
