//! Booking reminder planning, without a process timer or outbound side effect.
//!
//! The host owns exact wake custody, message copy, delivery, and the live
//! booking/passport re-read at due time. A plan is not permission to send.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::booking::BookingStatus;
use crate::calendar::EventOutcome;

/// The two default leads: a day before and two hours before the event.
pub const BOOKING_REMINDER_LEADS_SECS: [u64; 2] = [86_400, 7_200];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingReminderStage {
    DayBefore,
    TwoHoursBefore,
}

impl BookingReminderStage {
    const fn tag(self) -> &'static str {
        match self {
            Self::DayBefore => "booking.reminder.day_before",
            Self::TwoHoursBefore => "booking.reminder.two_hours_before",
        }
    }
}

/// Exact wake: stable id allows the host to replace a stale wake on reschedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookingReminderWake {
    pub id: String,
    pub at_utc: u64,
    pub reason_tag: String,
    pub event_ref: EntityId,
    pub expected_start_utc: u64,
    pub stage: BookingReminderStage,
}

/// Plan up to two future wakes for a confirmed booking. A late booking does
/// not create a retroactive reminder, and a booking already started gets none.
#[must_use]
pub fn plan_booking_reminders(
    event_ref: EntityId,
    start_utc: u64,
    now_utc: u64,
) -> Vec<BookingReminderWake> {
    [
        BookingReminderStage::DayBefore,
        BookingReminderStage::TwoHoursBefore,
    ]
    .into_iter()
    .zip(BOOKING_REMINDER_LEADS_SECS)
    .filter_map(|(stage, lead)| {
        let at_utc = start_utc.checked_sub(lead)?;
        (at_utc > now_utc).then(|| BookingReminderWake {
            id: format!("{}:{}", stage.tag(), event_ref.to_hex()),
            at_utc,
            reason_tag: stage.tag().to_owned(),
            event_ref,
            expected_start_utc: start_utc,
            stage,
        })
    })
    .collect()
}

/// Recheck the current status and start read from the vault at the due time.
/// A stale wake after cancel/reschedule must not send. A future or late
/// duplicate is not due either; delivery dedupe remains the host's job.
#[must_use]
pub fn booking_reminder_is_due(
    wake: &BookingReminderWake,
    now_utc: u64,
    current_status: BookingStatus,
    current_start_utc: u64,
) -> bool {
    plan_booking_reminders(wake.event_ref, current_start_utc, 0)
        .iter()
        .any(|planned| planned == wake)
        && current_status == BookingStatus::Confirmed
        && current_start_utc == wake.expected_start_utc
        && now_utc >= wake.at_utc
        && now_utc < current_start_utc
}

/// An advisory, not a payment or bearer-grant mutation. Only recorded CAL-07
/// outcomes for this booker should be passed in, never guessed from elapsed time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoShowEscalation {
    None,
    OfferConfirmLink,
}

#[must_use]
pub fn booking_no_show_escalation(recorded_history: &[EventOutcome]) -> NoShowEscalation {
    if recorded_history
        .iter()
        .filter(|outcome| **outcome == EventOutcome::NoShow)
        .take(2)
        .count()
        == 2
    {
        NoShowEscalation::OfferConfirmLink
    } else {
        NoShowEscalation::None
    }
}

#[cfg(test)]
#[path = "reminder/tests.rs"]
mod tests;
