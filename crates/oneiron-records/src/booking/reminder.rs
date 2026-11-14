//! Moved from `crates/oneiron/src/booking/reminder.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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
