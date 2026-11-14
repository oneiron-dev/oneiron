//! Moved from `crates/oneiron/src/booking/conversion/ux.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::booking::constraint::RankedSlot;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The first-ranked slot is the recommended one; the rest remain available
/// through a separate see-more action. Never re-rank the solver's answer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BookingShortlist {
    pub recommended: Option<RankedSlot>,
    pub visible: Vec<RankedSlot>,
    pub more_count: usize,
}

/// Copy/CTA posture chosen by a resolved notification-policy row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReminderAction {
    RescheduleFirst,
    Neutral,
}

/// Stable index across moves; a configured policy may have zero to eight
/// reminder steps. The host replaces a wake with the same event/index id.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReminderStep(pub u8);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurableReminderWake {
    pub id: String,
    /// Canonical hex, never an authority token or public page address.
    pub event_ref: String,
    pub expected_start_utc: u64,
    pub due_utc: u64,
    pub step: ReminderStep,
    pub action: ReminderAction,
}

/// The IANA identifier itself is the label (never an ambiguous abbreviation).
/// UTC is only an instant, not a fallback display zone. Both parties use the
/// calendar's single conversion border and the same instant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZonedBookingTime {
    pub utc: u64,
    pub zone: String,
    pub local: String,
}
