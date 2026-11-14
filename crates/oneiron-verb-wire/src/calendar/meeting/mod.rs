//! Moved from `crates/oneiron/src/calendar/meeting/mod.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::outcome;
use crate::calendar::outcome::EventOutcome;
use crate::calendar::outcome::EventOutcomeClaimValue;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarMeetingRequest {
    pub event_ref: String,
}

/// The vault-scope `calendar_outcome_grace_seconds` policy row the owner reads
/// and writes through the policy manifest
/// (`gate::policy_manifest_doors::set_calendar_outcome_grace_as_owner`); never
/// a caller-supplied clock or evidence signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarOutcomePolicy {
    pub grace_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarEventOutcome {
    pub event_ref: String,
    pub outcome: EventOutcome,
    pub claim: Option<EventOutcomeClaimValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarCheckInDue {
    pub event_ref: String,
    pub observed_at: u64,
    pub grace_secs: u64,
    pub due_at: Option<u64>,
    pub due: bool,
    pub outcome: Option<EventOutcomeClaimValue>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CalendarCheckInAnswer {
    Held,
    NoShow,
    Rescheduled,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarCheckInRequest {
    pub event_ref: String,
    pub answer: CalendarCheckInAnswer,
}

/// A reschedule disposition routes the consumer to scheduling; it is not an outcome.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum CalendarCheckInReceipt {
    Outcome {
        event_ref: String,
        claim_ref: String,
        value: EventOutcomeClaimValue,
    },
    RescheduleRequested {
        event_ref: String,
        claim_ref: String,
        value: EventOutcomeClaimValue,
    },
}
