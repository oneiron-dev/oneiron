//! Moved from `crates/oneiron/src/booking/constraint.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;
use oneiron_model::llm::BudgetLease;
use oneiron_model::llm::CallClass;
use oneiron_model::llm::CallEnvelope;
use oneiron_model::llm::CallPurpose;
use oneiron_model::llm::ContentPart;
use oneiron_model::llm::DeterministicFallback;
use oneiron_model::llm::LlmBackend;
use oneiron_model::llm::LlmMessage;
use oneiron_model::llm::LlmMessageRole;
use oneiron_model::llm::LlmRequest;
use oneiron_model::llm::ModelId;
use oneiron_model::llm::ModelLocality;
use oneiron_model::llm::ResponseFormat;
use oneiron_model::llm::TierPrecedence;
use oneiron_store::model_decision::AnswerContract;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::DecisionBand;
use oneiron_store::model_decision::DecisionBandPolicy;
use oneiron_store::model_decision::DecisionDial;
use oneiron_store::model_decision::DecisionRung;
use oneiron_store::model_decision::ProviderPin;
use oneiron_store::model_decision::Reversibility;
use oneiron_store::model_decision::catalogue::BOOKING_OFF_TOPIC;
use oneiron_store::retrieval_deadline::RetrievalDeadline;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde_json::Value as JsonValue;
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;
use std::time::Instant;

/// Wire version of [`ConstraintObject`]. A payload carrying any other version
/// fails closed rather than being coerced.
pub const CONSTRAINT_SCHEMA_VERSION: u16 = 1;

/// Exclusive upper bound for a local-minute-of-day.
pub const MINUTES_PER_DAY: u16 = 1440;

/// Host-configured event type. Configuration for the type (duration, pool,
/// flex policy) is ONE-1823's `EventTypeConfig`; the key alone lives here.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, schemars::JsonSchema)]
#[serde(transparent)]
pub struct EventTypeKey(pub String);

// -------------------------------------------------------------------------
// Normalized constraint
// -------------------------------------------------------------------------

/// Weekday axis of a normalized constraint.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintWeekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Half-open local-minute-of-day window.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct LocalMinuteWindow {
    /// Inclusive, `0..1440`.
    pub start_minute: u16,
    /// Exclusive, `start < end <= 1440`.
    pub end_minute: u16,
}

pub fn is_strictly_ascending<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// One slot the oracle chose. UTC times are the oracle's; no caller rewrites,
/// rounds, or invents them.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, schemars::JsonSchema)]
pub struct RankedSlot {
    pub start_utc: u64,
    pub end_utc: u64,
    pub rank: f32,
}
