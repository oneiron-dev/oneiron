//! Moved from `crates/oneiron/src/booking/agent_front.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::constraint::ConstraintObject;
use crate::booking::constraint::EventTypeKey;

/// The rung-2 envelope. It carries the same canonical constraint the oracle
/// saw and no raw free text.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, schemars::JsonSchema)]
pub struct ConstraintContinuation {
    pub event_type: EventTypeKey,
    pub visitor_tz: String,
    pub constraint: ConstraintObject,
    pub session_ref: String,
}
