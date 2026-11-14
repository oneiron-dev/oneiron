//! Moved from `crates/oneiron/src/inquiry/log.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::ops::Bound;

/// Who settled an inquiry in the member's vault (canon's ladder for an
/// inquiry: standing rows, the companion, the member).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InquiryDecider {
    /// One of the member's saved decisions for this asker.
    StandingRow { row_ref: String },
    /// The member's companion, from the opened scope.
    Companion,
    /// The member. `None` once the member's erase scrubbed it; the decision
    /// stands.
    Member { principal: Option<EntityId> },
    /// Nobody answered: the inquiry expired, or the check-in it waited on
    /// ended without an answer (held, or removed with its asker's erase).
    LetGo,
}
