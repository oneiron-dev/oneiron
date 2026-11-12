//! Moved from `crates/oneiron/src/skill/call/frozen/amend.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;

/// `vault.skills.callable.amend`: the caller of one callable call records
/// the answer the call should have given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallableAmendRequest {
    /// The attempt pack receipt of the run that made the call.
    pub receipt: String,
    /// The call's step seq in that run.
    pub seq: u64,
    /// The corrected answer, as the skill's contract returns it.
    pub answer: JsonValue,
}

/// What an amendment came to. None of these is a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CallableAmendOutcome {
    /// The call's case now expects the corrected answer.
    Refrozen,
    /// The call has no frozen case the amender may amend: it did not pass
    /// its contract, was too long to keep, was trimmed or erased since,
    /// never ran, or was another caller's. Nothing is stored.
    NoCase,
    /// The corrected answer is longer than the `[limits]
    /// maintenance_text_bytes` row: the row asked, and nothing is stored.
    OverLimit,
}

/// The answer of `vault.skills.callable.amend`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CallableAmendReceipt {
    pub outcome: CallableAmendOutcome,
    /// The skill entity whose case it is, hex; `None` with no case.
    pub skill: Option<String>,
}

impl CallableAmendReceipt {
    fn no_case() -> Self {
        Self {
            outcome: CallableAmendOutcome::NoCase,
            skill: None,
        }
    }
}
