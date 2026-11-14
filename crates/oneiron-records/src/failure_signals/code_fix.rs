//! Moved from `crates/oneiron/src/failure_signals/code_fix.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::failure_signals::FailureClassV1;
pub use crate::failure_signals::code_fix::exact::ReplayFidelity;
pub(super) use crate::failure_signals::code_fix::queue::CodeFixShare;
use oneiron_contracts::entity_id::EntityId;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventedRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventedMessage {
    pub role: InventedRole,
    pub text: String,
}

/// What a code fix is for (OF-380): a failure-ladder case, or a blocked
/// report the Coach filed a heal for with no failed case behind it. Each door
/// checks that it still stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeFixSource {
    /// A durable failed case, by its ref.
    Case { case_ref: String },
    /// A blocked report, by its receipt, and the durable run that filed it,
    /// if it had one. A pumped agent's run id is its attempt's id.
    Blocked {
        receipt: EntityId,
        run: Option<EntityId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventedFailureExample {
    pub version: u16,
    /// Random; derived from nothing in the vault.
    pub example_id: String,
    pub failure_class: FailureClassV1,
    pub note: String,
    pub conversation: Vec<InventedMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixOutcome {
    Fixed,
    NotFixed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateFixResult {
    pub version: u16,
    /// Random; derived from nothing in the vault.
    pub result_id: String,
    pub candidate_id: String,
    pub example_id: Option<String>,
    pub failure_class: FailureClassV1,
    pub outcome: FixOutcome,
}

/// The only shapes a code-fix export takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeFixExport {
    InventedExample(InventedFailureExample),
    FixResult(CandidateFixResult),
}

impl CodeFixExport {
    /// The record's public id, which [`Vault::ack_code_fix_records`] takes.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::InventedExample(example) => &example.example_id,
            Self::FixResult(result) => &result.result_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeFixWithheld {
    /// This deployment does not export.
    NotEligible,
    /// No durable failed case, or blocked report its run filed, by that
    /// source.
    UnknownCase,
    /// The failure touched a private world, or one whose privacy is unknown:
    /// its tier-1 counts are all that leaves.
    PrivateWorld,
    /// The vault holds no text of the failure: no instructions, briefing
    /// or task.
    SourceUnavailable,
    /// The draft or candidate is out of shape.
    Malformed,
    /// The example copies a span of the real chat.
    VerbatimSpan,
    /// The example carries a credential shape.
    Credential,
    /// The scrubber flagged the example or could not judge it.
    Scrubber,
    /// The invented conversation does not fail the same way.
    NotReproduced,
    /// The host has no replay for this case.
    ReplayUnavailable,
    /// The Coach drafted no example for it.
    NotDrafted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum CodeFixVerdict {
    /// Sealed and waiting for [`Vault::pending_code_fix_records`]; `id` is
    /// the record's public id.
    Queued {
        id: String,
    },
    Withheld {
        reason: CodeFixWithheld,
    },
}
pub mod exact;
pub mod queue;
