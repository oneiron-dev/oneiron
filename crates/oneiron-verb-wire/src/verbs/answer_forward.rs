//! Moved from `crates/oneiron/src/verbs/answer_forward.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `tasks.answer.forward.status`'s input: the intent a relay answered with
/// (FIX 20468). Only the intent's own holder reads where it stands.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAnswerForwardStatusRequest {
    /// The receipt's `intent_ref`, 32 hex.
    pub intent_ref: EntityId,
}
