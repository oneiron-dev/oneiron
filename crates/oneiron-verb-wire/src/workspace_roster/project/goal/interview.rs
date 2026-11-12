//! Moved from `crates/oneiron/src/workspace_roster/project/goal/interview.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::attempt_manifest::ManifestKind;
use crate::workspace_roster::project::invalid;
use heed::RoTxn;
use heed::RwTxn;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_MESSAGE;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// Four witnessed turns of one agent question, human answer, agent draft, human confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoalInterviewTurns {
    pub question: EntityId,
    pub answer: EntityId,
    pub draft: EntityId,
    pub confirmation: EntityId,
}

impl GoalInterviewTurns {
    /// The digest a human confirms: the project's goal generation, recorded
    /// when the draft was shown (8 bytes, big-endian), then the draft's bytes.
    pub fn confirmation_digest(draft: &str, generation: u64) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&generation.to_be_bytes());
        hasher.update(draft.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}
