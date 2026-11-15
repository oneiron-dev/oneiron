//! Moved from `crates/oneiron/src/skill/helper.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::skill::call::frozen::amend::CallableAmendOutcome;
pub use oneiron_verb_wire::skill::call::frozen::amend::CallableAmendRequest;
pub use oneiron_verb_wire::skill::helper::CallableCard;
pub use oneiron_verb_wire::skill::helper::CallableCardView;
pub use oneiron_verb_wire::skill::helper::SkillForkRequest;
pub use oneiron_verb_wire::skill::helper::SkillSaveRequest;
pub use oneiron_verb_wire::skill::helper::SkillSourceFile;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;

pub fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

/// One frozen case: the arguments a call took and the result it should give.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallableCase {
    /// The receipt or task the case was frozen from.
    pub case_ref: String,
    pub arguments: JsonValue,
    pub expected: JsonValue,
    /// Who supplied the case. A helper's own author never supplies its gate.
    pub source_author: Option<EntityId>,
}

/// What the shared paired measurement says of a helper against its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperPairedVerdict {
    /// Its sufficiency card found the helper not worse.
    NotWorse,
    /// Its card found the helper worse.
    Worse,
    /// No finished card yet, or one that reads unknown.
    Pending,
}
