//! Moved from `crates/oneiron/src/vault_shape/shared_setup.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// What an apply did with the conversation-learning answer it carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeLearningOutcome {
    /// The answer: `true` turns conversation learning on, `false` off.
    pub requested: bool,
    /// Whether the setting's setter wrote it.
    pub written: bool,
    /// Whether the answer went unread: an actor's apply, or one that created
    /// no shared vault.
    pub ignored: bool,
    /// The setting as read after; `None` when it could not be read.
    pub resulting: Option<ShapeLearningSetting>,
    /// Why the answer was not written, when it was not.
    pub reason: Option<String>,
}

/// The vault's conversation-learning setting, as an apply's receipt states
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeLearningSetting {
    /// Whether it is on.
    pub on: bool,
    /// Its revision, 64 hex.
    pub revision: String,
    /// The authority entry of the choice in force, 64 hex; `None` while none
    /// counts.
    pub act: Option<String>,
}
