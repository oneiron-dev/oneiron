//! Moved from `crates/oneiron/src/llm/model_pack/change.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::llm::model_pack::change::ModelPackRevertBlock;
pub use oneiron_verb_wire::llm::model_pack::change::ModelPackRevertRequest;
use serde::Deserialize;
use serde::Serialize;

/// What moved the pack the vault follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelPackChangeCause {
    /// A model pack's install.
    Install,
    /// A model pack's removal.
    Removal,
    /// The owner's own preference.
    Preference,
    /// The active pack, or the pack a pin named, retired (FIX 5368).
    Retirement,
    /// The owner's revert of the change before (FIX 5369).
    Revert,
    /// The owner moved a hub ref's pin or policy, which changes the model
    /// packs it admits (review #6390).
    HubRefPin,
}

impl ModelPackChangeCause {
    /// The cause in the owner's notice.
    fn text(self) -> &'static str {
        match self {
            Self::Install => "a model pack install",
            Self::Removal => "a model pack removal",
            Self::Preference => "the owner's model pack setting",
            Self::Retirement => "a model pack retirement",
            Self::Revert => "a revert",
            Self::HubRefPin => "a hub ref pin change",
        }
    }
}
