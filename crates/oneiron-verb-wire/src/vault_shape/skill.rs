//! Moved from `crates/oneiron/src/vault_shape/skill.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::vault_shape::invalid;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;
use oneiron_store::write_envelope::skill_record::SkillLifecycle;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// A skill's hub source as plain fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum ShapeSkillSource {
    /// The shipped library, by subtree, at the released commit.
    Library { subtree: String },
    /// A configured hub (entity id hex): the skill's folder there, a pin,
    /// and the publisher to admit for it.
    Hub {
        hub: String,
        folder: String,
        /// `semver`, `tag`, `commit` or `content_hash`.
        pin_type: String,
        pin_value: String,
        publisher: String,
    },
}

impl ShapeSkillSource {
    /// The door an import from this source lands through.
    pub const fn door(&self) -> &'static str {
        match self {
            Self::Library { .. } => "import_default_hub_skill",
            Self::Hub { .. } => "import_skill_from_hub_ref",
        }
    }
}
