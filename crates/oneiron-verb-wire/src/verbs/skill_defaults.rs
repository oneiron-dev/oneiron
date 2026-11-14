//! Moved from `crates/oneiron/src/verbs/skill_defaults.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::verbs::skills::SkillLibraryView;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::skill_source::hub_record::HubRef;
use serde::Deserialize;
use serde::Serialize;

/// The expected build source beside the actual resident. Absence is reported,
/// never repaired by a read, and resident files are not replaced by build bytes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BootstrapSkillView {
    pub skill_id: String,
    pub content_hash: String,
    pub source: HubRef,
    pub resident: Option<SkillLibraryView>,
}

impl BootstrapSkillView {
    pub fn rows(&self) -> Vec<EntityId> {
        self.resident
            .as_ref()
            .map_or_else(Vec::new, SkillLibraryView::rows)
    }
}
