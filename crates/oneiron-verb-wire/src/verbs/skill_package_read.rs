//! Moved from `crates/oneiron/src/verbs/skill_package_read.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::verbs::skills::SkillCapabilityView;
use crate::verbs::skills::SkillLibraryCall;
use crate::verbs::skills::SkillLibraryDependency;
use crate::verbs::skills::SkillLibraryFile;
use crate::verbs::skills::SkillLibraryLifecycle;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::skill_source::SkillPackageFormat;
use serde::Deserialize;
use serde::Serialize;

/// `self.skills.package`'s record on the wire: every `SkillRecord` field.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillPackageRecordView {
    pub skill_id: String,
    pub desc: String,
    pub version: String,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: SkillLibraryLifecycle,
    pub source: ClaimSource,
    pub confidence: f32,
    pub generated: bool,
    pub human_authored: bool,
    pub dependencies: Vec<SkillLibraryDependency>,
    pub provenance: serde_json::Value,
    pub content_hash: Option<String>,
    pub forked_from: Option<EntityId>,
    pub governance_tier: Option<String>,
    pub role: String,
    pub call: Option<SkillLibraryCall>,
}

/// `self.skills.package`'s answer: the skill's record with its runtime package's
/// files, capabilities and format. A missing, withheld, non-skill or unloadable
/// skill answers none, never this.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillPackageView {
    pub entity: EntityId,
    pub record: SkillPackageRecordView,
    pub files: Vec<SkillLibraryFile>,
    pub capabilities: SkillCapabilityView,
    /// How source fields relate to native metadata, as the stored package
    /// declares it.
    pub format: SkillPackageFormat,
}
