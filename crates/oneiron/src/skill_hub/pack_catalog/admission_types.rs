//! Source-bound post-fit decisions and install receipts; install never grants authority.
use super::{PackManifest, PackSection, PackSource};
use crate::skill_hub::{ForeignSkillPublisher, HubAskSurface, HubRef};
use crate::{entity_id::EntityId, error::Result};

/// The host's fit ladder evaluates the immutable source and the requested powers.
/// It must not treat installation itself as a grant of those powers.
pub trait PackFitPolicy {
    fn evaluate(
        &self,
        source: &PackSource,
        permissions: &PackPermissions,
    ) -> Result<PackFitVerdict>;
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackPermissions {
    pub bundled_skills: Vec<BundledSkillPermissions>,
    pub widening_bundled_skills: Vec<BundledSkillPermissions>,
    pub grants: Vec<String>,
    pub wakes: Vec<String>,
    pub section_verbs: Vec<String>,
    pub section_authorities: Vec<String>,
    /// Only added powers are the widening passed to the fit ladder.
    pub widening_grants: Vec<String>,
    pub widening_wakes: Vec<String>,
    pub widening_section_verbs: Vec<String>,
    pub widening_section_authorities: Vec<String>,
}
/// A skill's requested capability surface, keyed by the authored skill identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundledSkillPermissions {
    pub skill_id: String,
    pub bins: Vec<String>,
    pub env: Vec<String>,
    pub mcp: Vec<String>,
    pub allowed_tools: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackFitVerdict {
    /// False means the object does not fit and must not install.
    pub fits: bool,
    /// A rule hit keeps the source as Candidate, not as running code.
    pub rules_hit: bool,
    /// Until sandbox tests enable this flag, code-bearing objects are Candidates.
    pub code_auto_install: bool,
}
#[derive(Debug, Clone)]
pub struct PackInstallAsk {
    pub(super) source_id: EntityId,
    pub(super) hub: HubRef,
    pub(super) publisher: ForeignSkillPublisher,
    pub(super) binding: String,
    pub(super) verdict: PackFitVerdict,
    pub(super) manifest: PackManifest,
    pub(super) permissions: PackPermissions,
    pub(super) surface: HubAskSurface,
}
impl PackInstallAsk {
    pub fn source_id(&self) -> EntityId {
        self.source_id
    }
    pub fn manifest(&self) -> &PackManifest {
        &self.manifest
    }
    pub fn permissions(&self) -> &PackPermissions {
        &self.permissions
    }
    pub fn verdict(&self) -> PackFitVerdict {
        self.verdict
    }
    pub fn surface(&self) -> HubAskSurface {
        self.surface
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackInstallStatus {
    Active,
    Candidate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackCandidateReason {
    RulesHit,
    CodeAutoInstallOff,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackInstallReceipt {
    pub source_id: String,
    pub pack_name: String,
    pub content_hash: String,
    pub status: PackInstallStatus,
    pub candidate_reason: Option<PackCandidateReason>,
    pub hub_id: String,
    pub hub_ref: String,
    pub pin_type: String,
    pub pin_value: String,
    pub publisher: String,
    /// The object's card lists requested powers. None is granted by installation.
    pub permissions: PackPermissions,
    /// Typed section recipes from the pinned tree; runtime must enforce requested powers.
    pub sections: Vec<PackSection>,
    pub predicates: Vec<String>,
    pub kinds: Vec<String>,
    pub skills: Vec<String>,
    pub installed_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackInstallDisposition {
    Candidate(Box<PackInstallReceipt>),
    Installed(Box<PackInstallReceipt>),
}
