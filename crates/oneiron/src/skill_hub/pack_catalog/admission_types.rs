//! Source-bound qualification, owner asks, and inert installation receipts.
use super::{PackAdapter, PackManifest, PackSource};
use crate::skill_hub::{ForeignSkillPublisher, HubAskSurface, HubRef};
use crate::{consent::EffectDigest, entity_id::EntityId, error::Result};

/// Host-owned switch for automatic code import. Default off until the
/// provisioned foreign sandbox suite passes. This is never read from PACK.md.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PackCodeAutoInstall {
    #[default]
    Disabled,
    EnabledAfterSandboxTests,
}

/// Host callback qualifies these exact files. A code-running qualification step
/// must use the foreign code-mode sandbox under the object's grant, never a
/// host interpreter. No built-in passing verdict or execution right exists.
pub trait PackQualifier {
    fn qualify(&self, source: &PackSource) -> Result<PackQualification>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackQualification {
    pub suite: String,
    /// Hash of the host's reproducible test/advisory report.
    pub report_hash: String,
    pub passed: bool,
    pub advisory_accepted: bool,
    pub advisory: String,
    /// Required for connector/code packs; fingerprints a provisioned runtime.
    pub runtime: Option<PackRuntimeRecipe>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRuntimeRecipe {
    pub adapter: PackAdapter,
    pub runtime_id: String,
    pub runtime_hash: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackInstallAsk {
    pub(super) source_id: EntityId,
    pub(super) hub: HubRef,
    pub(super) publisher: ForeignSkillPublisher,
    pub(super) binding: String,
    pub(super) effect: EffectDigest,
    pub(super) qualification: PackQualification,
    pub(super) manifest: PackManifest,
    pub(super) surface: HubAskSurface,
}
impl PackInstallAsk {
    pub fn source_id(&self) -> EntityId {
        self.source_id
    }
    pub fn manifest(&self) -> &PackManifest {
        &self.manifest
    }
    pub fn qualification(&self) -> &PackQualification {
        &self.qualification
    }
    pub fn surface(&self) -> HubAskSurface {
        self.surface
    }
    pub fn effect_digest(&self) -> EffectDigest {
        self.effect
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackInstallReceipt {
    pub source_id: String,
    pub pack_name: String,
    pub content_hash: String,
    pub consent_digest: String,
    pub qualification_report_hash: String,
    /// Provisioned recipe as data. Execution must still use the ordinary action gate.
    pub runtime: Option<PackRuntimeRecipe>,
    pub hub_id: String,
    pub publisher: String,
    /// A slate of requested powers, not a standing grant.
    pub requested_grants: Vec<String>,
    /// Subscriptions remain inert until a separately authorized runtime binds them.
    pub wake_subscriptions: Vec<String>,
    pub predicates: Vec<String>,
    pub kinds: Vec<String>,
    /// Candidate imports; activation still requires their individual held-out door.
    pub candidate_skills: Vec<String>,
    pub installed_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackInstallDisposition {
    /// Auto-import of code while its host sandbox switch is off. The same
    /// immutable ask is the permission card; no grant or runtime is active.
    CodeCandidate(Box<PackInstallAsk>),
    PendingConsent,
    Installed(Box<PackInstallReceipt>),
}
