//! Source-bound post-fit decisions and install receipts; install never grants authority.
use super::{PackAdapter, PackKind, PackManifest, PackSection, PackSource};
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

    /// A code-running qualification must use the foreign code-mode sandbox
    /// under the object's grant. Script packs cannot become Active without a
    /// source-bound qualified runtime; a flag-off Candidate needs no run yet.
    fn qualify_script(&self, _source: &PackSource) -> Result<Option<PackQualification>> {
        Ok(None)
    }

    /// A connector, including an engine-built adapter, stays Candidate until
    /// the engine probes its source-bound wire contract. A script qualification
    /// alone cannot activate a connector.
    fn qualify_connector(&self, _source: &PackSource) -> Result<Option<PackQualification>> {
        Ok(None)
    }

    /// Host-observed tool surfaces from the pinned source's actual adapter.
    /// Empty is a declaration of no external tool surface, not a passing scan.
    fn observed_tools(&self, _source: &PackSource) -> Result<Vec<PackObservedTool>> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackObservedTool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

pub trait PackQualifier {
    fn qualify(&self, source: &PackSource) -> Result<PackQualification>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackQualification {
    pub suite: String,
    pub report_hash: String,
    pub passed: bool,
    pub advisory_accepted: bool,
    pub advisory: String,
    pub runtime: Option<PackRuntimeRecipe>,
    pub connector: Option<super::ConnectorPackQualification>,
}
#[doc(hidden)]
pub use oneiron_verb_wire::skill_hub::pack_catalog::admission_types::{
    BundledSkillPermissions, PackCandidateReason, PackInstallStatus, PackPermissions,
    PackRuntimeRecipe,
};

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
    pub(super) qualification: Option<PackQualification>,
    pub(super) surface: HubAskSurface,
    pub(super) observed_tools: Vec<PackObservedTool>,
    pub(super) blocked_reason: Option<String>,
    pub(super) scan_risk: Option<crate::skill_hub::ScanRiskLevel>,
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
    pub fn qualification(&self) -> Option<&PackQualification> {
        self.qualification.as_ref()
    }
    pub fn surface(&self) -> HubAskSurface {
        self.surface
    }
    pub fn blocked_reason(&self) -> Option<&str> {
        self.blocked_reason.as_deref()
    }
    /// Hash-bound scanner signal only; a rule decides blocking.
    pub fn scan_risk(&self) -> Option<crate::skill_hub::ScanRiskLevel> {
        self.scan_risk
    }
}
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PackInstallReceipt {
    pub source_id: String,
    pub pack_name: String,
    pub content_hash: String,
    pub kind: PackKind,
    pub adapter: Option<PackAdapter>,
    /// Present only for an engine-embedded source; this is provenance, not authority.
    pub engine_version: Option<String>,
    pub status: PackInstallStatus,
    pub candidate_reason: Option<PackCandidateReason>,
    pub hub_id: String,
    pub hub_ref: String,
    pub pin_type: String,
    pub pin_value: String,
    pub publisher: String,
    /// The object's card lists requested powers. None is granted by installation.
    pub permissions: PackPermissions,
    /// Qualified source/runtime as data. A Candidate has no execution right.
    pub qualification_report_hash: Option<String>,
    pub connector_qualification: Option<super::PackConnectorReceipt>,
    pub runtime: Option<PackRuntimeRecipe>,
    /// Typed section recipes from the pinned tree; runtime must enforce requested powers.
    pub sections: Vec<PackSection>,
    pub predicates: Vec<String>,
    pub kinds: Vec<String>,
    pub skills: Vec<String>,
    /// The agent an active travelling AgentPack minted, hex (OF-491).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The agent whose own local pack this is, hex, as its put door verified
    /// it; `None` for the owner's and the hub's installs. An owner door that
    /// completes the held install mints its travelling agent through the
    /// author writer under this agent, verified again (ARCH-0053:20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_author: Option<String>,
    pub installed_at: u64,
    /// A travelling agent's world whose current setting does not cover this
    /// machine: "please double-check", kept with the install, which landed
    /// all the same (FIX 5493).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<crate::share_travel::WorldRecipientNotice>,
    /// The holds the owner lifted on these exact bytes through
    /// `Vault::activate_pack_candidate`: the owner activated this install.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_activated: Vec<PackCandidateReason>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackInstallDisposition {
    Blocked { reason: String },
    Candidate(Box<PackInstallReceipt>),
    Installed(Box<PackInstallReceipt>),
}
