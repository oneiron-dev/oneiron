//! Portable source files and typed bundle facets. These are not entity kinds.
use super::ExportEntity;
use serde::{Deserialize, Serialize};

/// UTF-8 source stays exact. Opaque or credential-bearing files are nulled,
/// never base64-encoded around the mandatory serializer inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSourceFile {
    pub path: String,
    pub content: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportFileTree {
    /// Canonical skill-tree SHA-256 law, also used for agent folders.
    /// Absent whenever any file is redacted; never a false identity claim.
    pub content_hash: Option<String>,
    pub files: Vec<ExportSourceFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSkillBundle {
    pub entity: ExportEntity,
    /// Actual persisted SKILL.md/scripts, not a rendering of the record metadata.
    pub source_tree: Option<ExportFileTree>,
    /// Source syntax, never an approval or a provenance assertion.
    pub source_format: Option<crate::skill_hub::SkillPackageFormat>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportAgentBundle {
    /// Names the actual AGENT_DEF row in the evidence ledger.
    pub entity_id: String,
    /// Locally captured birth/fork identity, or untrusted lineage from an imported
    /// archive (the owning row carries Imported source). Never a current-parent guess.
    #[serde(rename = "forkHash")]
    pub fork_hash: Option<String>,
    pub source_tree: Option<ExportFileTree>,
    pub omission: Option<AgentBundleOmission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentBundleOmission {
    ForkBindingUnavailable,
    UnresolvedSkill,
    CredentialRedaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportBundleOmission {
    pub entity_id: String,
    pub reason: BundleOmissionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleOmissionReason {
    SkillSourceUnavailable,
    SkillSourceRedacted,
    AgentForkBindingUnavailable,
    AgentUnresolvedSkill,
    AgentCredentialRedaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportImportOmission {
    pub entity_id: String,
    pub reason: ImportOmissionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportOmissionReason {
    /// Never restore a publisher's provenance or scanner verdict as local authority.
    ForeignSkillSignalNotRestored,
    /// A local scan materializes its own anchor; the archive cannot create one.
    SkillAnchorRecomputed,
    /// A hub's endpoint/trust/sync policy needs separate local configuration.
    HubConfigurationNotRestored,
    /// Policy bodies remain archive data; only a local authority can install policy.
    PolicyAuthorityNotRestored,
    /// A foreign authority roster, grant, address or credential binding is not a local act.
    LocalAuthorityNotRestored,
    /// Local audit/sequence history remains readable archive data, never replay authority.
    LocalHistoryNotRestored,
    /// Derived cache state is rebuilt from locally admitted inputs.
    LocalProjectionNotRestored,
    /// A witness MESSAGE needs live witness authorization; an archive supplies none.
    WitnessAuthorizationNotRestored,
    /// Attributed NOTE authorship is not conferred on the importing actor.
    NoteAuthorshipNotRestored,
    /// Device-local routing/binding and owner confidence are not portable authority.
    LocalActorConfigurationNotRestored,
}

/// Foundations not stored as vault-owned source. Never fabricate PACK.md/code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportSourceBoundary {
    PredicatePackCatalogUnavailable,
    BuiltinAdapterCodeNotStored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExportImportRefusal {
    Entity {
        entity_id: String,
        reason: ImportRefusalReason,
    },
    ProvenancedEdge {
        source: String,
        edge_kind: u8,
        target: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportRefusalReason {
    OwningEntityAdapterRequired,
    OwningClaimAdapterRequired,
    RedactedBody,
    RedactedSource,
}
