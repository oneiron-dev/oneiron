//! Portable source files and typed bundle facets. These are not entity kinds.
use serde::{Deserialize, Serialize};

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
    /// A retained fork hash is not a substitute for the actual captured bytes.
    AgentBirthSourceUnavailable,
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
    /// A foreign authority roster, grant, address, credential binding or world key pad is
    /// not a local act.
    LocalAuthorityNotRestored,
    /// Local audit/sequence history remains readable archive data, never replay authority.
    LocalHistoryNotRestored,
    /// Derived cache state is rebuilt from locally admitted inputs.
    LocalProjectionNotRestored,
    /// Device-local routing/binding and owner confidence are not portable authority.
    LocalActorConfigurationNotRestored,
    /// Learning cells are projector-only views, rebuilt from their receipts
    /// after import; the archive row stays archive data.
    LearningCellsRebuiltFromReceipts,
    /// What the engine attested when it inspected something (a signature
    /// event, a section fit receipt): no archive row can attest it again here.
    EngineAttestationNotRestored,
    /// The origin's record of what a repo published, admitted, proposed or
    /// marked: importing the repository again records its own.
    RepoClaimsNotRestored,
    /// The archive's `vault.default_facet` stays archive data: only the owner's
    /// restore into a fresh vault sets this vault's default facet from it.
    TargetDefaultFacetKept,
    /// A claim a MACHINE signed (a Dreamer landing, say): its proof binds the
    /// source vault, and the import never passes a signed write off as an
    /// unsigned one (FIX 3497).
    MachineSignedClaimNotRestored,
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
    /// Typed expression restore needs a host-authenticated local writer and Auto policy.
    LocalExpressionWriterRequired,
    RedactedBody,
    RedactedSource,
}
