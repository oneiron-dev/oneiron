//! Versioned six-part whole-vault interchange document.
use serde::{Deserialize, Serialize};

use super::{ExportManifest, ExportSerializerManifest, VaultImportReceipt};
use crate::error::{Error, Result};
use crate::serialize::{ExportBody, ExportValue};

pub const WHOLE_VAULT_DOCUMENT_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WholeVaultDocumentManifest {
    pub manifest_version: u16,
    pub format: String,
    pub serializer: ExportSerializerManifest,
    pub secrets_nulled: bool,
    pub source_vault: ExportSourceVault,
    /// Existing ABI/DB/authority validation is retained, not reimplemented.
    pub storage: ExportManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSourceVault {
    pub vault_id: Option<String>,
    pub exported_at: u64,
}

impl WholeVaultDocumentManifest {
    pub(crate) fn validate_json(&self) -> Result<()> {
        self.validate(crate::context_pack::PackFormat::Json)
    }

    /// Validate the versioned manifest for the format being consumed.
    pub fn validate(&self, format: crate::context_pack::PackFormat) -> Result<()> {
        let format = match format {
            crate::context_pack::PackFormat::Json => "json",
            crate::context_pack::PackFormat::Yaml => "yaml",
            crate::context_pack::PackFormat::Toon => "toon",
            crate::context_pack::PackFormat::Markdown => "markdown",
            crate::context_pack::PackFormat::Plaintext => "plaintext",
        };
        if self.manifest_version != WHOLE_VAULT_DOCUMENT_VERSION
            || self.format != format
            || self.serializer != ExportSerializerManifest::current()
            || !self.secrets_nulled
            || !self.storage.redacted()
            || !self.storage.structurally_secret_nulled()
            || self.source_vault.vault_id.as_deref()
                != self
                    .storage
                    .authority()
                    .map(super::ExportAuthorityManifest::vault_id)
        {
            return Err(Error::InvalidConfig(
                "unsupported whole-vault JSON manifest".to_owned(),
            ));
        }
        self.storage.validate_import_supported()
    }
}

/// An archive payload and its standalone validating manifest. Fields are private:
/// only the serializer can produce the credential-nulling proof on this result.
#[derive(Debug, Clone)]
pub struct WholeVaultExport {
    pub(crate) bytes: Vec<u8>,
    pub(crate) manifest: WholeVaultDocumentManifest,
}

impl WholeVaultExport {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn manifest(&self) -> &WholeVaultDocumentManifest {
        &self.manifest
    }
    pub fn manifest_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(&self.manifest)
            .map_err(|_| Error::InvariantViolation("whole-vault manifest serialization failed"))
    }
}

/// Exactly six sections. Entities occur once. Derived evidence is an index into
/// claim evidence, not a second authoritative body. Structural graph edges live
/// beside the evidence ledger and carry full value metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WholeVaultDocument {
    pub manifest: WholeVaultDocumentManifest,
    pub evidence_ledger: ExportLedger,
    pub claims: Vec<ExportEntity>,
    pub packs: Vec<ExportAdapterDescriptor>,
    pub skills: Vec<ExportEntity>,
    pub agent_packs: Vec<ExportEntity>,
    pub derivation_envelopes: Vec<ExportDerivationEnvelope>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportLedger {
    pub entities: Vec<ExportEntity>,
    pub edges: Vec<ExportEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEntity {
    pub id: String,
    pub entity_type: u8,
    pub occurred_start: u64,
    pub occurred_end: u64,
    pub learned_at: u64,
    pub body: ExportBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEdge {
    pub source: String,
    pub kind: u8,
    pub target: String,
    pub weight: f32,
    pub created_at: u64,
    pub vad: Option<[f32; 3]>,
    pub provenance: Option<[u8; 2]>,
}

/// Built-in adapters are code registrations, not runtime SKILL records. The
/// descriptor identifies the decoder; it does not claim to contain its code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportAdapterDescriptor {
    pub source_id: String,
    pub adapter_skill_id: Option<String>,
    pub adapter_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportDerivationEnvelope {
    pub id: String,
    pub evidence: ExportValue,
}

#[derive(Debug, Clone)]
pub struct WholeVaultImportReceipt {
    pub authority: VaultImportReceipt,
    pub inserted_entities: usize,
    pub unchanged_entities: usize,
}

impl WholeVaultDocument {
    pub(crate) fn entities(&self) -> impl Iterator<Item = &ExportEntity> {
        self.evidence_ledger
            .entities
            .iter()
            .chain(self.claims.iter())
            .chain(self.skills.iter())
            .chain(self.agent_packs.iter())
    }
}
