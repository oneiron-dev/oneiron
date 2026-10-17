//! The typed whole-vault document: what the archive's JSONL rows assemble
//! into on import, and what the snapshot builds before the archive is cut.
use serde::{Deserialize, Serialize};

use super::{
    ArchiveFile, ArchiveRecordFile, ExportAgentBundle, ExportBundleOmission, ExportDiaryHold,
    ExportImportOmission, ExportImportRefusal, ExportManifest, ExportSerializerManifest,
    ExportSkillBundle, ExportSourceBoundary, VAULT_ARCHIVE_FORMAT, VaultImportReceipt,
};
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
    /// Exact archive-only rows. Local scans are re-derived; foreign signals and
    /// hub authority are retained in the archive, not restored into local state.
    pub import_omissions: Vec<ExportImportOmission>,
    /// Known refusals remain executable admission errors, not a replay option.
    pub import_refusals: Vec<ExportImportRefusal>,
    /// Missing or redacted source bundles, never presented as complete archives.
    pub bundle_omissions: Vec<ExportBundleOmission>,
    pub source_boundaries: Vec<ExportSourceBoundary>,
    /// The archive's JSONL files, one per record kind.
    pub records: Vec<ArchiveRecordFile>,
    /// The attached files, each once under its BLAKE3.
    pub files: Vec<ArchiveFile>,
    /// OF-490: agents whose diaries this export holds out.
    pub diary_holds: Vec<ExportDiaryHold>,
    /// Whether this archive carries custody secret values (the default for
    /// the owner's own archive) or each custody record as its handle only.
    pub secrets_included: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportSourceVault {
    pub vault_id: Option<String>,
    pub exported_at: u64,
}

impl WholeVaultDocumentManifest {
    /// Validate the versioned manifest of a whole-vault archive.
    pub fn validate(&self) -> Result<()> {
        if self.source_boundaries != [ExportSourceBoundary::BuiltinAdapterCodeNotStored]
            || self.manifest_version != WHOLE_VAULT_DOCUMENT_VERSION
            || self.format != VAULT_ARCHIVE_FORMAT
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
                "unsupported whole-vault archive manifest".to_owned(),
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
    /// OF-490: the diaries this export read, for the vault's own log.
    pub(crate) diary_reads: Vec<super::ExportDiaryRead>,
}

impl WholeVaultExport {
    /// The archive: a ZIP of `manifest.json`, `records/*.jsonl` and `files/*`.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn diary_reads(&self) -> &[super::ExportDiaryRead] {
        &self.diary_reads
    }
    pub fn manifest(&self) -> &WholeVaultDocumentManifest {
        &self.manifest
    }
    pub fn manifest_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(&self.manifest)
            .map_err(|_| Error::InvariantViolation("whole-vault manifest serialization failed"))
    }
}

/// Seven sections. Entities occur once. Derived evidence is an index into
/// claim evidence, not a second authoritative body. Structural graph edges live
/// beside the evidence ledger and carry full value metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WholeVaultDocument {
    pub manifest: WholeVaultDocumentManifest,
    pub evidence_ledger: ExportLedger,
    pub claims: Vec<ExportEntity>,
    pub packs: Vec<ExportPack>,
    pub skills: Vec<ExportSkillBundle>,
    pub agent_packs: Vec<ExportAgentBundle>,
    pub derivation_envelopes: Vec<ExportDerivationEnvelope>,
    pub run_results: ExportRunResults,
}

/// The code runs' results (OF-190 B++): each run's result manifests, and
/// each body they name once. An off-record run's results never reach the
/// base vault, so no export holds them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRunResults {
    pub runs: Vec<ExportRun>,
    pub bodies: Vec<ExportResultBody>,
}

/// One run's results, as its replay record names them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRun {
    pub run_id: String,
    pub outputs: Vec<ExportRunOutput>,
    /// The run's fold receipts (ARCH-0079 #reader-forks), each beside the
    /// manifest of the occurrence it describes.
    pub receipts: Vec<ExportReaderFold>,
}

/// One fold receipt: the path of the folded occurrence in its run, and the
/// receipt. A withheld occurrence's receipt carries its marker and its
/// occurrence refs only, and `withheld` says why; it holds no content
/// either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportReaderFold {
    pub path: String,
    pub receipt: serde_json::Value,
    pub withheld: Option<String>,
}

/// One result occurrence's manifest. Its preview and line index are derived
/// from the body, so an import rebuilds them rather than reading them here.
/// The egress door judges each occurrence on its own (Docs Q08): a withheld
/// one says why and names no body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRunOutput {
    pub path: String,
    /// The body's BLAKE3, lowercase hex: its key in `bodies`. `None` when
    /// this occurrence is withheld.
    pub blake3: Option<String>,
    pub bytes: u64,
    pub kind: String,
    pub lines: u64,
    pub complete: bool,
    /// Why this occurrence is withheld: the secret scan marked it, or it
    /// carries taint refs.
    pub withheld: Option<String>,
}

/// One result body, which a clean occurrence names. Its text goes out
/// through the release door's scan; `content` is `None` when the body is
/// withheld, and `withheld` says why: the release scan found a credential
/// in it, or no row holds it any longer (`absent`). A body that is no UTF-8
/// text goes in the archive's `files/` with neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportResultBody {
    pub blake3: String,
    pub bytes: u64,
    pub content: Option<String>,
    pub withheld: Option<String>,
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
    /// Source-vault short ref for hydration. Absent when no live short ID exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_ref: Option<String>,
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

/// Source packages and compiled registrations are intentionally distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ExportPack {
    BuiltinAdapter(ExportAdapterDescriptor),
    Source(ExportPackSource),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportPackSource {
    /// The replicated source ASSET, never a grant or executable installation.
    pub entity_id: String,
    pub source_tree: super::ExportFileTree,
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
    /// Actual cited task receipts, or explicit source omissions. Archive data
    /// only: these cannot stamp terminal attempts in the receiving vault.
    pub receipts: Vec<super::ExportReceiptSource>,
}

#[derive(Debug, Clone)]
pub struct WholeVaultImportReceipt {
    pub authority: VaultImportReceipt,
    pub inserted_entities: usize,
    pub unchanged_entities: usize,
    /// New inert source ASSETs; these never count as native terminal receipts.
    pub archived_receipt_sources: usize,
    /// Archived rows intentionally not restored as local authority or verdicts.
    pub omitted_entities: usize,
    /// Domain-owned identities (currently MODEL name/version) rebound locally.
    pub remapped_entities: std::collections::BTreeMap<String, String>,
    /// Run results whose bodies came back, and those whose bodies the export
    /// withheld (their manifests stay in the archive only).
    pub imported_results: usize,
    pub withheld_results: usize,
    /// Custody records the owner's own archive carried, restored under their
    /// own ids, and those already here unchanged.
    pub restored_secrets: usize,
    pub unchanged_secrets: usize,
    /// Custody records the archive carried as handles only: secrets to
    /// re-enter through the owner's registration door.
    pub missing_secrets: Vec<crate::secret_custody::SecretCustodyMetadata>,
}

impl WholeVaultDocument {
    pub(crate) fn entities(&self) -> impl Iterator<Item = &ExportEntity> {
        self.evidence_ledger
            .entities
            .iter()
            .chain(self.claims.iter())
            .chain(self.skills.iter().map(|bundle| &bundle.entity))
    }
}
