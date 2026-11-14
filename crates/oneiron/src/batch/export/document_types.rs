//! The typed whole-vault document: what the archive's JSONL rows assemble
//! into on import, and what the snapshot builds before the archive is cut.
use serde::{Deserialize, Serialize};

use super::{
    ArchiveFile, ArchiveRecordFile, EmbeddingSetupImport, EmbeddingSetupWithheld,
    ExportAgentBundle, ExportBundleOmission, ExportDiaryHold, ExportImportOmission,
    ExportImportRefusal, ExportManifest, ExportSerializerManifest, ExportSkillBundle,
    ExportSourceBoundary, PortableEmbeddingSpace, PortableSlotBindings, VAULT_ARCHIVE_FORMAT,
    VaultImportReceipt,
};
use crate::error::{Error, Result};
use crate::serialize::{ExportBody, ExportValue};

#[doc(hidden)]
pub use oneiron_records::batch::export::document_types::{
    ExportAdapterDescriptor, ExportDeterminism, ExportEdge, ExportEpochFloor, ExportPack,
    ExportPackSource, ExportReaderFold, ExportResultBody, ExportRun, ExportRunBinding,
    ExportRunOutput, ExportRunResults, ExportSourceVault, WHOLE_VAULT_DOCUMENT_VERSION,
};

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
    /// FIX 12066: the custody secrets the exporting install's fold proves an
    /// install holds but that have no row there, so this archive carries no
    /// handle of theirs: each comes as its export secret supplement. Ids,
    /// lowercase hex.
    pub fold_only_secrets: Vec<String>,
    /// OF-370: embedding setup the nulling pass withheld from this archive.
    pub embedding_setup_withheld: EmbeddingSetupWithheld,
    /// FIX 2768: side rows this archive holds out, and why.
    pub side_rows_withheld: Vec<super::ArchiveSideWithheld>,
}

impl WholeVaultDocumentManifest {
    /// Validate the versioned manifest of a whole-vault archive. A keeping
    /// archive (`secrets_nulled` false) is valid only with secrets included
    /// in the archive format and with both storage nulling claims false;
    /// every other archive keeps the historical nulling claims.
    pub fn validate(&self) -> Result<()> {
        if self.source_boundaries != [ExportSourceBoundary::BuiltinAdapterCodeNotStored]
            || self.manifest_version != WHOLE_VAULT_DOCUMENT_VERSION
            || self.format != VAULT_ARCHIVE_FORMAT
            || self.serializer != ExportSerializerManifest::current()
            || self.storage.redacted() != self.secrets_nulled
            || self.storage.structurally_secret_nulled() != self.secrets_nulled
            || (!self.secrets_nulled && !self.secrets_included)
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

/// An export written to a caller's file (FIX 2766): the manifest it carries
/// and the diaries it read. The archive is the caller's file; no byte of it
/// is held here. Fields are private: only the serializer produces one.
#[derive(Debug, Clone)]
pub struct WholeVaultExportReceipt {
    pub(crate) manifest: WholeVaultDocumentManifest,
    /// OF-490: the diaries this export read, for the vault's own log.
    pub(crate) diary_reads: Vec<super::ExportDiaryRead>,
    /// The rows the archive is derived from, as its snapshot read them
    /// (DEC-0005), for a host that judges it again before it leaves.
    pub(crate) sources: Vec<crate::entity_id::EntityId>,
    /// The root of each thread a TURN the archive carries is of, with its
    /// binding as the snapshot read it, for the export's audit and notices
    /// (FIX 6427, 6681). Never serialized.
    pub(crate) thread_roots: crate::workspace_roster::ExportThreadRoots,
    /// FIX 4624(b): each custody value the archive carries as its handle
    /// because it did not open here, and where its holder's sealed copy
    /// stands once the export's audit recorded it.
    pub(crate) holder_requests: Vec<crate::authority::HolderExportRequest>,
    /// Owner ruling 1-EXPORT = B: each world the owner's own export carries
    /// that his recipient choice would keep from where it goes, and why.
    /// None on this device.
    pub(crate) notices: Vec<crate::share_travel::WorldRecipientNotice>,
}

impl WholeVaultExportReceipt {
    pub fn diary_reads(&self) -> &[super::ExportDiaryRead] {
        &self.diary_reads
    }
    /// FIX 4624(b): each custody value carried as its handle that its holder
    /// is asked for, and where that stands.
    pub fn holder_requests(&self) -> &[crate::authority::HolderExportRequest] {
        &self.holder_requests
    }
    pub fn manifest(&self) -> &WholeVaultDocumentManifest {
        &self.manifest
    }
    /// Owner ruling 1-EXPORT = B: each world this export carries that the
    /// owner's recipient choice would keep from where it goes, and why.
    pub fn notices(&self) -> &[crate::share_travel::WorldRecipientNotice] {
        &self.notices
    }
}

/// An archive payload in memory and its standalone validating manifest, for a
/// door that answers in one frame; it is built through a spool file (FIX
/// 2766). Fields are private: only the serializer can produce the
/// credential-nulling proof on this result.
#[derive(Debug, Clone)]
pub struct WholeVaultExport {
    pub(crate) bytes: Vec<u8>,
    pub(crate) manifest: WholeVaultDocumentManifest,
    /// OF-490: the diaries this export read, for the vault's own log.
    pub(crate) diary_reads: Vec<super::ExportDiaryRead>,
    /// As [`WholeVaultExportReceipt::notices`].
    pub(crate) notices: Vec<crate::share_travel::WorldRecipientNotice>,
}

impl WholeVaultExport {
    /// The archive: a ZIP of `manifest.json`, `records/*.jsonl` and `files/*`.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn diary_reads(&self) -> &[super::ExportDiaryRead] {
        &self.diary_reads
    }
    /// As [`WholeVaultExportReceipt::notices`].
    pub fn notices(&self) -> &[crate::share_travel::WorldRecipientNotice] {
        &self.notices
    }
    pub fn manifest(&self) -> &WholeVaultDocumentManifest {
        &self.manifest
    }
    pub fn manifest_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(&self.manifest)
            .map_err(|_| Error::InvariantViolation("whole-vault manifest serialization failed"))
    }
}

/// Twelve sections. Entities occur once. Derived evidence is an index into
/// claim evidence, not a second authoritative body. Structural graph edges live
/// beside the evidence ledger and carry full value metadata. The embedding
/// setup is descriptors only (OF-370): no vector travels. Epoch floors carry a
/// count position only (OF-013): no removed summary's words travel.
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
    /// Every declared embedding space, in id order.
    pub embedding_spaces: Vec<PortableEmbeddingSpace>,
    /// The three kind slots; `None` when the export carries no setup (a
    /// records archive, OKF).
    pub slot_bindings: Option<PortableSlotBindings>,
    /// Every lineage's epoch floor, in key order; empty outside a
    /// whole-vault export.
    pub epoch_floors: Vec<ExportEpochFloor>,
    /// FIX 2768: the allowlisted side-table rows that index the records here
    /// (blob versions, LFS objects, codebase snapshots, code revisions and
    /// code-document history); empty outside a whole-vault export.
    pub side_tables: Vec<super::ArchiveSideRow>,
    /// FIX 1178: the birth envelope of each carried row that has one,
    /// masked to the rows this document carries; empty in an archive an
    /// older engine wrote.
    #[serde(default)]
    pub row_births: Vec<ExportRowBirth>,
}

/// One carried row's birth envelope (FIX 1178): the row it belongs to and
/// its birth as the source vault stamped it, masked to the rows the archive
/// carries ([`crate::provenance::birth::RowBirth::masked`]). An import
/// stamps it beside the landed row; it grants nothing on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRowBirth {
    /// The born row's id, hex.
    pub id: String,
    pub birth: crate::provenance::birth::RowBirth,
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
    /// Durable `gate:<32 hex>` owner-act receipt naming this archive's full document-manifest
    /// digest. Present only for the owner-authenticated restore entry, not a reusable grant.
    pub owner_restore_receipt_ref: Option<String>,
    pub inserted_entities: usize,
    pub unchanged_entities: usize,
    /// Engine seed rows an owner restore into a fresh vault replaced with the archive's owner-edited row.
    pub replaced_seed_entities: usize,
    /// New inert source ASSETs; these never count as native terminal receipts.
    pub archived_receipt_sources: usize,
    /// Archived rows intentionally not restored as local authority or verdicts.
    pub omitted_entities: usize,
    /// The archived rows among `omitted_entities` that this vault's state kept
    /// out, beyond the manifest's `import_omissions`: an archived
    /// `vault.default_facet` outside the owner's restore into a fresh vault
    /// (`TargetDefaultFacetKept`).
    pub destination_omissions: Vec<ExportImportOmission>,
    /// Domain-owned identities (currently MODEL name/version) rebound locally.
    pub remapped_entities: std::collections::BTreeMap<String, String>,
    /// Run results whose bodies came back, and those whose bodies the export
    /// withheld (their manifests stay in the archive only).
    pub imported_results: usize,
    pub withheld_results: usize,
    /// Archived result names rebound to restored outputs, left unresolved, or
    /// kept withheld by their occurrence's egress judgment.
    pub bindings_bound: usize,
    pub bindings_unresolved: usize,
    pub bindings_withheld: usize,
    /// Replay records written from restored outputs, or left untouched because
    /// the existing record already carried the same archived facts.
    pub records_rebuilt: usize,
    pub records_skipped: usize,
    /// Custody records the owner's own archive carried, restored under their
    /// own ids, and those already here unchanged.
    pub restored_secrets: usize,
    pub unchanged_secrets: usize,
    /// Portable custody records the archive carried whose id an admitted
    /// revoke here names: they stay dead and are not restored (FIX 4852).
    pub skipped_revoked_secrets: usize,
    /// Archived `regenerates` links whose restored MESSAGE pair does not
    /// prove what the stream proved: left out, not restored (FIX 6206).
    pub skipped_unproven_regenerates_edges: usize,
    /// Custody records the archive carried as handles only: secrets to
    /// re-enter through the owner's registration door.
    pub missing_secrets: Vec<crate::secret_record::SecretCustodyMetadata>,
    /// FIX 12066: the fold-only custody secrets the archive's manifest names
    /// that have no record here after the import: each is owed through its
    /// export secret supplement.
    pub owed_secrets: Vec<crate::EntityId>,
    /// What the archive's embedding setup did here (OF-370).
    pub embedding_setup: EmbeddingSetupImport,
    /// FIX 2768: side rows written, and those already here unchanged.
    pub restored_side_rows: usize,
    pub unchanged_side_rows: usize,
}

impl WholeVaultDocument {
    /// Every entity row of the document, section by section. The import
    /// reads its rows from the row index instead (FIX 3678).
    #[cfg(test)]
    pub(crate) fn entities(&self) -> impl Iterator<Item = &ExportEntity> {
        self.evidence_ledger
            .entities
            .iter()
            .chain(self.claims.iter())
            .chain(self.skills.iter().map(|bundle| &bundle.entity))
    }
}
