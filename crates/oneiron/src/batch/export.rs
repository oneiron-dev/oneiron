use std::fs;
use std::path::{Path, PathBuf};

use crate::Vault;
use crate::claim::ClaimLifecycleStatus;
use crate::companion::{
    CompanionExportClassification, CompanionExpression, CompanionExpressionRegister,
    CompanionRecord, CompanionRecordKey, CompanionRecordKind, CompanionRegister, CompanionScope,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::serialize::{WHOLE_VAULT_EXPORT_SERIALIZER, WHOLE_VAULT_EXPORT_SERIALIZER_VERSION};
use crate::store::{
    DB_MANIFEST, DB_MANIFEST_VERSION, DbManifestEntry, MAX_DBS, STORAGE_ABI_VERSION,
    STORAGE_SCHEMA_VERSION,
};

pub const EXPORT_MANIFEST_ARTIFACT_NAME: &str = "manifest.json";
pub const EXPORT_MANIFEST_VERSION: u16 = 1;
pub const COMPANION_EXPORT_LAYER_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionExportLayer {
    layer_version: u16,
    personas: Vec<CompanionExportRecord>,
    relationships: Vec<CompanionExportRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionExportRecord {
    key: CompanionRecordKey,
    record: CompanionRecord,
    expression: Option<CompanionExpression>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportManifestArtifact {
    relative_path: &'static str,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportManifest {
    manifest_version: u16,
    serializer: ExportSerializerManifest,
    secrets_nulled: ExportSecretsNulledManifest,
    data_shape: ExportDataShapeManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportSerializerManifest {
    name: String,
    version: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportSecretsNulledManifest {
    payloads: bool,
    structural_placeholders: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportDataShapeManifest {
    storage_abi_version: u16,
    storage_schema_version: u16,
    db_manifest_version: u16,
    max_dbs: u32,
    named_databases: Vec<ExportDbManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportDbManifestEntry {
    n: u8,
    name: String,
    group: String,
}

pub fn companion_export_layer(
    records: &CompanionRegister,
    expressions: &CompanionExpressionRegister,
) -> CompanionExportLayer {
    let mut personas = Vec::new();
    let mut relationships = Vec::new();

    for (key, record) in records.iter() {
        if !companion_record_exportable(record) {
            continue;
        }

        let exported = CompanionExportRecord {
            key: key.clone(),
            record: record.clone(),
            expression: expressions.lookup(key),
        };

        match record.kind() {
            CompanionRecordKind::Persona => personas.push(exported),
            CompanionRecordKind::Relationship => relationships.push(exported),
        }
    }

    CompanionExportLayer {
        layer_version: COMPANION_EXPORT_LAYER_VERSION,
        personas,
        relationships,
    }
}

fn companion_record_exportable(record: &CompanionRecord) -> bool {
    record.lifecycle == ClaimLifecycleStatus::Active
        && record.export_classification == CompanionExportClassification::Portable
        && !matches!(&record.scope, CompanionScope::SharedVault { .. })
}

impl CompanionExportLayer {
    #[must_use]
    pub const fn layer_version(&self) -> u16 {
        self.layer_version
    }

    #[must_use]
    pub fn personas(&self) -> &[CompanionExportRecord] {
        &self.personas
    }

    #[must_use]
    pub fn relationships(&self) -> &[CompanionExportRecord] {
        &self.relationships
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.personas.len() + self.relationships.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.personas.is_empty() && self.relationships.is_empty()
    }
}

impl CompanionExportRecord {
    #[must_use]
    pub const fn key(&self) -> &CompanionRecordKey {
        &self.key
    }

    #[must_use]
    pub const fn record(&self) -> &CompanionRecord {
        &self.record
    }

    #[must_use]
    pub const fn expression(&self) -> Option<CompanionExpression> {
        self.expression
    }
}

impl ExportManifestArtifact {
    pub fn current(redacted: bool) -> Result<Self> {
        Self::from_manifest(&ExportManifest::from_redacted(redacted))
    }

    pub fn from_manifest(manifest: &ExportManifest) -> Result<Self> {
        Ok(Self {
            relative_path: EXPORT_MANIFEST_ARTIFACT_NAME,
            bytes: manifest.to_json_pretty()?,
        })
    }

    #[must_use]
    pub const fn relative_path(&self) -> &str {
        self.relative_path
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn write_to_dir(&self, export_dir: impl AsRef<Path>) -> Result<PathBuf> {
        let path = export_dir.as_ref().join(self.relative_path);
        fs::write(&path, &self.bytes)?;
        Ok(path)
    }
}

/// THE WHOLE-VAULT EXPORT EGRESS DOOR (ARCH-0052 P6, owner ruling
/// R-20260807-06).
///
/// One of the two surviving off-record egress doors, and the ONLY off-record
/// question the export path asks. `true` means the row belongs to a live
/// session overlay and is SKIPPED; export itself always runs.
///
/// Export used to REFUSE outright while any session was open, because base
/// carried fenced session rows an artifact could ship. It no longer does:
/// session content lives only in the overlay, so the artifact cannot contain it
/// and a refusal would only punish the user for having a room open. What CAN
/// appear in an enumeration is an id — an overlay member reachable through a
/// composed view — so the door skips ids, never refuses.
///
/// A base write commissioned during a live session (an on-record write after a
/// mode flip, or a P5 promote) is NOT an overlay member, so it exports
/// normally. That asymmetry is the whole point of the predicate: it asks about
/// membership in a room, not about whether a room exists.
///
/// The whole-vault ROW enumerator is OF-222 / ONE-1240 and does not exist yet.
/// When it lands, its sole entity-row loop calls THIS function and nothing
/// else — no second predicate, no fences-present fast path, no scrub.
pub fn whole_vault_export_excludes_entity(vault: &Vault, id: &EntityId) -> Result<bool> {
    vault.store.off_record_sessions.contains_entity(id)
}

/// Pure manifest construction for internal fixtures/import tooling.
pub(crate) fn whole_vault_export_manifest_artifact(
    secrets_nulled: ExportSecretsNulledManifest,
) -> Result<ExportManifestArtifact> {
    ExportManifestArtifact::from_manifest(&ExportManifest::from_secrets_nulled(secrets_nulled))
}

/// Builds a whole-vault export manifest for a vault handle.
///
/// Runs unconditionally: the manifest describes the vault's SHAPE (serializer,
/// ABI, DB manifest), which no session can taint, and per-row exclusion is
/// [`whole_vault_export_excludes_entity`]'s job at the enumeration door.
pub fn whole_vault_export_manifest_artifact_for_vault(
    _vault: &Vault,
    secrets_nulled: ExportSecretsNulledManifest,
) -> Result<ExportManifestArtifact> {
    whole_vault_export_manifest_artifact(secrets_nulled)
}

/// Writes a whole-vault export manifest for a vault handle.
pub fn write_whole_vault_export_manifest_for_vault(
    vault: &Vault,
    export_dir: impl AsRef<Path>,
    secrets_nulled: ExportSecretsNulledManifest,
) -> Result<PathBuf> {
    whole_vault_export_manifest_artifact_for_vault(vault, secrets_nulled)?.write_to_dir(export_dir)
}

impl Vault {
    /// Builds the manifest for a whole-vault export. Succeeds while an
    /// off-record session is live.
    pub fn whole_vault_export_manifest_artifact(
        &self,
        secrets_nulled: ExportSecretsNulledManifest,
    ) -> Result<ExportManifestArtifact> {
        whole_vault_export_manifest_artifact_for_vault(self, secrets_nulled)
    }

    /// Writes the manifest for a whole-vault export. Succeeds while an
    /// off-record session is live.
    pub fn write_whole_vault_export_manifest(
        &self,
        export_dir: impl AsRef<Path>,
        secrets_nulled: ExportSecretsNulledManifest,
    ) -> Result<PathBuf> {
        write_whole_vault_export_manifest_for_vault(self, export_dir, secrets_nulled)
    }
}

impl ExportManifest {
    #[must_use]
    pub fn clear() -> Self {
        Self::from_redacted(false)
    }

    #[must_use]
    pub fn from_redacted(redacted: bool) -> Self {
        Self {
            manifest_version: EXPORT_MANIFEST_VERSION,
            serializer: ExportSerializerManifest::current(),
            secrets_nulled: ExportSecretsNulledManifest::from_redacted(redacted),
            data_shape: ExportDataShapeManifest::current(),
        }
    }

    #[must_use]
    pub fn from_secrets_nulled(secrets_nulled: ExportSecretsNulledManifest) -> Self {
        Self {
            manifest_version: EXPORT_MANIFEST_VERSION,
            serializer: ExportSerializerManifest::current(),
            secrets_nulled,
            data_shape: ExportDataShapeManifest::current(),
        }
    }

    #[must_use]
    pub const fn redacted(&self) -> bool {
        self.secrets_nulled.payloads
    }

    #[must_use]
    pub const fn structurally_secret_nulled(&self) -> bool {
        self.secrets_nulled.structural_placeholders
    }

    #[must_use]
    pub const fn manifest_version(&self) -> u16 {
        self.manifest_version
    }

    #[must_use]
    pub const fn serializer(&self) -> &ExportSerializerManifest {
        &self.serializer
    }

    #[must_use]
    pub const fn data_shape(&self) -> &ExportDataShapeManifest {
        &self.data_shape
    }

    pub fn to_json_pretty(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self)
            .map_err(|_| Error::InvariantViolation("export manifest JSON encode failed"))
    }

    pub fn from_json_for_import(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|_| Error::InvalidConfig("invalid export manifest JSON".to_owned()))?;
        manifest.validate_import_supported()?;
        Ok(manifest)
    }

    pub fn validate_import_supported(&self) -> Result<()> {
        if self.manifest_version != EXPORT_MANIFEST_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported export manifest version {}",
                self.manifest_version
            )));
        }
        self.serializer.validate_import_supported()?;
        self.data_shape.validate_import_supported()
    }
}

impl ExportSerializerManifest {
    #[must_use]
    pub fn current() -> Self {
        Self {
            name: WHOLE_VAULT_EXPORT_SERIALIZER.to_owned(),
            version: WHOLE_VAULT_EXPORT_SERIALIZER_VERSION,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    fn validate_import_supported(&self) -> Result<()> {
        if self.name != WHOLE_VAULT_EXPORT_SERIALIZER
            || self.version != WHOLE_VAULT_EXPORT_SERIALIZER_VERSION
        {
            return Err(Error::InvalidConfig(format!(
                "unsupported export serializer {}@{}",
                self.name, self.version
            )));
        }
        Ok(())
    }
}

impl ExportSecretsNulledManifest {
    #[must_use]
    pub const fn from_redacted(redacted: bool) -> Self {
        Self {
            payloads: redacted,
            structural_placeholders: redacted,
        }
    }

    #[must_use]
    pub const fn payloads(&self) -> bool {
        self.payloads
    }

    #[must_use]
    pub const fn structural_placeholders(&self) -> bool {
        self.structural_placeholders
    }
}

impl ExportDataShapeManifest {
    #[must_use]
    pub fn current() -> Self {
        Self {
            storage_abi_version: STORAGE_ABI_VERSION,
            storage_schema_version: STORAGE_SCHEMA_VERSION,
            db_manifest_version: DB_MANIFEST_VERSION,
            max_dbs: MAX_DBS,
            named_databases: DB_MANIFEST
                .iter()
                .copied()
                .map(ExportDbManifestEntry::from)
                .collect(),
        }
    }

    #[must_use]
    pub const fn storage_abi_version(&self) -> u16 {
        self.storage_abi_version
    }

    #[must_use]
    pub const fn storage_schema_version(&self) -> u16 {
        self.storage_schema_version
    }

    #[must_use]
    pub const fn db_manifest_version(&self) -> u16 {
        self.db_manifest_version
    }

    #[must_use]
    pub const fn max_dbs(&self) -> u32 {
        self.max_dbs
    }

    #[must_use]
    pub fn named_databases(&self) -> &[ExportDbManifestEntry] {
        &self.named_databases
    }

    fn validate_import_supported(&self) -> Result<()> {
        if self.storage_abi_version != STORAGE_ABI_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported export storage ABI version {}",
                self.storage_abi_version
            )));
        }
        if self.storage_schema_version != STORAGE_SCHEMA_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported export storage schema version {}",
                self.storage_schema_version
            )));
        }
        if self.db_manifest_version != DB_MANIFEST_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported export DB manifest version {}",
                self.db_manifest_version
            )));
        }
        if self.max_dbs != MAX_DBS {
            return Err(Error::InvalidConfig(format!(
                "unsupported export max DB count {}",
                self.max_dbs
            )));
        }
        if self.named_databases.len() != DB_MANIFEST.len()
            || !self
                .named_databases
                .iter()
                .zip(DB_MANIFEST.iter().copied())
                .all(|(actual, expected)| actual.matches_store_entry(expected))
        {
            return Err(Error::InvalidConfig(
                "unsupported export DB manifest shape".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ExportDbManifestEntry {
    #[must_use]
    pub const fn n(&self) -> u8 {
        self.n
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn group(&self) -> &str {
        &self.group
    }

    fn matches_store_entry(&self, entry: DbManifestEntry) -> bool {
        self.n == entry.n && self.name == entry.name && self.group == entry.group
    }
}

impl From<DbManifestEntry> for ExportDbManifestEntry {
    fn from(value: DbManifestEntry) -> Self {
        Self {
            n: value.n,
            name: value.name.to_owned(),
            group: value.group.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests;
