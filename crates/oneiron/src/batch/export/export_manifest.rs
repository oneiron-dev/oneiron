//! Whole-vault export manifest artifact types and stanza impls.
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::serialize::{WHOLE_VAULT_EXPORT_SERIALIZER, WHOLE_VAULT_EXPORT_SERIALIZER_VERSION};
use crate::store::{
    DB_MANIFEST, DB_MANIFEST_VERSION, DbManifestEntry, MAX_DBS, STORAGE_ABI_VERSION,
    STORAGE_SCHEMA_VERSION,
};

use super::export_authority::ExportAuthorityManifest;

pub const EXPORT_MANIFEST_ARTIFACT_NAME: &str = "manifest.json";

pub const EXPORT_MANIFEST_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportManifestArtifact {
    relative_path: &'static str,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportManifest {
    manifest_version: u16,
    serializer: ExportSerializerManifest,
    pub(super) secrets_nulled: ExportSecretsNulledManifest,
    data_shape: ExportDataShapeManifest,
    /// Absent on artifacts written before the authority stanza existed, and on
    /// vaults that have no derived root to record. Both are import-visible as
    /// mismatches, never as a silent pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) authority: Option<ExportAuthorityManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) vault_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportSerializerManifest {
    name: String,
    version: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportSecretsNulledManifest {
    pub(super) payloads: bool,
    pub(super) structural_placeholders: bool,
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

impl ExportManifest {
    #[must_use]
    pub fn clear() -> Self {
        Self::from_redacted(false)
    }

    #[must_use]
    pub fn from_redacted(redacted: bool) -> Self {
        Self::from_secrets_nulled(ExportSecretsNulledManifest::from_redacted(redacted))
    }

    #[must_use]
    pub fn from_secrets_nulled(secrets_nulled: ExportSecretsNulledManifest) -> Self {
        Self {
            manifest_version: EXPORT_MANIFEST_VERSION,
            serializer: ExportSerializerManifest::current(),
            secrets_nulled,
            data_shape: ExportDataShapeManifest::current(),
            authority: None,
            vault_label: None,
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

    #[must_use]
    pub const fn authority(&self) -> Option<&ExportAuthorityManifest> {
        self.authority.as_ref()
    }

    #[must_use]
    pub fn vault_label(&self) -> Option<&str> {
        self.vault_label.as_deref()
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

    /// Declares STRUCTURAL placeholders without forcing payload nulling.
    ///
    /// [`Self::from_redacted`] couples the two flags because a redacted
    /// export means both. SECRET-04 (ONE-1922) needs exactly one of them:
    /// an export carrying secret-tainted build exhaust serializes that
    /// exhaust nulled with the structural placeholder, while the rest of
    /// the bundle's payloads are as clear as the caller asked for. Coupling
    /// them here would have quietly redacted a whole export because one
    /// artifact touched one secret.
    #[must_use]
    pub const fn with_structural_placeholders(self) -> Self {
        Self {
            payloads: self.payloads,
            structural_placeholders: true,
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

/// Pure manifest construction for internal fixtures/import tooling.
pub(crate) fn whole_vault_export_manifest_artifact(
    secrets_nulled: ExportSecretsNulledManifest,
) -> Result<ExportManifestArtifact> {
    ExportManifestArtifact::from_manifest(&ExportManifest::from_secrets_nulled(secrets_nulled))
}
