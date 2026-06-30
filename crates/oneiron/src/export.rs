use crate::error::{Error, Result};
use crate::serialize::{WHOLE_VAULT_EXPORT_SERIALIZER, WHOLE_VAULT_EXPORT_SERIALIZER_VERSION};
use crate::store::{
    DB_MANIFEST, DB_MANIFEST_VERSION, DbManifestEntry, MAX_DBS, STORAGE_ABI_VERSION,
    STORAGE_SCHEMA_VERSION,
};

pub const EXPORT_MANIFEST_VERSION: u16 = 1;

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

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
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
        self.serializer.validate_import_supported()
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
mod tests {
    use super::*;

    #[test]
    fn export_manifest_stable_fixture_records_data_shape_and_secret_nulling() {
        let manifest = ExportManifest::from_redacted(true);

        let snapshot = String::from_utf8(manifest.to_json_pretty().expect("manifest serializes"))
            .expect("manifest JSON is UTF-8");

        assert_eq!(
            snapshot,
            "{\n  \"manifest_version\": 1,\n  \"serializer\": {\n    \"name\": \"oneiron.whole_vault_export\",\n    \"version\": 1\n  },\n  \"secrets_nulled\": {\n    \"payloads\": true,\n    \"structural_placeholders\": true\n  },\n  \"data_shape\": {\n    \"storage_abi_version\": 4,\n    \"storage_schema_version\": 1,\n    \"db_manifest_version\": 1,\n    \"max_dbs\": 32,\n    \"named_databases\": [\n      {\n        \"n\": 1,\n        \"name\": \"entities\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 2,\n        \"name\": \"type_index\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 3,\n        \"name\": \"short_ids\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 4,\n        \"name\": \"short_ids_reverse\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 5,\n        \"name\": \"vault_meta\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 6,\n        \"name\": \"vectors\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 7,\n        \"name\": \"hnsw_neighbors\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 8,\n        \"name\": \"hnsw_meta\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 9,\n        \"name\": \"text_postings\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 10,\n        \"name\": \"text_meta\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 11,\n        \"name\": \"text_forward\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 12,\n        \"name\": \"text_bm25_field_stats\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 13,\n        \"name\": \"text_doc_field_lengths\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 14,\n        \"name\": \"edges_out\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 15,\n        \"name\": \"edges_in\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 16,\n        \"name\": \"ppr_cache\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 17,\n        \"name\": \"ppr_cache_deps\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 18,\n        \"name\": \"temporal_occurred_start\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 19,\n        \"name\": \"temporal_occurred_end\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 20,\n        \"name\": \"temporal_learned\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 21,\n        \"name\": \"temporal_long_intervals\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 22,\n        \"name\": \"phonetic_index\",\n        \"group\": \"Phonetic\"\n      },\n      {\n        \"n\": 23,\n        \"name\": \"phonetic_forward\",\n        \"group\": \"Phonetic\"\n      },\n      {\n        \"n\": 24,\n        \"name\": \"sync_state\",\n        \"group\": \"Sync\"\n      },\n      {\n        \"n\": 25,\n        \"name\": \"sync_queue\",\n        \"group\": \"Sync\"\n      }\n    ]\n  }\n}"
        );
        assert!(manifest.redacted());
        assert!(manifest.structurally_secret_nulled());
        assert_eq!(manifest.manifest_version(), EXPORT_MANIFEST_VERSION);
        assert_eq!(manifest.serializer().name(), WHOLE_VAULT_EXPORT_SERIALIZER);
        assert_eq!(manifest.data_shape().named_databases().len(), 25);
    }

    #[test]
    fn export_manifest_clear_fixture_keeps_secrets_nulled_explicit_false() {
        let manifest = ExportManifest::clear();
        let value: serde_json::Value =
            serde_json::from_slice(&manifest.to_json_pretty().expect("manifest serializes"))
                .expect("manifest JSON parses");

        assert_eq!(value["secrets_nulled"]["payloads"], false);
        assert_eq!(value["secrets_nulled"]["structural_placeholders"], false);
        assert!(!manifest.redacted());
        assert!(!manifest.structurally_secret_nulled());
    }

    #[test]
    fn export_manifest_import_rejects_unsupported_manifest_version() {
        let manifest = ExportManifest::clear();
        let mut value: serde_json::Value =
            serde_json::from_slice(&manifest.to_json_pretty().expect("manifest serializes"))
                .expect("manifest JSON parses");
        value["manifest_version"] = serde_json::Value::from(EXPORT_MANIFEST_VERSION + 1);
        let unsupported =
            serde_json::to_vec_pretty(&value).expect("unsupported manifest serializes");

        let err = ExportManifest::from_json_for_import(&unsupported)
            .expect_err("unsupported manifest version must fail closed");

        match err {
            Error::InvalidConfig(message) => {
                assert_eq!(message, "unsupported export manifest version 2");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }
}
