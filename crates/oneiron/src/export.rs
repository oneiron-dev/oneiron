use std::fs;
use std::path::{Path, PathBuf};

use crate::claim::ClaimLifecycleStatus;
use crate::error::{Error, Result};
use crate::serialize::{WHOLE_VAULT_EXPORT_SERIALIZER, WHOLE_VAULT_EXPORT_SERIALIZER_VERSION};
use crate::store::{
    DB_MANIFEST, DB_MANIFEST_VERSION, DbManifestEntry, MAX_DBS, STORAGE_ABI_VERSION,
    STORAGE_SCHEMA_VERSION,
};
use crate::types::{
    CompanionExportClassification, CompanionExpression, CompanionExpressionRegister,
    CompanionRecord, CompanionRecordKey, CompanionRecordKind, CompanionRegister, CompanionScope,
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

pub fn whole_vault_export_manifest_artifact(
    secrets_nulled: ExportSecretsNulledManifest,
) -> Result<ExportManifestArtifact> {
    ExportManifestArtifact::from_manifest(&ExportManifest::from_secrets_nulled(secrets_nulled))
}

pub fn write_whole_vault_export_manifest(
    export_dir: impl AsRef<Path>,
    secrets_nulled: ExportSecretsNulledManifest,
) -> Result<PathBuf> {
    whole_vault_export_manifest_artifact(secrets_nulled)?.write_to_dir(export_dir)
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
mod tests {
    use super::*;
    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::types::{
        CompanionProvenance, EdgeActorClass, EntityId, WriteActor, WriteEnvelope, WriteProvenance,
    };
    use rmpv::Value;

    fn entity(seed: u8) -> EntityId {
        let mut bytes = [seed; 16];
        bytes[0] = seed.max(1);
        EntityId::from_bytes(bytes).expect("test entity id")
    }

    fn provenance(seed: u8) -> CompanionProvenance {
        let envelope = WriteEnvelope::new(
            WriteActor::new(entity(seed), EdgeActorClass::Agent),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from(format!("fixture-{seed}"))).unwrap(),
            ClaimApprovalStatus::Approved,
        );
        CompanionProvenance::from_envelope(&envelope)
    }

    #[test]
    fn companion_export_includes_portable_persona_and_relationship_layer() -> Result<()> {
        let neutral = CompanionScope::neutral();
        let personal = CompanionScope::personal(entity(0x51));
        let persona_ref = entity(0x52);
        let relationship_source = entity(0x53);
        let relationship_target = entity(0x54);

        let persona = CompanionRecord::persona(
            neutral,
            persona_ref,
            Value::from("portable persona"),
            provenance(0xA1),
            CompanionExportClassification::Portable,
        );
        let relationship = CompanionRecord::relationship(
            personal,
            relationship_source,
            relationship_target,
            Value::from("portable relationship"),
            provenance(0xA2),
            CompanionExportClassification::Portable,
        );

        let mut records = CompanionRegister::new();
        records.register(persona.clone())?;
        records.register(relationship.clone())?;

        let mut expressions = CompanionExpressionRegister::new();
        expressions.update(persona.key(), CompanionExpression::Professional)?;
        expressions.update(relationship.key(), CompanionExpression::Warm)?;

        let layer = companion_export_layer(&records, &expressions);

        assert_eq!(layer.layer_version(), COMPANION_EXPORT_LAYER_VERSION);
        assert_eq!(layer.len(), 2);
        assert_eq!(layer.personas().len(), 1);
        assert_eq!(layer.relationships().len(), 1);
        assert_eq!(layer.personas()[0].record(), &persona);
        assert_eq!(
            layer.personas()[0].expression(),
            Some(CompanionExpression::Professional)
        );
        assert_eq!(layer.relationships()[0].record(), &relationship);
        assert_eq!(
            layer.relationships()[0].expression(),
            Some(CompanionExpression::Warm)
        );
        Ok(())
    }

    #[test]
    fn companion_export_excludes_private_shared_and_closed_records() -> Result<()> {
        let neutral = CompanionScope::neutral();
        let personal = CompanionScope::personal(entity(0x61));
        let shared = CompanionScope::shared_vault(7);

        let included = CompanionRecord::persona(
            neutral,
            entity(0x62),
            Value::from("portable neutral persona"),
            provenance(0xB1),
            CompanionExportClassification::Portable,
        );
        let private = CompanionRecord::persona(
            personal.clone(),
            entity(0x63),
            Value::from("private personal persona"),
            provenance(0xB2),
            CompanionExportClassification::LocalOnly,
        );
        let shared_classified = CompanionRecord::relationship(
            shared.clone(),
            entity(0x64),
            entity(0x65),
            Value::from("shared org relationship"),
            provenance(0xB3),
            CompanionExportClassification::SharedVault,
        );
        let shared_misclassified = CompanionRecord::persona(
            shared,
            entity(0x66),
            Value::from("shared scope with portable flag"),
            provenance(0xB4),
            CompanionExportClassification::Portable,
        );
        let mut closed = CompanionRecord::relationship(
            personal,
            entity(0x67),
            entity(0x68),
            Value::from("closed relationship"),
            provenance(0xB5),
            CompanionExportClassification::Portable,
        );
        closed.lifecycle = ClaimLifecycleStatus::Retracted;

        let mut records = CompanionRegister::new();
        for record in [
            included.clone(),
            private.clone(),
            shared_classified.clone(),
            shared_misclassified.clone(),
            closed.clone(),
        ] {
            records.register(record)?;
        }

        let mut expressions = CompanionExpressionRegister::new();
        expressions.update(included.key(), CompanionExpression::Warm)?;
        expressions.update(private.key(), CompanionExpression::Unrestricted)?;
        expressions.update(shared_classified.key(), CompanionExpression::Unrestricted)?;
        expressions.update(
            shared_misclassified.key(),
            CompanionExpression::Unrestricted,
        )?;
        expressions.update(closed.key(), CompanionExpression::Professional)?;

        let layer = companion_export_layer(&records, &expressions);

        assert_eq!(layer.len(), 1);
        assert_eq!(layer.personas().len(), 1);
        assert!(layer.relationships().is_empty());
        assert_eq!(layer.personas()[0].record(), &included);
        assert_eq!(
            layer.personas()[0].expression(),
            Some(CompanionExpression::Warm)
        );
        assert_ne!(layer.personas()[0].record(), &private);
        assert_ne!(layer.personas()[0].record(), &shared_misclassified);
        Ok(())
    }

    #[test]
    fn export_manifest_stable_fixture_records_data_shape_and_secret_nulling() {
        let manifest = ExportManifest::from_redacted(true);

        let snapshot = String::from_utf8(manifest.to_json_pretty().expect("manifest serializes"))
            .expect("manifest JSON is UTF-8");

        assert_eq!(
            snapshot,
            "{\n  \"manifest_version\": 1,\n  \"serializer\": {\n    \"name\": \"oneiron.whole_vault_export\",\n    \"version\": 1\n  },\n  \"secrets_nulled\": {\n    \"payloads\": true,\n    \"structural_placeholders\": true\n  },\n  \"data_shape\": {\n    \"storage_abi_version\": 6,\n    \"storage_schema_version\": 1,\n    \"db_manifest_version\": 1,\n    \"max_dbs\": 32,\n    \"named_databases\": [\n      {\n        \"n\": 1,\n        \"name\": \"entities\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 2,\n        \"name\": \"type_index\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 3,\n        \"name\": \"short_ids\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 4,\n        \"name\": \"short_ids_reverse\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 5,\n        \"name\": \"vault_meta\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 6,\n        \"name\": \"vectors\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 7,\n        \"name\": \"hnsw_neighbors\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 8,\n        \"name\": \"hnsw_meta\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 9,\n        \"name\": \"text_postings\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 10,\n        \"name\": \"text_meta\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 11,\n        \"name\": \"text_forward\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 12,\n        \"name\": \"text_bm25_field_stats\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 13,\n        \"name\": \"text_doc_field_lengths\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 14,\n        \"name\": \"edges_out\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 15,\n        \"name\": \"edges_in\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 16,\n        \"name\": \"ppr_cache\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 17,\n        \"name\": \"ppr_cache_deps\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 18,\n        \"name\": \"temporal_occurred_start\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 19,\n        \"name\": \"temporal_occurred_end\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 20,\n        \"name\": \"temporal_learned\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 21,\n        \"name\": \"temporal_long_intervals\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 22,\n        \"name\": \"phonetic_index\",\n        \"group\": \"Phonetic\"\n      },\n      {\n        \"n\": 23,\n        \"name\": \"phonetic_forward\",\n        \"group\": \"Phonetic\"\n      },\n      {\n        \"n\": 24,\n        \"name\": \"sync_state\",\n        \"group\": \"Sync\"\n      },\n      {\n        \"n\": 25,\n        \"name\": \"sync_queue\",\n        \"group\": \"Sync\"\n      }\n    ]\n  }\n}"
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
    fn whole_vault_export_manifest_artifact_writes_stable_manifest_json() {
        let secrets_nulled = ExportSecretsNulledManifest::from_redacted(true);
        let artifact =
            whole_vault_export_manifest_artifact(secrets_nulled).expect("manifest artifact builds");
        let repeated = whole_vault_export_manifest_artifact(secrets_nulled)
            .expect("repeated manifest artifact builds");

        assert_eq!(artifact.relative_path(), EXPORT_MANIFEST_ARTIFACT_NAME);
        assert_eq!(artifact.bytes(), repeated.bytes());
        assert_eq!(
            artifact.bytes(),
            ExportManifest::from_secrets_nulled(secrets_nulled)
                .to_json_pretty()
                .expect("manifest serializes")
                .as_slice()
        );

        let dir = tempfile::tempdir().expect("temp dir");
        let path = write_whole_vault_export_manifest(dir.path(), secrets_nulled)
            .expect("manifest artifact writes");
        let written = std::fs::read(path).expect("manifest artifact is readable");
        assert_eq!(written, artifact.bytes());
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

    #[test]
    fn export_manifest_import_rejects_unsupported_storage_abi() {
        let mut value = manifest_json_value();
        let unsupported_abi = STORAGE_ABI_VERSION + 1;
        value["data_shape"]["storage_abi_version"] = serde_json::Value::from(unsupported_abi);
        let unsupported =
            serde_json::to_vec_pretty(&value).expect("unsupported manifest serializes");

        let err = ExportManifest::from_json_for_import(&unsupported)
            .expect_err("unsupported storage ABI must fail closed");

        match err {
            Error::InvalidConfig(message) => {
                assert_eq!(
                    message,
                    format!("unsupported export storage ABI version {unsupported_abi}")
                );
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn export_manifest_import_rejects_unsupported_storage_schema() {
        let mut value = manifest_json_value();
        value["data_shape"]["storage_schema_version"] =
            serde_json::Value::from(u64::from(STORAGE_SCHEMA_VERSION) + 1);
        let unsupported =
            serde_json::to_vec_pretty(&value).expect("unsupported manifest serializes");

        let err = ExportManifest::from_json_for_import(&unsupported)
            .expect_err("unsupported storage schema must fail closed");

        match err {
            Error::InvalidConfig(message) => {
                assert_eq!(message, "unsupported export storage schema version 2");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn export_manifest_import_rejects_unsupported_db_manifest_shape() {
        let mut value = manifest_json_value();
        value["data_shape"]["named_databases"][0]["name"] =
            serde_json::Value::from("future_entities");
        let unsupported =
            serde_json::to_vec_pretty(&value).expect("unsupported manifest serializes");

        let err = ExportManifest::from_json_for_import(&unsupported)
            .expect_err("unsupported DB manifest shape must fail closed");

        match err {
            Error::InvalidConfig(message) => {
                assert_eq!(message, "unsupported export DB manifest shape");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    fn manifest_json_value() -> serde_json::Value {
        serde_json::from_slice(
            &ExportManifest::clear()
                .to_json_pretty()
                .expect("manifest serializes"),
        )
        .expect("manifest JSON parses")
    }
}
