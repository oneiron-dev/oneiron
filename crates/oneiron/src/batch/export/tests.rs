use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::CompanionProvenance;
use crate::edge::EdgeActorClass;
use crate::off_record::OffRecordBackendClass;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;
use crate::{Vault, VaultConfig};
use rmpv::Value;

use crate::test_util::entity;

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
        provenance(0x55),
        CompanionExportClassification::Portable,
    );
    let relationship = CompanionRecord::relationship(
        personal,
        relationship_source,
        relationship_target,
        Value::from("portable relationship"),
        provenance(0x56),
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
        "{\n  \"manifest_version\": 1,\n  \"serializer\": {\n    \"name\": \"oneiron.whole_vault_export\",\n    \"version\": 1\n  },\n  \"secrets_nulled\": {\n    \"payloads\": true,\n    \"structural_placeholders\": true\n  },\n  \"data_shape\": {\n    \"storage_abi_version\": 15,\n    \"storage_schema_version\": 1,\n    \"db_manifest_version\": 2,\n    \"max_dbs\": 32,\n    \"named_databases\": [\n      {\n        \"n\": 1,\n        \"name\": \"entities\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 2,\n        \"name\": \"type_index\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 3,\n        \"name\": \"short_ids\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 4,\n        \"name\": \"short_ids_reverse\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 5,\n        \"name\": \"vault_meta\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 6,\n        \"name\": \"vectors\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 7,\n        \"name\": \"hnsw_neighbors\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 8,\n        \"name\": \"hnsw_meta\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 9,\n        \"name\": \"text_postings\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 10,\n        \"name\": \"text_meta\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 11,\n        \"name\": \"text_forward\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 12,\n        \"name\": \"text_bm25_field_stats\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 13,\n        \"name\": \"text_doc_field_lengths\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 14,\n        \"name\": \"edges_out\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 15,\n        \"name\": \"edges_in\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 16,\n        \"name\": \"ppr_cache\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 17,\n        \"name\": \"ppr_cache_deps\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 18,\n        \"name\": \"temporal_occurred_start\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 19,\n        \"name\": \"temporal_occurred_end\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 20,\n        \"name\": \"temporal_learned\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 21,\n        \"name\": \"temporal_long_intervals\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 22,\n        \"name\": \"phonetic_index\",\n        \"group\": \"Phonetic\"\n      },\n      {\n        \"n\": 23,\n        \"name\": \"phonetic_forward\",\n        \"group\": \"Phonetic\"\n      },\n      {\n        \"n\": 24,\n        \"name\": \"sync_state\",\n        \"group\": \"Sync\"\n      },\n      {\n        \"n\": 25,\n        \"name\": \"sync_queue\",\n        \"group\": \"Sync\"\n      },\n      {\n        \"n\": 26,\n        \"name\": \"job_records\",\n        \"group\": \"Jobs\"\n      },\n      {\n        \"n\": 27,\n        \"name\": \"job_ready\",\n        \"group\": \"Jobs\"\n      },\n      {\n        \"n\": 28,\n        \"name\": \"job_dedupe\",\n        \"group\": \"Jobs\"\n      }\n    ]\n  }\n}",
    );
    assert!(manifest.redacted());
    assert!(manifest.structurally_secret_nulled());
    assert_eq!(manifest.manifest_version(), EXPORT_MANIFEST_VERSION);
    assert_eq!(manifest.serializer().name(), WHOLE_VAULT_EXPORT_SERIALIZER);
    assert_eq!(manifest.data_shape().named_databases().len(), 28);
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
    let path = whole_vault_export_manifest_artifact(secrets_nulled)
        .expect("manifest artifact builds")
        .write_to_dir(dir.path())
        .expect("manifest artifact writes");
    let written = std::fs::read(path).expect("manifest artifact is readable");
    assert_eq!(written, artifact.bytes());
}

/// THE EXPORT EGRESS DOOR (ARCH-0052 P6, ONE-1731 / R-20260807-06).
///
/// Every whole-vault export entry SUCCEEDS while a session is live — the
/// pre-P6 refusal existed because base carried fenced session rows an artifact
/// could ship, and base carries none now. What the door does instead is skip
/// overlay MEMBERS, one predicate, no refusal: a room's own id is excluded, an
/// ordinary base write commissioned during the same live session is not.
#[test]
fn whole_vault_export_runs_during_a_live_session_and_skips_only_overlay_members() -> Result<()> {
    let vault_dir = tempfile::tempdir()?;
    let vault = Vault::open(vault_dir.path(), VaultConfig::default())?;
    let export_dir = tempfile::tempdir()?;
    let artifact_path = export_dir.path().join(EXPORT_MANIFEST_ARTIFACT_NAME);
    let secrets_nulled = ExportSecretsNulledManifest::from_redacted(false);
    let session = vault
        .off_record_session_vault()
        .enter("sess-export-door", OffRecordBackendClass::Local)?;

    // A commissioned ordinary base write made DURING the live session.
    let commissioned = EntityId::now();
    vault.put_entity(
        &commissioned,
        crate::registry::ENTITY_TYPE_TURN,
        crate::temporal::TimeRange {
            start: 1000,
            end: 1000,
        },
        1000,
        b"commissioned during a live session",
    )?;

    // A room member, staged straight into the overlay (the K4 taint guard
    // forbids a base write at this id, which is the point).
    let room_member = EntityId::now();
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        room_member.as_bytes(),
        b"live session overlay entity",
    )?;
    segment.commit()?;

    // Every entry point runs — no refusal, artifact written.
    whole_vault_export_manifest_artifact_for_vault(&vault, secrets_nulled)?;
    vault.whole_vault_export_manifest_artifact(secrets_nulled)?;
    write_whole_vault_export_manifest_for_vault(&vault, export_dir.path(), secrets_nulled)?;
    std::fs::remove_file(&artifact_path)?;
    vault.write_whole_vault_export_manifest(export_dir.path(), secrets_nulled)?;
    assert!(
        artifact_path.is_file(),
        "a live session must not stop the export from writing manifest.json"
    );

    // The door: the room member is excluded, the commissioned write is not.
    assert!(whole_vault_export_excludes_entity(&vault, &room_member)?);
    assert!(!whole_vault_export_excludes_entity(&vault, &commissioned)?);

    // Close drops membership; the id stops being excluded because the room it
    // belonged to is gone, not because anything was deleted.
    session.close()?;
    assert!(!whole_vault_export_excludes_entity(&vault, &room_member)?);
    assert!(vault.get_raw(&commissioned)?.is_some());
    Ok(())
}
