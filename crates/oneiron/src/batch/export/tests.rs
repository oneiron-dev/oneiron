use super::*;
use crate::authority::{
    AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, DeviceAuthority, ROLE_OWNER, authority_transcript,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::CompanionProvenance;
use crate::edge::EdgeActorClass;
use crate::off_record::OffRecordBackendClass;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;
use crate::{Vault, VaultConfig};
use ed25519_dalek::{Signer, SigningKey};
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
        "{\n  \"manifest_version\": 1,\n  \"serializer\": {\n    \"name\": \"oneiron.whole_vault_export\",\n    \"version\": 1\n  },\n  \"secrets_nulled\": {\n    \"payloads\": true,\n    \"structural_placeholders\": true\n  },\n  \"data_shape\": {\n    \"storage_abi_version\": 17,\n    \"storage_schema_version\": 1,\n    \"db_manifest_version\": 2,\n    \"max_dbs\": 32,\n    \"named_databases\": [\n      {\n        \"n\": 1,\n        \"name\": \"entities\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 2,\n        \"name\": \"type_index\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 3,\n        \"name\": \"short_ids\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 4,\n        \"name\": \"short_ids_reverse\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 5,\n        \"name\": \"vault_meta\",\n        \"group\": \"Core\"\n      },\n      {\n        \"n\": 6,\n        \"name\": \"vectors\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 7,\n        \"name\": \"hnsw_neighbors\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 8,\n        \"name\": \"hnsw_meta\",\n        \"group\": \"Vector\"\n      },\n      {\n        \"n\": 9,\n        \"name\": \"text_postings\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 10,\n        \"name\": \"text_meta\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 11,\n        \"name\": \"text_forward\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 12,\n        \"name\": \"text_bm25_field_stats\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 13,\n        \"name\": \"text_doc_field_lengths\",\n        \"group\": \"Text\"\n      },\n      {\n        \"n\": 14,\n        \"name\": \"edges_out\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 15,\n        \"name\": \"edges_in\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 16,\n        \"name\": \"ppr_cache\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 17,\n        \"name\": \"ppr_cache_deps\",\n        \"group\": \"Graph\"\n      },\n      {\n        \"n\": 18,\n        \"name\": \"temporal_occurred_start\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 19,\n        \"name\": \"temporal_occurred_end\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 20,\n        \"name\": \"temporal_learned\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 21,\n        \"name\": \"temporal_long_intervals\",\n        \"group\": \"Temporal\"\n      },\n      {\n        \"n\": 22,\n        \"name\": \"phonetic_index\",\n        \"group\": \"Phonetic\"\n      },\n      {\n        \"n\": 23,\n        \"name\": \"phonetic_forward\",\n        \"group\": \"Phonetic\"\n      },\n      {\n        \"n\": 24,\n        \"name\": \"sync_state\",\n        \"group\": \"Sync\"\n      },\n      {\n        \"n\": 25,\n        \"name\": \"sync_queue\",\n        \"group\": \"Sync\"\n      },\n      {\n        \"n\": 26,\n        \"name\": \"job_records\",\n        \"group\": \"Jobs\"\n      },\n      {\n        \"n\": 27,\n        \"name\": \"job_ready\",\n        \"group\": \"Jobs\"\n      },\n      {\n        \"n\": 28,\n        \"name\": \"job_dedupe\",\n        \"group\": \"Jobs\"\n      }\n    ]\n  }\n}",
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

#[test]
fn export_manifest_import_rejects_unsupported_manifest_version() {
    let manifest = ExportManifest::clear();
    let mut value: serde_json::Value =
        serde_json::from_slice(&manifest.to_json_pretty().expect("manifest serializes"))
            .expect("manifest JSON parses");
    value["manifest_version"] = serde_json::Value::from(EXPORT_MANIFEST_VERSION + 1);
    let unsupported = serde_json::to_vec_pretty(&value).expect("unsupported manifest serializes");

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
    let unsupported = serde_json::to_vec_pretty(&value).expect("unsupported manifest serializes");

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
    let unsupported = serde_json::to_vec_pretty(&value).expect("unsupported manifest serializes");

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
    value["data_shape"]["named_databases"][0]["name"] = serde_json::Value::from("future_entities");
    let unsupported = serde_json::to_vec_pretty(&value).expect("unsupported manifest serializes");

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

/// Opens a vault whose authority log carries a single genesis, so
/// `authority_fold()` derives a vault id. `seed` picks the chain: two different
/// seeds are two different vaults.
fn open_rooted_vault(seed: u8) -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.put_authority_log_entry(&genesis_entry(seed), TimeRange { start: 1, end: 1 }, 1)?;
    Ok((dir, vault))
}

fn genesis_entry(seed: u8) -> AuthorityLogEntry {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: 1,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [0; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER,
            },
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = authority_transcript(&entry).expect("genesis transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

fn manifest_value(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("manifest JSON parses")
}

fn manifest_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec_pretty(value).expect("manifest JSON serializes")
}

/// An owner's own artifact, offered back to the vault that wrote it, is the ONE
/// shape that may restore bytes: same chain, same chain state, nothing nulled.
#[test]
fn own_export_round_trips_byte_faithful() -> Result<()> {
    let (_dir, vault) = open_rooted_vault(0x21)?;
    let secrets_nulled = ExportSecretsNulledManifest::from_redacted(false);
    let artifact = vault.whole_vault_export_manifest_artifact_with_label(
        secrets_nulled,
        Some("laptop, before the reinstall"),
    )?;

    // The vault-handle export now states its own chain identity; the pure
    // fixture builder, which has no vault to ask, still does not.
    let manifest = ExportManifest::from_json_for_import(artifact.bytes())?;
    let authority = manifest
        .authority()
        .expect("rooted export states authority");
    let fold = vault.authority_fold()?;
    let vault_id = fold.vault_id.expect("genesis roots the vault");
    assert_eq!(authority.vault_id(), hex_lower(&vault_id));
    assert_eq!(
        authority.valid_entries_digest(),
        hex_lower(&authority_valid_entries_digest(
            &vault_id,
            &fold.valid_entries
        ))
    );
    assert_eq!(manifest.vault_label(), Some("laptop, before the reinstall"));
    assert!(
        whole_vault_export_manifest_artifact(secrets_nulled)?
            .bytes()
            .ne(artifact.bytes())
    );

    // Re-encoding what was parsed reproduces the artifact byte for byte, which
    // is what lets the receipt digest commit to the parse instead of the file.
    assert_eq!(manifest.to_json_pretty()?, artifact.bytes());

    let receipt = vault
        .classify_vault_import_manifest(artifact.bytes(), Some("laptop, before the reinstall"))?;
    assert_eq!(
        receipt.classification,
        VaultImportClassification::ByteFaithfulOwnerRestore
    );
    assert!(receipt.byte_faithful);
    assert!(receipt.mismatches.is_empty());
    assert_eq!(receipt.exported_vault_id, Some(vault_id));
    assert_eq!(receipt.local_vault_id, Some(vault_id));
    assert_eq!(
        receipt.exported_label.as_deref(),
        Some("laptop, before the reinstall")
    );
    assert_eq!(
        receipt.expected_label.as_deref(),
        Some("laptop, before the reinstall")
    );
    assert_eq!(
        receipt.manifest_digest,
        canonical_manifest_digest(&manifest)?
    );

    // No expected label is not a label mismatch: the caller simply did not ask.
    let unasked = vault.classify_vault_import_manifest(artifact.bytes(), None)?;
    assert_eq!(
        unasked.classification,
        VaultImportClassification::ByteFaithfulOwnerRestore
    );
    assert_eq!(unasked.expected_label, None);
    assert_eq!(unasked.manifest_digest, receipt.manifest_digest);
    Ok(())
}

/// A well-formed artifact from someone else's chain is FOREIGN, not a restore —
/// and no amount of matching label makes it one.
#[test]
fn foreign_chain_not_treated_as_restore() -> Result<()> {
    let (_local_dir, local) = open_rooted_vault(0x31)?;
    let (_foreign_dir, foreign) = open_rooted_vault(0x32)?;
    let secrets_nulled = ExportSecretsNulledManifest::from_redacted(false);
    let artifact =
        foreign.whole_vault_export_manifest_artifact_with_label(secrets_nulled, Some("shared"))?;

    let receipt = local.classify_vault_import_manifest(artifact.bytes(), Some("shared"))?;

    assert_eq!(
        receipt.classification,
        VaultImportClassification::ForeignAuthorityChain
    );
    assert!(!receipt.byte_faithful);
    assert_eq!(
        receipt.mismatches,
        vec![VaultImportMismatch::AuthorityVaultId]
    );
    assert_eq!(
        receipt.exported_vault_id,
        foreign.authority_fold()?.vault_id,
        "the receipt must name the chain it refused"
    );
    assert_eq!(receipt.local_vault_id, local.authority_fold()?.vault_id);
    assert_ne!(receipt.exported_vault_id, receipt.local_vault_id);

    // Same manifest, offered to the vault that wrote it: a restore. Foreignness
    // is a relation between artifact and vault, not a property of either.
    let home = foreign.classify_vault_import_manifest(artifact.bytes(), Some("shared"))?;
    assert_eq!(
        home.classification,
        VaultImportClassification::ByteFaithfulOwnerRestore
    );
    Ok(())
}

/// Everything that is neither a restore nor a foreign chain lands in
/// ReviewRequired with its reasons spelled out.
#[test]
fn mismatch_surfaces_receipt() -> Result<()> {
    let (_dir, vault) = open_rooted_vault(0x41)?;
    let clear = ExportSecretsNulledManifest::from_redacted(false);
    let vault_id = vault.authority_fold()?.vault_id.expect("rooted vault");

    // A legacy artifact, written before the authority stanza existed.
    let legacy = whole_vault_export_manifest_artifact(clear)?;
    let receipt = vault.classify_vault_import_manifest(legacy.bytes(), None)?;
    assert_eq!(
        receipt.classification,
        VaultImportClassification::ReviewRequired
    );
    assert!(!receipt.byte_faithful);
    assert_eq!(
        receipt.mismatches,
        vec![VaultImportMismatch::MissingAuthorityManifest]
    );
    assert_eq!(receipt.exported_vault_id, None);
    assert_eq!(receipt.local_vault_id, Some(vault_id));

    // Same root, different chain state: the artifact commits to a valid-entry
    // set this vault does not have.
    let artifact = vault.whole_vault_export_manifest_artifact(clear)?;
    let mut drifted = manifest_value(artifact.bytes());
    drifted["authority"]["valid_entries_digest"] = serde_json::Value::from(hex_lower(
        &authority_valid_entries_digest(&vault_id, &BTreeSet::new()),
    ));
    let receipt = vault.classify_vault_import_manifest(&manifest_bytes(&drifted), None)?;
    assert_eq!(
        receipt.classification,
        VaultImportClassification::ReviewRequired
    );
    assert_eq!(
        receipt.mismatches,
        vec![VaultImportMismatch::AuthorityChainDigest]
    );
    assert_eq!(receipt.exported_vault_id, Some(vault_id));

    // Same owner, same chain, but the artifact shipped nulled content: it can
    // no longer restore the bytes it came from, so authority matching is not
    // enough.
    let redacted = vault
        .whole_vault_export_manifest_artifact(ExportSecretsNulledManifest::from_redacted(true))?;
    let receipt = vault.classify_vault_import_manifest(redacted.bytes(), None)?;
    assert_eq!(
        receipt.classification,
        VaultImportClassification::ReviewRequired
    );
    assert!(!receipt.byte_faithful);
    assert_eq!(
        receipt.mismatches,
        vec![VaultImportMismatch::RedactedOrSecretNulled]
    );
    assert_eq!(receipt.exported_vault_id, Some(vault_id));

    // A label the caller did not expect. The chain still matches, so the label
    // demotes the verdict without ever being able to promote one.
    let labelled =
        vault.whole_vault_export_manifest_artifact_with_label(clear, Some("desk machine"))?;
    let receipt = vault.classify_vault_import_manifest(labelled.bytes(), Some("laptop"))?;
    assert_eq!(
        receipt.classification,
        VaultImportClassification::ReviewRequired
    );
    assert_eq!(receipt.mismatches, vec![VaultImportMismatch::VaultLabel]);
    assert_eq!(receipt.exported_label.as_deref(), Some("desk machine"));
    assert_eq!(receipt.expected_label.as_deref(), Some("laptop"));

    // An expected label against an unlabelled artifact is the same mismatch.
    let receipt = vault.classify_vault_import_manifest(artifact.bytes(), Some("laptop"))?;
    assert_eq!(receipt.mismatches, vec![VaultImportMismatch::VaultLabel]);
    assert_eq!(receipt.exported_label, None);

    // Reasons accumulate in declaration order, deduped, one receipt.
    let mut both = manifest_value(redacted.bytes());
    both["authority"]["valid_entries_digest"] = serde_json::Value::from(hex_lower(
        &authority_valid_entries_digest(&vault_id, &BTreeSet::new()),
    ));
    let receipt = vault.classify_vault_import_manifest(&manifest_bytes(&both), Some("laptop"))?;
    assert_eq!(
        receipt.mismatches,
        vec![
            VaultImportMismatch::AuthorityChainDigest,
            VaultImportMismatch::VaultLabel,
            VaultImportMismatch::RedactedOrSecretNulled,
        ]
    );

    // An unrooted vault cannot establish its own side of the comparison.
    let unrooted_dir = tempfile::tempdir()?;
    let unrooted = Vault::open(unrooted_dir.path(), VaultConfig::device())?;
    let receipt = unrooted.classify_vault_import_manifest(artifact.bytes(), None)?;
    assert_eq!(
        receipt.classification,
        VaultImportClassification::ReviewRequired
    );
    assert_eq!(
        receipt.mismatches,
        vec![VaultImportMismatch::LocalAuthorityMissing]
    );
    assert_eq!(receipt.local_vault_id, None);
    assert_eq!(receipt.exported_vault_id, Some(vault_id));

    // Malformed chain identity fails closed rather than classifying.
    for spelling in [
        hex_lower(&vault_id).to_uppercase(),
        hex_lower(&vault_id)[..62].to_owned(),
    ] {
        let mut malformed = manifest_value(artifact.bytes());
        malformed["authority"]["vault_id"] = serde_json::Value::from(spelling);
        let err = vault
            .classify_vault_import_manifest(&manifest_bytes(&malformed), None)
            .expect_err("malformed chain identity must fail closed");
        match err {
            Error::InvalidConfig(message) => {
                assert_eq!(message, "malformed export authority vault id");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    // A label that is not displayable never reaches a verdict either.
    validate_export_vault_label("laptop").expect("an ordinary label is fine");
    validate_export_vault_label("").expect_err("empty label");
    validate_export_vault_label("desk\tmachine").expect_err("control character");
    validate_export_vault_label(&"a".repeat(MAX_EXPORT_VAULT_LABEL_BYTES + 1))
        .expect_err("over the byte bound");
    validate_export_vault_label(&"a".repeat(MAX_EXPORT_VAULT_LABEL_BYTES))
        .expect("exactly at the byte bound");
    Ok(())
}

type AuthoritySyncRows = (Option<Vec<u8>>, Option<Vec<u8>>);

/// SOL-ONE-1379-1: asking "what is this artifact, relative to me?" must not
/// change the subject it asks about. The classifier's local identity lookup
/// used to run the WRITE-side fold, which backfills first-seen sidecars,
/// stamps the one-shot migration marker, and advances the observation clock —
/// a manifest-only question mutating `sync_state`, against the blueprint's
/// "performs no writes" contract. The tripwire is the exact pre-backfill
/// branch: marker absent, classify, marker STILL absent and the clock row
/// still untouched.
#[test]
fn classify_performs_no_writes() -> Result<()> {
    let (_dir, vault) = open_rooted_vault(0x61)?;
    let authority_sync_rows = |vault: &Vault| -> Result<AuthoritySyncRows> {
        let rtxn = vault.store.env.read_txn()?;
        let marker = vault
            .store
            .sync_state
            .get(
                &rtxn,
                crate::authority::authority_first_seen_backfill_sync_key(),
            )?
            .map(|raw| raw.to_vec());
        let clock = vault
            .store
            .sync_state
            .get(
                &rtxn,
                crate::authority::authority_first_seen_clock_sync_key(),
            )?
            .map(|raw| raw.to_vec());
        Ok((marker, clock))
    };
    // Fixture sanity: opening and rooting a vault never FOLDS, so the one-shot
    // backfill marker is absent — the exact pre-backfill branch the finding
    // reproduces. (The clock row MAY exist already: the entity write path
    // maintains it on every authority put. What may never move during
    // classification is BOTH rows.) Under the old code the classification
    // below was precisely what stamped the marker.
    let before = authority_sync_rows(&vault)?;
    assert_eq!(before.0, None, "no fold ran yet, so no backfill marker");

    let legacy =
        whole_vault_export_manifest_artifact(ExportSecretsNulledManifest::from_redacted(false))?;
    let receipt = vault.classify_vault_import_manifest(legacy.bytes(), None)?;
    // The question was still answered — the receipt is unchanged in shape….
    assert_eq!(
        receipt.classification,
        VaultImportClassification::ReviewRequired
    );
    assert_eq!(
        receipt.mismatches,
        vec![VaultImportMismatch::MissingAuthorityManifest]
    );
    // …and it was answered through the READONLY fold: a genesis-only chain is
    // determinate, so local identity resolves even with the marker absent.
    assert!(receipt.local_vault_id.is_some());

    assert_eq!(
        authority_sync_rows(&vault)?,
        before,
        "classification must leave the first-seen marker and clock untouched"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn foreign_import_staged_and_receipted() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let classification = VaultImportReceipt {
        manifest_digest: [1; 32],
        classification: VaultImportClassification::ByteFaithfulOwnerRestore,
        mismatches: vec![],
        exported_vault_id: None,
        local_vault_id: None,
        exported_label: None,
        expected_label: None,
        byte_faithful: true,
    };
    let result = stage_foreign_vault_import(
        &vault,
        &classification,
        ForeignVaultImportSource::ForeignPlatform {
            platform: "x".into(),
        },
        &crate::sync::types::WindowKey::new("2026-01"),
        &[],
    );
    assert!(result.is_err());
    assert_eq!(VAULT_IMPORT_RECEIPT_SCHEMA_VERSION, 1);
    assert_eq!(VAULT_IMPORT_RECEIPT_KEY_PREFIX, "vault_import_receipt:v1:");
}
#[cfg(feature = "sync")]
#[test]
fn pending_import_is_invisible_until_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let c = VaultImportReceipt {
        manifest_digest: [2; 32],
        classification: VaultImportClassification::ForeignAuthorityChain,
        mismatches: vec![],
        exported_vault_id: None,
        local_vault_id: None,
        exported_label: None,
        expected_label: None,
        byte_faithful: false,
    };
    let staged = stage_foreign_vault_import(
        &vault,
        &c,
        ForeignVaultImportSource::ForeignPlatform {
            platform: "remote".into(),
        },
        &crate::sync::types::WindowKey::new("2026-01"),
        &[1, 2, 3],
    );
    let staged = staged.expect("failed admission returns receipt");
    let durable = vault_import_stage_receipt(&vault, &staged.receipt.receipt_id)
        .unwrap()
        .unwrap();
    assert_eq!(durable.status, VaultImportStageStatus::Failed);
    assert_eq!(durable.failure, Some(VaultImportFailure::AdmissionRejected));
}
#[cfg(feature = "sync")]
#[test]
fn failed_admission_is_receipted() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let c = VaultImportReceipt {
        manifest_digest: [3; 32],
        classification: VaultImportClassification::ForeignAuthorityChain,
        mismatches: vec![],
        exported_vault_id: None,
        local_vault_id: None,
        exported_label: None,
        expected_label: None,
        byte_faithful: false,
    };
    let staged = stage_foreign_vault_import(
        &vault,
        &c,
        ForeignVaultImportSource::ForeignPlatform {
            platform: "remote".into(),
        },
        &crate::sync::types::WindowKey::new("2026-01"),
        &[0xff],
    );
    let staged = staged.expect("failed staging returns its durable receipt");
    let durable = vault_import_stage_receipt(&vault, &staged.receipt.receipt_id)
        .unwrap()
        .unwrap();
    assert_eq!(durable.status, VaultImportStageStatus::Failed);
    assert_eq!(durable.failure, Some(VaultImportFailure::AdmissionRejected));
}
#[cfg(feature = "sync")]
#[test]
fn strict_receipt_codec_schema_is_versioned() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let c = VaultImportReceipt {
        manifest_digest: [3; 32],
        classification: VaultImportClassification::ForeignAuthorityChain,
        mismatches: vec![],
        exported_vault_id: None,
        local_vault_id: None,
        exported_label: None,
        expected_label: None,
        byte_faithful: false,
    };
    let staged = stage_foreign_vault_import(
        &vault,
        &c,
        ForeignVaultImportSource::ForeignPlatform {
            platform: "codec".into(),
        },
        &crate::sync::types::WindowKey::new("2026-01"),
        &[1, 2, 3],
    )
    .unwrap();
    let read = vault_import_stage_receipt(&vault, &staged.receipt.receipt_id)
        .unwrap()
        .unwrap();
    assert_eq!(read.receipt_id, staged.receipt.receipt_id);
    assert_eq!(read.status, VaultImportStageStatus::Failed);
}
