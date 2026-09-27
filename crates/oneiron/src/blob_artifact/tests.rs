use super::*;
use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, short_id_prefix,
};
use crate::test_util::embedding_test_config;

fn test_body() -> BlobArtifactBody {
    BlobArtifactBody::new(
        "forecast.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
}

fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn put_actor(vault: &Vault, learned_at: u64) -> Result<WriteActor> {
    let actor_id = EntityId::now();
    vault.put_entity(
        &actor_id,
        ENTITY_TYPE_PERSON,
        test_time(learned_at),
        learned_at,
        b"uploader",
    )?;
    Ok(WriteActor::new(actor_id, EdgeActorClass::Human))
}

fn put_artifact(vault: &Vault, learned_at: u64) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_blob_artifact(&id, &test_body(), test_time(learned_at), learned_at)?;
    Ok(id)
}

fn encode_map(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        ),
    )
    .expect("encode msgpack");
    out
}

#[test]
fn blob_artifact_codec_round_trips_pinned_keys() -> Result<()> {
    let body = test_body();
    let encoded = encode_blob_artifact_body(&body)?;
    let decoded = decode_blob_artifact_body(&encoded)?;
    assert_eq!(decoded, body);

    // Inline content slots are rejected by the pinned-key law.
    let with_content = encode_map(vec![
        ("name", Value::from("forecast.xlsx")),
        ("media_type", Value::from("application/x-test")),
        ("content", Value::Binary(vec![1, 2, 3])),
    ]);
    let err = decode_blob_artifact_body(&with_content)
        .expect_err("BLOB artifact body must reject inline content slots");
    assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);

    for missing_key in BLOB_ARTIFACT_BODY_KEYS {
        let entries = BLOB_ARTIFACT_BODY_KEYS
            .into_iter()
            .filter(|key| *key != missing_key)
            .map(|key| (key, Value::from("value")))
            .collect();
        let err = decode_blob_artifact_body(&encode_map(entries))
            .expect_err("missing pinned key must fail closed");
        assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);
    }
    Ok(())
}

#[test]
fn blob_artifact_registry_and_vault_helpers_round_trip() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let id = put_artifact(&vault, 11)?;

    let decoded = vault.get_blob_artifact(&id)?.ok_or(Error::EntityNotFound)?;
    let expected = test_body();
    assert_eq!(decoded.name, expected.name);
    assert_eq!(decoded.media_type, expected.media_type);
    assert!(decoded.secret_taint_refs.is_empty());
    assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_BLOB_ARTIFACT));
    assert_eq!(short_id_prefix(ENTITY_TYPE_BLOB_ARTIFACT)?, "ba");
    Ok(())
}

#[test]
fn blob_artifact_upload_creates_v1_with_ledger_event() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let artifact_id = put_artifact(&vault, 10)?;
    let actor = put_actor(&vault, 10)?;

    let version = vault.append_blob_artifact_version(
        &artifact_id,
        b"office bytes v1",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;

    assert_eq!(version.version, 1);
    assert_eq!(
        version.content_hash,
        *blake3::hash(b"office bytes v1").as_bytes()
    );
    assert_eq!(version.provenance, BlobVersionProvenance::UserUpload);
    assert_eq!(version.calc_engine, None, "an upload was not recalculated");
    // The LEDGER event landed as a CLAIM entity.
    assert_eq!(
        vault.get_entity_type(&version.claim_id)?,
        Some(ENTITY_TYPE_CLAIM)
    );
    assert_eq!(
        vault.read_blob_artifact_version(&artifact_id, 1)?,
        Some(b"office bytes v1".to_vec())
    );
    assert_eq!(vault.blob_artifact_head(&artifact_id)?, Some(version));
    Ok(())
}

#[test]
fn blob_artifact_identical_bytes_dedupe() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let artifact_id = put_artifact(&vault, 10)?;
    let actor = put_actor(&vault, 10)?;

    let first = vault.append_blob_artifact_version(
        &artifact_id,
        b"same bytes",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;
    let second = vault.append_blob_artifact_version(
        &artifact_id,
        b"same bytes",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(12),
        12,
    )?;

    // Same content hash, same version, no new chain entry or claim.
    assert_eq!(second, first);
    assert_eq!(vault.blob_artifact_versions(&artifact_id)?.len(), 1);

    // Identical bytes uploaded into ANOTHER artifact keep their own
    // chain but share the content-addressed asset entity.
    let other_id = put_artifact(&vault, 13)?;
    let other = vault.append_blob_artifact_version(
        &other_id,
        b"same bytes",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(14),
        14,
    )?;
    assert_eq!(other.version, 1);
    assert_eq!(other.content_hash, first.content_hash);
    assert_eq!(
        blob_artifact_asset_entity_id(&other.content_hash)?,
        blob_artifact_asset_entity_id(&first.content_hash)?
    );
    Ok(())
}

#[test]
fn blob_artifact_version_chain_is_append_only() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let artifact_id = put_artifact(&vault, 10)?;
    let actor = put_actor(&vault, 10)?;

    let v1 = vault.append_blob_artifact_version(
        &artifact_id,
        b"bytes v1",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;
    let v2 = vault.append_blob_artifact_version(
        &artifact_id,
        b"bytes v2",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(12),
        12,
    )?;
    // Returning to v1's bytes appends a NEW version — history is never
    // rewritten, mirroring the OF-320 non-destructive revert law.
    let v3 = vault.append_blob_artifact_version(
        &artifact_id,
        b"bytes v1",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(13),
        13,
    )?;

    assert_eq!((v1.version, v2.version, v3.version), (1, 2, 3));
    assert_eq!(v3.content_hash, v1.content_hash);
    let versions = vault.blob_artifact_versions(&artifact_id)?;
    assert_eq!(versions, vec![v1, v2, v3.clone()]);
    // Every version's bytes stay readable after later appends.
    assert_eq!(
        vault.read_blob_artifact_version(&artifact_id, 1)?,
        Some(b"bytes v1".to_vec())
    );
    assert_eq!(
        vault.read_blob_artifact_version(&artifact_id, 2)?,
        Some(b"bytes v2".to_vec())
    );
    assert_eq!(vault.blob_artifact_head(&artifact_id)?, Some(v3));
    assert_eq!(vault.read_blob_artifact_version(&artifact_id, 4)?, None);
    Ok(())
}

#[test]
fn blob_artifact_provenance_round_trips_per_version() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let artifact_id = put_artifact(&vault, 10)?;
    let actor = put_actor(&vault, 10)?;

    let v1 = vault.append_blob_artifact_version(
        &artifact_id,
        b"uploaded by user",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;
    let agent_run = BlobVersionProvenance::AgentRun {
        run_ref: "run:2026-07-07T00:00:00Z#42".to_owned(),
    };
    let v2 = vault.append_blob_artifact_version(
        &artifact_id,
        b"edited by agent",
        &agent_run,
        actor,
        test_time(12),
        12,
    )?;

    let versions = vault.blob_artifact_versions(&artifact_id)?;
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].calc_engine, None);
    assert_eq!(versions[0].provenance, BlobVersionProvenance::UserUpload);
    assert_eq!(versions[1].provenance, agent_run);
    assert_ne!(v1.claim_id, v2.claim_id);
    for version in &versions {
        assert_eq!(
            vault.get_entity_type(&version.claim_id)?,
            Some(ENTITY_TYPE_CLAIM)
        );
    }
    Ok(())
}

#[test]
fn blob_artifact_delete_cleans_chain_and_orphaned_assets() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10)?;
    let artifact_a = put_artifact(&vault, 10)?;
    let artifact_b = put_artifact(&vault, 10)?;

    vault.append_blob_artifact_version(
        &artifact_a,
        b"shared bytes",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;
    let a_only = vault.append_blob_artifact_version(
        &artifact_a,
        b"a-only bytes",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(12),
        12,
    )?;
    let shared = vault.append_blob_artifact_version(
        &artifact_b,
        b"shared bytes",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(13),
        13,
    )?;
    let a_only_asset = blob_artifact_asset_entity_id(&a_only.content_hash)?;
    let shared_asset = blob_artifact_asset_entity_id(&shared.content_hash)?;

    // Batch-path delete (BatchOp::Delete routes through deindex_entity).
    vault.batch().delete(&artifact_a).commit()?;
    assert!(vault.blob_artifact_versions(&artifact_a)?.is_empty());
    assert_eq!(vault.blob_artifact_head(&artifact_a)?, None);
    // Bytes only artifact A referenced die with their last reference…
    assert!(vault.get_raw(&a_only_asset)?.is_none());
    // …while the shared asset survives because artifact B still holds a
    // reference, and B's chain stays fully readable.
    assert!(vault.get_raw(&shared_asset)?.is_some());
    assert_eq!(
        vault.read_blob_artifact_version(&artifact_b, 1)?,
        Some(b"shared bytes".to_vec())
    );

    // Deleting the LAST referencing artifact removes the shared bytes.
    vault.delete_entity(&artifact_b)?;
    assert!(vault.blob_artifact_versions(&artifact_b)?.is_empty());
    assert!(vault.get_raw(&shared_asset)?.is_none());
    Ok(())
}

#[test]
fn blob_artifact_append_fails_closed_on_bad_input() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10)?;

    // Unknown artifact.
    let err = vault
        .append_blob_artifact_version(
            &EntityId::now(),
            b"bytes",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(11),
            11,
        )
        .expect_err("append to unknown artifact must fail");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);

    // Wrong entity type.
    let session_id = EntityId::now();
    vault.put_entity(
        &session_id,
        ENTITY_TYPE_SESSION,
        test_time(11),
        11,
        b"session",
    )?;
    let err = vault
        .append_blob_artifact_version(
            &session_id,
            b"bytes",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(12),
            12,
        )
        .expect_err("append to non-BLOB_ARTIFACT must fail");
    assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);

    // Empty bytes and blank agent run refs fail closed.
    let artifact_id = put_artifact(&vault, 13)?;
    let err = vault
        .append_blob_artifact_version(
            &artifact_id,
            b"",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(14),
            14,
        )
        .expect_err("empty bytes must fail");
    assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);
    let err = vault
        .append_blob_artifact_version(
            &artifact_id,
            b"bytes",
            &BlobVersionProvenance::AgentRun {
                run_ref: "   ".to_owned(),
            },
            actor,
            test_time(15),
            15,
        )
        .expect_err("blank run_ref must fail");
    assert_eq!(err.kind(), ErrorKind::InvalidBlobArtifactBody);
    assert!(vault.blob_artifact_versions(&artifact_id)?.is_empty());
    Ok(())
}

#[test]
fn blob_birth_four_rungs_only_normalize_transport_and_are_purged() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let artifact = put_artifact(&vault, 1)?;
    let actor = put_actor(&vault, 1)?;
    let append = |bytes: &[u8]| {
        vault.append_blob_artifact_version(
            &artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(2),
            2,
        )
    };
    let first = append(b"# Page\n\nText")?;
    let transport = append(b"# Page\r\n\r\nText")?;
    assert_eq!(transport.version, first.version + 1);
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, first.version)?,
        Some(b"# Page\n\nText".to_vec())
    );
    assert_eq!(
        vault.read_blob_artifact_version(&artifact, transport.version)?,
        Some(b"# Page\r\n\r\nText".to_vec())
    );
    assert_eq!(append(b"# Page\r\n\r\nText")?, transport);
    let initial = vault.blob_fingerprint(&artifact)?.unwrap();
    let next = append(b"# Page\n\nText\n\n# Another\n\nMore")?;
    assert_eq!(next.version, 3);
    let changed = vault.blob_fingerprint(&artifact)?.unwrap();
    for (key, value) in &initial.blocks {
        assert_eq!(Some(value), changed.blocks.get(key));
    }
    assert_eq!(append(b"# Page\n\nTEXT\n\n# Another\n\nMore")?.version, 4);
    vault.delete_entity(&artifact)?;
    assert!(vault.blob_fingerprint(&artifact)?.is_none());
    Ok(())
}

#[test]
fn blob_artifact_forks_machine_version_without_rewriting_history() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let artifact = put_artifact(&vault, 10)?; // an xlsx body
    let actor = put_actor(&vault, 10)?;
    let upload = vault.append_blob_artifact_version(
        &artifact,
        b"uploaded xlsx",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;
    let machine = vault.append_blob_artifact_version(
        &artifact,
        b"machine xlsx",
        &BlobVersionProvenance::AgentRun {
            run_ref: "run:edit".into(),
        },
        actor,
        test_time(12),
        12,
    )?;
    let original = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(
                &txn,
                &super::store_keys::blob_artifact_version_key(&artifact, machine.version),
            )?
            .unwrap()
            .to_vec()
    };
    let child = vault.fork_blob_artifact_version(
        &artifact,
        machine.version,
        b"person xlsx",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(13),
        13,
    )?;
    assert_eq!(child.version, 3);
    assert_eq!(child.parent_version, Some(machine.version));
    assert_eq!(child.fork_of_version, Some(machine.version));
    let linear = vault.append_blob_artifact_version(
        &artifact,
        b"next xlsx",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(14),
        14,
    )?;
    assert_eq!(linear.version, 4);
    assert_eq!(linear.parent_version, Some(child.version));
    assert_eq!(linear.fork_of_version, None);
    assert_eq!(vault.blob_artifact_head(&artifact)?, Some(linear.clone()));
    assert_eq!(upload.parent_version, None);
    assert_eq!(upload.fork_of_version, None);
    let txn = vault.store.env.read_txn()?;
    let legacy_raw = vault
        .store
        .vault_meta
        .get(
            &txn,
            &super::store_keys::blob_artifact_version_key(&artifact, upload.version),
        )?
        .unwrap();
    assert_eq!(
        rmpv::decode::read_value(&mut std::io::Cursor::new(legacy_raw))
            .unwrap()
            .as_map()
            .unwrap()
            .len(),
        8 // the root also records both nil calculator fields
    );
    drop(txn);
    assert_eq!(
        vault.blob_artifact_versions(&artifact)?,
        vec![upload, machine.clone(), child.clone(), linear]
    );
    assert_eq!(
        vault.blob_artifact_version_metadata(&artifact, child.version)?,
        Some(child.clone())
    );
    let claim = vault.get_claim(&child.claim_id)?.expect("fork claim");
    assert!(
        claim
            .value
            .as_map()
            .expect("map")
            .iter()
            .any(|(key, val)| key.as_str() == Some("parent_version")
                && val.as_u64() == Some(machine.version))
    );
    let txn = vault.store.env.read_txn()?;
    let unchanged = vault.store.vault_meta.get(
        &txn,
        &super::store_keys::blob_artifact_version_key(&artifact, machine.version),
    )?;
    assert_eq!(unchanged.as_deref(), Some(original.as_slice()));
    Ok(())
}

#[test]
fn blob_artifact_fork_rejects_missing_parent_without_advancing_head() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let artifact = put_artifact(&vault, 10)?;
    let other = put_artifact(&vault, 10)?;
    let actor = put_actor(&vault, 10)?;
    let initial = vault.append_blob_artifact_version(
        &artifact,
        b"xlsx v1",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;
    vault.append_blob_artifact_version(
        &other,
        b"other xlsx",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;
    for missing in [0, 2, u64::MAX] {
        assert_eq!(
            vault
                .fork_blob_artifact_version(
                    &artifact,
                    missing,
                    b"fork",
                    &BlobVersionProvenance::UserUpload,
                    actor,
                    test_time(12),
                    12,
                )
                .expect_err("parent must exist on this artifact")
                .kind(),
            ErrorKind::InvalidBlobArtifactBody,
        );
    }
    assert_eq!(
        vault.blob_artifact_versions(&artifact)?,
        vec![initial.clone()]
    );
    assert_eq!(vault.blob_artifact_head(&artifact)?, Some(initial.clone()));
    // The explicit fork remains an event even when its bytes equal the head's.
    let identical = vault.fork_blob_artifact_version(
        &artifact,
        1,
        b"xlsx v1",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(13),
        13,
    )?;
    assert_eq!(identical.version, 2);
    assert_eq!(identical.content_hash, initial.content_hash);
    assert_eq!(identical.parent_version, Some(1));
    assert_eq!(vault.blob_artifact_head(&artifact)?, Some(identical));
    Ok(())
}

#[test]
fn blob_artifact_tree_reader_refuses_bad_parent_and_head() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let artifact = put_artifact(&vault, 10)?;
    let actor = put_actor(&vault, 10)?;
    let first = vault.append_blob_artifact_version(
        &artifact,
        b"xlsx v1",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(11),
        11,
    )?;
    vault.append_blob_artifact_version(
        &artifact,
        b"machine xlsx",
        &BlobVersionProvenance::AgentRun {
            run_ref: "run:1".into(),
        },
        actor,
        test_time(12),
        12,
    )?;
    let child = vault.fork_blob_artifact_version(
        &artifact,
        first.version,
        b"forked xlsx",
        &BlobVersionProvenance::UserUpload,
        actor,
        test_time(13),
        13,
    )?;
    let key = super::store_keys::blob_artifact_version_key(&artifact, child.version);
    let head_key = super::store_keys::blob_artifact_head_key(&artifact);
    let first_key = super::store_keys::blob_artifact_version_key(&artifact, first.version);
    let (original, root) = {
        let txn = vault.store.env.read_txn()?;
        (
            vault.store.vault_meta.get(&txn, &key)?.unwrap().to_vec(),
            vault
                .store
                .vault_meta
                .get(&txn, &first_key)?
                .unwrap()
                .to_vec(),
        )
    };
    let mut forged = rmpv::decode::read_value(&mut std::io::Cursor::new(&original))
        .expect("decode stored version");
    let Value::Map(ref mut fields) = forged else {
        panic!("stored version must be a map");
    };
    for (name, value) in fields {
        if name.as_str() == Some("parent_version") {
            *value = Value::from(child.version); // cannot be its own parent
        }
    }
    let mut invalid = Vec::new();
    rmpv::encode::write_value(&mut invalid, &forged).expect("encode invalid pointer");
    let mut txn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(&mut txn, &key, &invalid)?;
    txn.commit()?;
    assert_eq!(
        vault
            .blob_artifact_versions(&artifact)
            .expect_err("reject a cycle")
            .kind(),
        ErrorKind::InvalidBlobArtifactBody
    );

    let mut txn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(&mut txn, &key, &original)?;
    vault.store.vault_meta.put(&mut txn, &head_key, &root)?;
    txn.commit()?;
    assert_eq!(
        vault
            .blob_artifact_versions(&artifact)
            .expect_err("reject stale head")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    Ok(())
}
