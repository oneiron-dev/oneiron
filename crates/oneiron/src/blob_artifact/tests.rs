use super::*;
use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, EntityClassification, TypeByteBand,
    entity_type_registry_entry, short_id_prefix,
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
    assert_eq!(decoded, test_body());
    assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_BLOB_ARTIFACT));
    assert_eq!(short_id_prefix(ENTITY_TYPE_BLOB_ARTIFACT)?, "ba");
    let entry =
        entity_type_registry_entry(ENTITY_TYPE_BLOB_ARTIFACT).expect("BLOB_ARTIFACT registry row");
    assert_eq!(entry.kind, "BLOB_ARTIFACT");
    assert_eq!(entry.classification, EntityClassification::Pack);
    assert_eq!(entry.band, TypeByteBand::Productivity);
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
