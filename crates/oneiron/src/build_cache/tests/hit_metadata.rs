use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::blob_artifact::{BLOB_ARTIFACT_VERSION_RECORD_KEYS, BlobArtifactVersion};
use crate::registry::ENTITY_TYPE_ASSET;
use rmpv::Value;

fn two_versions(vault: &Vault) -> (ArtifactVersionRef, BlobArtifactVersion) {
    let first = artifact(vault, b"first version bytes");
    let actor_id = EntityId::now();
    let at = TimeRange { start: 20, end: 20 };
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, at, 20, b"uploader")
        .expect("put actor");
    let second = vault
        .append_blob_artifact_version(
            first.artifact_id(),
            b"second version bytes",
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(actor_id, EdgeActorClass::Human),
            at,
            21,
        )
        .expect("append second version");
    assert_eq!(second.version, 2);
    (first, second)
}

// Discover existing rows by their public record fields. These corruption
// fixtures neither reproduce private key encoding nor decode secret taint.
fn version_rows(vault: &Vault, record: &BlobArtifactVersion) -> Vec<(Vec<u8>, Vec<u8>)> {
    let txn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .vault_meta
        .iter(&txn)
        .expect("metadata iter")
        .filter_map(|entry| {
            let (key, raw) = entry.expect("metadata row");
            let Ok(Value::Map(fields)) = rmpv::decode::read_value(&mut Cursor::new(&raw)) else {
                return None;
            };
            fields
                .iter()
                .any(|(key, value)| {
                    key.as_str() == Some(BLOB_ARTIFACT_VERSION_RECORD_KEYS[4])
                        && value == &Value::Binary(record.claim_id.as_bytes().to_vec())
                })
                .then(|| (key.to_vec(), raw.to_vec()))
        })
        .collect()
}

#[test]
fn metadata_lookup_is_exact_and_never_falls_back_to_head() {
    let (_dir, vault) = temp_vault();
    let (first, second) = two_versions(&vault);
    let oldest = vault
        .blob_artifact_version_metadata(first.artifact_id(), first.version())
        .expect("metadata lookup")
        .expect("oldest version");
    assert_eq!(oldest.version, 1);
    assert_ne!(oldest.content_hash, second.content_hash);
    assert_eq!(
        vault
            .blob_artifact_version_metadata(first.artifact_id(), second.version)
            .expect("head metadata"),
        Some(second)
    );
    for version in [0, 3, u64::MAX] {
        assert!(
            vault
                .blob_artifact_version_metadata(first.artifact_id(), version)
                .expect("absent version")
                .is_none()
        );
    }
    assert!(
        vault
            .blob_artifact_version_metadata(&EntityId::now(), 1)
            .expect("absent artifact")
            .is_none()
    );
}

#[test]
fn hits_ignore_unrelated_version_metadata_and_do_not_read_content() {
    let (_dir, vault) = temp_vault();
    let (first, second) = two_versions(&vault);
    let action = action();
    let cache = BuildCache::new(&vault);
    let BuildCachePutOutcome::Stored(stored) = cache
        .put(&action, result(first.clone()))
        .expect("store oldest version")
    else {
        panic!("expected Stored");
    };
    let before = raw_row(&vault, &stored.action_key).expect("cache row");
    let unrelated = version_rows(&vault, &second);
    assert_eq!(unrelated.len(), 2, "the second version and head records");
    let assets: Vec<Vec<u8>> = {
        let txn = vault.store.env.read_txn().expect("read txn");
        vault
            .store
            .entities
            .iter(&txn)
            .expect("entity iter")
            .filter_map(|entry| {
                let (key, raw) = entry.expect("entity row");
                let header = EntityMetadataHeader::parse(&raw).expect("entity header");
                (header.entity_type == ENTITY_TYPE_ASSET).then(|| key.to_vec())
            })
            .collect()
    };
    assert_eq!(assets.len(), 2);
    let mut txn = vault.store.env.write_txn().expect("write txn");
    for (key, _) in unrelated {
        vault
            .store
            .vault_meta
            .put(&mut txn, &key, &[0xc0])
            .expect("corrupt unrelated metadata");
    }
    for key in assets {
        assert!(
            vault
                .store
                .entities
                .delete(&mut txn, &key)
                .expect("remove content without lifecycle cleanup")
        );
    }
    txn.commit().expect("commit corruption fixture");
    assert!(vault.blob_artifact_versions(first.artifact_id()).is_err());
    assert!(
        vault
            .read_blob_artifact_version(first.artifact_id(), first.version())
            .is_err(),
        "a content read would fail, so a successful hit proves it never ran"
    );
    assert_eq!(
        cache.get(&stored.action_key).expect("metadata-only hit"),
        Some(stored.clone())
    );
    assert_eq!(
        cache
            .put(&action, result(first.clone()))
            .expect("metadata-only existing result"),
        BuildCachePutOutcome::Existing(stored.clone())
    );
    assert_eq!(raw_row(&vault, &stored.action_key).expect("row"), before);
    mark_live(&vault, &first);
    assert!(matches!(
        cache.get(&stored.action_key),
        Err(BuildCacheError::TaintedResult { .. })
    ));
    assert!(matches!(
        cache.put(&action, result(first)),
        Err(BuildCacheError::TaintedResult { .. })
    ));
    assert_eq!(raw_row(&vault, &stored.action_key).expect("row"), before);
}

#[test]
fn requested_version_corruption_tombstones_hits_without_repair() {
    let (_dir, vault) = temp_vault();
    let (first, second) = two_versions(&vault);
    let oldest = vault
        .blob_artifact_version_metadata(first.artifact_id(), first.version())
        .expect("lookup")
        .expect("oldest metadata");
    let rows = version_rows(&vault, &oldest);
    assert_eq!(rows.len(), 1, "the head has advanced beyond this version");
    let version_key = &rows[0].0;
    let second_raw = version_rows(&vault, &second)[0].1.clone();
    let action = action();
    let cache = BuildCache::new(&vault);
    cache
        .put(&action, result(first.clone()))
        .expect("store oldest");
    let key = key(&action);
    let before = raw_row(&vault, &key).expect("cache row");
    for replacement in [None, Some(vec![0xc0]), Some(second_raw)] {
        let mut txn = vault.store.env.write_txn().expect("write txn");
        if let Some(raw) = &replacement {
            vault
                .store
                .vault_meta
                .put(&mut txn, version_key, raw)
                .expect("corrupt requested record");
        } else {
            assert!(
                vault
                    .store
                    .vault_meta
                    .delete(&mut txn, version_key)
                    .expect("remove requested record")
            );
        }
        txn.commit().expect("commit fixture");
        let metadata = vault.blob_artifact_version_metadata(first.artifact_id(), first.version());
        match replacement.as_deref() {
            None => assert!(metadata.expect("absent record").is_none()),
            Some([0xc0]) => assert!(matches!(metadata, Err(Error::InvalidBlobArtifactBody(_)))),
            Some(_) => assert!(matches!(
                metadata,
                Err(Error::CorruptedIndex("blob artifact version record"))
            )),
        }
        for refused in [
            cache.get(&key),
            cache.put(&action, result(first.clone())).map(|_| None),
        ] {
            if replacement.is_none() {
                assert!(matches!(refused,
                    Err(BuildCacheError::ArtifactUnavailable { artifact_ref })
                        if artifact_ref == first.to_result_ref()));
            } else {
                assert!(matches!(refused, Err(BuildCacheError::Store(_))));
            }
        }
        assert_eq!(raw_row(&vault, &key).expect("row"), before);
    }
}

#[test]
fn taint_read_errors_refuse_metadata_only_hits_without_repair() {
    let (_dir, vault) = temp_vault();
    let first = artifact(&vault, b"clean at insertion");
    let action = action();
    let cache = BuildCache::new(&vault);
    cache
        .put(&action, result(first.clone()))
        .expect("store clean");
    let key = key(&action);
    let before = raw_row(&vault, &key).expect("cache row");
    let mut raw = vault
        .get_raw(first.artifact_id())
        .expect("read artifact")
        .expect("artifact metadata");
    raw.truncate(ENTITY_METADATA_HEADER_LEN);
    raw.push(0xc0);
    let mut txn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .entities
        .put(&mut txn, first.artifact_id().as_bytes(), &raw)
        .expect("corrupt artifact metadata");
    txn.commit().expect("commit fixture");
    assert!(
        vault
            .blob_artifact_version_metadata(first.artifact_id(), first.version())
            .expect("version metadata remains valid")
            .is_some()
    );
    assert!(vault.artifact_taint_state(first.artifact_id()).is_err());
    assert!(matches!(
        cache.get(&key),
        Err(BuildCacheError::Store(Error::InvalidBlobArtifactBody(_)))
    ));
    assert!(matches!(
        cache.put(&action, result(first)),
        Err(BuildCacheError::Store(Error::InvalidBlobArtifactBody(_)))
    ));
    assert_eq!(raw_row(&vault, &key).expect("row"), before);
}
