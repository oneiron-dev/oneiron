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

// Select the version index rather than its duplicate head row. Use the
// discovered key bytes; do not reconstruct the private artifact/version key.
fn exact_version_row(vault: &Vault, record: &BlobArtifactVersion) -> (Vec<u8>, Vec<u8>) {
    let mut rows = version_rows(vault, record)
        .into_iter()
        .filter(|(key, _)| key.starts_with(b"blob_artifact:version:"));
    let row = rows.next().expect("exact version row");
    assert!(rows.next().is_none(), "one row for this version claim");
    row
}

#[derive(Debug, PartialEq, Eq)]
struct HitStorageSnapshot {
    metadata: BTreeMap<Vec<u8>, Vec<u8>>,
    entities: BTreeMap<Vec<u8>, Vec<u8>>,
}

fn hit_storage_snapshot(vault: &Vault) -> HitStorageSnapshot {
    let txn = vault.store.env.read_txn().expect("read txn");
    HitStorageSnapshot {
        metadata: vault
            .store
            .vault_meta
            .iter(&txn)
            .expect("metadata iter")
            .map(|entry| {
                let (key, raw) = entry.expect("metadata row");
                (key.to_vec(), raw.to_vec())
            })
            .collect(),
        entities: vault
            .store
            .entities
            .iter(&txn)
            .expect("entity iter")
            .map(|entry| {
                let (key, raw) = entry.expect("entity row");
                (key.to_vec(), raw.to_vec())
            })
            .collect(),
    }
}

fn assert_binding_refuses_hits(
    vault: &Vault,
    action: &BuildAction,
    reference: &ArtifactVersionRef,
) {
    let before = hit_storage_snapshot(vault);
    assert!(matches!(
        vault.blob_artifact_version_metadata(reference.artifact_id(), reference.version()),
        Err(Error::CorruptedIndex("blob artifact version claim")) | Err(Error::InvalidClaimBody(_))
    ));
    let cache = BuildCache::new(vault);
    assert!(matches!(
        cache.get(&key(action)),
        Err(BuildCacheError::Store(Error::CorruptedIndex(
            "blob artifact version claim"
        ))) | Err(BuildCacheError::Store(Error::InvalidClaimBody(_)))
    ));
    assert_eq!(hit_storage_snapshot(vault), before);
    assert!(matches!(
        cache.put(action, result(reference.clone())),
        Err(BuildCacheError::Store(Error::CorruptedIndex(
            "blob artifact version claim"
        ))) | Err(BuildCacheError::Store(Error::InvalidClaimBody(_)))
    ));
    assert_eq!(hit_storage_snapshot(vault), before);
}

fn same_version_substitution_fails_closed(historical: bool) {
    let (_dir, vault) = temp_vault();
    let references = [
        artifact(&vault, b"clean artifact version one"),
        artifact(&vault, b"foreign artifact version one"),
    ];
    let first_action = action();
    let mut foreign_action = first_action.clone();
    foreign_action.input_root.fork_hash[0] ^= 1;
    let actions = [first_action, foreign_action];
    let cache = BuildCache::new(&vault);
    let mut stored = Vec::new();
    for (action, reference) in actions.iter().zip(&references) {
        let BuildCachePutOutcome::Stored(record) = cache
            .put(action, result(reference.clone()))
            .expect("store before substitution")
        else {
            panic!("expected Stored");
        };
        stored.push(record);
    }
    if historical {
        let actor_id = EntityId::now();
        let at = TimeRange { start: 20, end: 20 };
        vault
            .put_entity(&actor_id, ENTITY_TYPE_PERSON, at, 20, b"uploader")
            .expect("put actor");
        for reference in &references {
            let head = vault
                .append_blob_artifact_version(
                    reference.artifact_id(),
                    b"newer head bytes",
                    &BlobVersionProvenance::UserUpload,
                    WriteActor::new(actor_id, EdgeActorClass::Human),
                    at,
                    21,
                )
                .expect("advance head");
            assert_eq!(head.version, 2);
        }
    }
    // Valid historical refs must still hit after both heads advance.
    let before_hits = hit_storage_snapshot(&vault);
    for ((action, reference), record) in actions.iter().zip(&references).zip(&stored) {
        assert_eq!(
            cache.get(&record.action_key).expect("hit"),
            Some(record.clone())
        );
        assert_eq!(
            cache
                .put(action, result(reference.clone()))
                .expect("existing"),
            BuildCachePutOutcome::Existing(record.clone())
        );
    }
    assert_eq!(hit_storage_snapshot(&vault), before_hits);
    mark_live(&vault, &references[1]);
    assert_eq!(
        vault
            .artifact_taint_state(references[0].artifact_id())
            .expect("clean target"),
        ArtifactTaintState::Clean
    );
    let rows = references.each_ref().map(|reference| {
        let record = vault
            .blob_artifact_version_metadata(reference.artifact_id(), reference.version())
            .expect("metadata")
            .expect("version");
        assert_eq!(record.version, 1);
        exact_version_row(&vault, &record)
    });
    let heads = references.each_ref().map(|reference| {
        vault
            .blob_artifact_head(reference.artifact_id())
            .expect("head")
    });
    let before_swap = hit_storage_snapshot(&vault);
    let mut txn = vault.store.env.write_txn().expect("write txn");
    for (target, source) in [(&rows[0], &rows[1]), (&rows[1], &rows[0])] {
        vault
            .store
            .vault_meta
            .put(&mut txn, &target.0, &source.1)
            .expect("swap same-version records only");
    }
    txn.commit().expect("commit substitution");
    let after_swap = hit_storage_snapshot(&vault);
    assert_eq!(
        after_swap.entities, before_swap.entities,
        "bodies untouched"
    );
    for ((action, reference), head) in actions.iter().zip(&references).zip(&heads) {
        assert_eq!(
            vault
                .blob_artifact_head(reference.artifact_id())
                .expect("unchanged head"),
            *head
        );
        assert_eq!(
            raw_row(&vault, &key(action)),
            before_swap
                .metadata
                .get(build_cache_key(&key(action)).as_slice())
                .cloned()
        );
        assert_binding_refuses_hits(&vault, action, reference);
    }
    assert_eq!(hit_storage_snapshot(&vault), after_swap);
}

#[test]
fn current_head_same_version_substitution_refuses_get_and_existing_put() {
    same_version_substitution_fails_closed(false);
}

#[test]
fn historical_same_version_substitution_refuses_get_and_existing_put() {
    same_version_substitution_fails_closed(true);
}

fn replace_version_field(raw: &[u8], field: &str, replacement: Value) -> Vec<u8> {
    let mut value = rmpv::decode::read_value(&mut Cursor::new(raw)).expect("version record");
    let Value::Map(fields) = &mut value else {
        panic!("version map");
    };
    let (_, field_value) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(field))
        .expect("version field");
    *field_value = replacement;
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &value).expect("encode forged version");
    encoded
}

#[test]
fn version_claim_binding_checks_hash_version_and_claim_existence() {
    let (_dir, vault) = temp_vault();
    let (first, second) = two_versions(&vault);
    let oldest = vault
        .blob_artifact_version_metadata(first.artifact_id(), first.version())
        .expect("metadata")
        .expect("oldest");
    let actor_id = EntityId::now();
    let at = TimeRange { start: 30, end: 30 };
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, at, 30, b"uploader")
        .expect("put actor");
    let third = vault
        .append_blob_artifact_version(
            first.artifact_id(),
            b"first version bytes",
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(actor_id, EdgeActorClass::Human),
            at,
            31,
        )
        .expect("revisit first hash at a distinct version");
    assert_eq!(third.version, 3);
    assert_eq!(third.content_hash, oldest.content_hash);
    let (version_key, original) = exact_version_row(&vault, &oldest);
    let action = action();
    BuildCache::new(&vault)
        .put(&action, result(first.clone()))
        .expect("store oldest");
    for (field, replacement) in [
        // The right subject and version cannot authorize a different hash.
        (
            BLOB_ARTIFACT_VERSION_RECORD_KEYS[1],
            Value::Binary(second.content_hash.to_vec()),
        ),
        // The right subject and hash cannot authorize a different version.
        (
            BLOB_ARTIFACT_VERSION_RECORD_KEYS[4],
            Value::Binary(third.claim_id.as_bytes().to_vec()),
        ),
        // A dangling id or an existing non-CLAIM cannot establish ownership.
        (
            BLOB_ARTIFACT_VERSION_RECORD_KEYS[4],
            Value::Binary(EntityId::now().as_bytes().to_vec()),
        ),
        (
            BLOB_ARTIFACT_VERSION_RECORD_KEYS[4],
            Value::Binary(first.artifact_id().as_bytes().to_vec()),
        ),
    ] {
        let forged = replace_version_field(&original, field, replacement);
        let mut txn = vault.store.env.write_txn().expect("write txn");
        vault
            .store
            .vault_meta
            .put(&mut txn, &version_key, &forged)
            .expect("forge version binding");
        txn.commit().expect("commit fixture");
        assert_binding_refuses_hits(&vault, &action, &first);
    }
}
