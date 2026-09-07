//! Public cache boundary: real vaults and BLOB_ARTIFACT versions only.

use std::collections::BTreeMap;

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::edge::EdgeActorClass;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::write_envelope::WriteActor;
use oneiron::{
    ActionResult, ArtifactVersionRef, BuildAction, BuildCache, BuildCacheError,
    BuildCachePutOutcome, BuildInputRoot, BuildPlatform, DeclaredOutputPath, EntityId,
    FrozenBuildCommand, RepoRef, Vault, VaultConfig,
};

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn path(value: &str) -> DeclaredOutputPath {
    DeclaredOutputPath::parse(value).expect("canonical path")
}

fn action() -> BuildAction {
    BuildAction::new(
        FrozenBuildCommand::new(vec!["cc".into(), "main.c".into()], [("LANG", "C")])
            .expect("command"),
        BuildInputRoot {
            repo_ref: RepoRef::parse(&format!("github:owner/repo#{}", "a".repeat(40)))
                .expect("repo"),
            fork_hash: [7; 32],
            extra_inputs: Vec::new(),
        },
        BuildPlatform::new([("os", "linux")]).expect("platform"),
        vec![path("out/bin"), path("out/optional")],
    )
    .expect("action")
}

fn append(vault: &Vault, id: &EntityId, bytes: &[u8]) -> ArtifactVersionRef {
    let at = TimeRange { start: 10, end: 10 };
    let actor_id = EntityId::now();
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, at, 10, b"uploader")
        .expect("put actor");
    let version = vault
        .append_blob_artifact_version(
            id,
            bytes,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(actor_id, EdgeActorClass::Human),
            at,
            11,
        )
        .expect("append version");
    ArtifactVersionRef::new(*id, version.version).expect("version ref")
}

fn artifact(vault: &Vault, bytes: &[u8]) -> ArtifactVersionRef {
    let id = EntityId::now();
    vault
        .put_blob_artifact(
            &id,
            &BlobArtifactBody::new("build.bin", "application/octet-stream"),
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("put artifact");
    append(vault, &id, bytes)
}

fn result(reference: ArtifactVersionRef) -> ActionResult {
    ActionResult {
        exit_code: 17,
        outputs: BTreeMap::from([(path("out/bin"), reference.clone())]),
        stdout_ref: Some(reference),
        stderr_ref: None,
        produced_at: 1_700_000_123,
        producer_ref: "executor:first".into(),
    }
}

#[test]
fn put_get_preserves_full_result_and_exact_versions() {
    let (_dir, vault) = temp_vault();
    let output = artifact(&vault, b"binary");
    let stdout = append(&vault, output.artifact_id(), b"stdout");
    let stderr = artifact(&vault, b"stderr!");
    let mut proposed = result(output.clone());
    proposed.stdout_ref = Some(stdout.clone());
    proposed.stderr_ref = Some(stderr.clone());
    let action = action();
    let cache = BuildCache::new(&vault);
    let BuildCachePutOutcome::Stored(stored) = cache.put(&action, proposed.clone()).expect("store")
    else {
        panic!("expected Stored");
    };
    assert_eq!(stored.result, proposed);
    assert_eq!(stored.action_key, action.action_key().expect("key"));
    assert_eq!(stored.referenced_bytes, 19);
    let newer = append(&vault, output.artifact_id(), b"new head");
    assert!(newer.version() > stdout.version());
    let hit = cache.get(&stored.action_key).expect("get").expect("hit");
    assert_eq!(hit, stored);
    assert_eq!(hit.result.outputs.get(&path("out/bin")), Some(&output));
    assert_eq!(hit.result.stdout_ref, Some(stdout));
    assert_eq!(hit.result.stderr_ref, Some(stderr));
}

#[test]
fn first_writer_wins_and_existing_short_circuits_invalid_proposals() {
    let (_dir, vault) = temp_vault();
    let action = action();
    let reference = artifact(&vault, b"first result");
    let first = result(reference.clone());
    let cache = BuildCache::new(&vault);
    cache.put(&action, first.clone()).expect("store first");
    let candidate_ref = append(&vault, reference.artifact_id(), b"different candidate");
    let mut candidate = result(candidate_ref);
    candidate.producer_ref = "executor:second".into();
    let BuildCachePutOutcome::Existing(existing) = cache.put(&action, candidate).expect("existing")
    else {
        panic!("expected Existing");
    };
    assert_eq!(existing.result, first);
    let mut invalid = result(reference.clone());
    invalid.outputs.insert(path("undeclared"), reference);
    invalid.producer_ref.clear();
    assert!(invalid.validate().is_err());
    assert_eq!(
        cache
            .put(&action, invalid)
            .expect("existing before validation"),
        BuildCachePutOutcome::Existing(existing.clone())
    );
    assert_eq!(
        cache.get(&existing.action_key).expect("get"),
        Some(existing)
    );
}

#[test]
fn independent_vaults_do_not_share_rows_or_artifacts() {
    let (_dir_a, vault_a) = temp_vault();
    let (_dir_b, vault_b) = temp_vault();
    let action_a = action();
    let action_b = action();
    let key = action_a.action_key().expect("key");
    assert_eq!(key, action_b.action_key().expect("identical key"));
    let proposed = result(artifact(&vault_a, b"vault A only"));
    BuildCache::new(&vault_a)
        .put(&action_a, proposed.clone())
        .expect("store A");
    assert!(matches!(BuildCache::new(&vault_b).get(&key), Ok(None)));
    assert!(matches!(
        BuildCache::new(&vault_b).put(&action_b, proposed),
        Err(BuildCacheError::ArtifactUnavailable { .. })
    ));
    assert!(matches!(BuildCache::new(&vault_b).get(&key), Ok(None)));
}

#[test]
fn unavailable_artifacts_or_versions_leave_no_index_row() {
    let (_dir, vault) = temp_vault();
    let cache = BuildCache::new(&vault);
    let action = action();
    let key = action.action_key().expect("key");
    let missing_artifact = ArtifactVersionRef::new(EntityId::now(), 1).expect("ref");
    let existing = artifact(&vault, b"present version");
    let missing_version =
        ArtifactVersionRef::new(*existing.artifact_id(), existing.version() + 1).expect("ref");
    for reference in [missing_artifact, missing_version] {
        let expected = reference.to_result_ref();
        assert!(matches!(cache.put(&action, result(reference)),
            Err(BuildCacheError::ArtifactUnavailable { artifact_ref }) if artifact_ref == expected));
        assert!(matches!(cache.get(&key), Ok(None)));
    }
}

#[test]
fn independent_cache_instances_share_one_vault() {
    let (_dir, vault) = temp_vault();
    let action = action();
    let writer = BuildCache::new(&vault);
    let reader = BuildCache::new(&vault);
    let BuildCachePutOutcome::Stored(stored) = writer
        .put(&action, result(artifact(&vault, b"shared")))
        .expect("store")
    else {
        panic!("expected Stored");
    };
    assert_eq!(
        reader.get(&stored.action_key).expect("read"),
        Some(stored.clone())
    );
    assert_eq!(writer.get(&stored.action_key).expect("read"), Some(stored));
}

#[test]
fn decoded_refs_have_exact_artifact_at_version_spelling() {
    let (_dir, vault) = temp_vault();
    let reference = artifact(&vault, b"version one");
    let reference = append(&vault, reference.artifact_id(), b"version two");
    let expected = format!("{}@2", reference.artifact_id().to_hex());
    let mut proposed = result(reference.clone());
    proposed.stderr_ref = Some(reference);
    let action = action();
    let cache = BuildCache::new(&vault);
    cache.put(&action, proposed).expect("store");
    let hit = cache
        .get(&action.action_key().expect("key"))
        .expect("get")
        .expect("hit");
    for reference in hit
        .result
        .outputs
        .values()
        .chain(hit.result.stdout_ref.iter())
        .chain(hit.result.stderr_ref.iter())
    {
        assert_eq!(reference.to_result_ref(), expected);
        assert_eq!(
            &ArtifactVersionRef::parse(&expected).expect("parse exact ref"),
            reference
        );
    }
    assert_eq!(
        hit.referenced_bytes, 11,
        "same version in three roles counts once"
    );
}
