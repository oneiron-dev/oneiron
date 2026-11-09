//! Public cache boundary: real vaults and BLOB_ARTIFACT versions only.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::collections::BTreeMap;

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::edge::EdgeActorClass;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::write_envelope::WriteActor;
use oneiron::{
    ActionResult, ArtifactVersionRef, BuildAction, BuildCache, BuildCacheError, BuildInputRoot,
    BuildPlatform, DeclaredOutputPath, EntityId, FrozenBuildCommand, RepoRef, Vault, VaultConfig,
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
fn account_vaults_share_rows_artifact_bytes_and_producer_provenance() {
    let (_dir_a, vault_a) = temp_vault();
    let (_dir_b, vault_b) = temp_vault();
    let (_account_dir, account_vault) = temp_vault();
    for vault in [&vault_a, &vault_b, &account_vault] {
        BuildCache::bind_account(vault, "account-A").expect("bind account");
    }
    let writer = BuildCache::for_account(&vault_a, &account_vault, "account-A").expect("writer");
    let reader = BuildCache::for_account(&vault_b, &account_vault, "account-A").expect("reader");
    let action = action();
    let key = action.action_key().expect("key");
    let output = artifact(writer.artifact_vault(), b"shared account bytes");
    let mut proposed = result(output.clone());
    proposed.producer_ref = "member-A:build-1".into();
    writer.put(&action, proposed.clone()).expect("store from A");
    let hit = reader
        .get(&key)
        .expect("lookup from B")
        .expect("shared hit");
    assert_eq!(hit.result, proposed);
    assert_eq!(hit.result.producer_ref, "member-A:build-1");
    assert_eq!(
        reader
            .artifact_vault()
            .read_blob_artifact_version(output.artifact_id(), output.version())
            .expect("shared artifact"),
        Some(b"shared account bytes".to_vec())
    );
    assert!(matches!(
        BuildCache::for_account(&vault_b, &account_vault, "account-B"),
        Err(BuildCacheError::AccountMismatch)
    ));
    assert!(matches!(
        BuildCache::bind_account(&vault_b, "account-B"),
        Err(BuildCacheError::AccountMismatch)
    ));
}
