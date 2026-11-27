//! Artifact hard-delete clears Unattached snapshots but keeps the rows
//! (FIX HARD-DELETE-SETTLED-WORDS-OUTLIVE-ARTIFACT).

use super::*;
use crate::anchored_annotation::Anchor;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::embedding_test_config;

const TEXT_MIME: &str = "text/plain";
const WORDS: &str = "Budget: 40k.";

fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn put_actor(vault: &Vault, at: u64) -> WriteActor {
    let actor_id = EntityId::now();
    vault
        .put_entity(&actor_id, ENTITY_TYPE_PERSON, test_time(at), at, b"human")
        .expect("put actor");
    WriteActor::new(actor_id, EdgeActorClass::Human)
}

fn put_artifact(vault: &Vault, name: &str, mime: &str, v1: &[u8], actor: WriteActor) -> EntityId {
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(name, mime),
            test_time(10),
            10,
        )
        .expect("put artifact");
    let version = vault
        .append_blob_artifact_version(
            &artifact,
            v1,
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(10),
            10,
        )
        .expect("append version 1")
        .version;
    assert_eq!(version, 1);
    artifact
}

fn upload(vault: &Vault, artifact: &EntityId, actor: WriteActor, bytes: &[u8], at: u64) -> u64 {
    vault
        .append_blob_artifact_version(
            artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(at),
            at,
        )
        .expect("append version")
        .version
}

fn open_thread(
    vault: &Vault,
    artifact: EntityId,
    version: u64,
    locator: &Locator,
    actor: WriteActor,
) -> AnnotationThread {
    vault
        .open_annotation_thread(
            &Anchor::new(artifact, version, locator.clone()),
            actor,
            "Check this.",
            test_time(11),
            11,
        )
        .expect("open thread")
}

fn v1_bytes() -> Vec<u8> {
    format!("Intro.\n{WORDS}\n").into_bytes()
}

fn v2_bytes() -> Vec<u8> {
    b"Intro.\n".to_vec()
}

/// The drifted-thread fixture: v1 holds the words, v2 deletes them, the thread opened on v1
/// drifts on the 1 -> 2 sweep and its Unattached row quotes the words.
fn unattached_fixture(vault: &Vault, actor: WriteActor) -> (EntityId, EntityId) {
    let artifact = put_artifact(vault, "notes.txt", TEXT_MIME, &v1_bytes(), actor);
    assert_eq!(upload(vault, &artifact, actor, &v2_bytes(), 11), 2);
    let locator = Locator::text(7, 19).expect("text locator");
    let thread = open_thread(vault, artifact, 1, &locator, actor);
    let thread_id = thread.thread_id;
    let summary = vault
        .reanchor_annotation_threads(&artifact, 1, 2, &[], actor, test_time(13), 13)
        .expect("reanchor sweep");
    assert_eq!(summary.drifted.len(), 1);
    assert!(summary.remapped.is_empty());
    (artifact, thread_id)
}

#[test]
fn hard_delete_of_an_artifact_clears_its_unattached_quotes_and_keeps_the_rows() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let (artifact, thread_id) = unattached_fixture(&vault, actor);
    let rtxn = vault.store.env.read_txn()?;
    let before = super::UNATTACHED
        .get(&vault.store, &rtxn, &(artifact, thread_id))?
        .expect("unattached row");
    assert_eq!(before.snapshot.as_deref(), Some(WORDS));
    let pinned = before.pinned_version;
    let detached_at = before.detached_at_version;
    drop(rtxn);
    vault.delete_entity_with_reason(&artifact, DeleteReason::UserHardDelete)?;
    let rtxn = vault.store.env.read_txn()?;
    let after = super::UNATTACHED
        .get(&vault.store, &rtxn, &(artifact, thread_id))?
        .expect("unattached row stays");
    assert_eq!(after.snapshot, None);
    assert_eq!(after.pinned_version, pinned);
    assert_eq!(after.detached_at_version, detached_at);
    Ok(())
}

#[test]
fn deleting_one_artifact_keeps_another_artifacts_unattached_quote() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(embedding_test_config());
    let actor = put_actor(&vault, 10);
    let (first, _) = unattached_fixture(&vault, actor);
    let (second, second_thread) = unattached_fixture(&vault, actor);
    vault.delete_entity_with_reason(&first, DeleteReason::UserHardDelete)?;
    let rtxn = vault.store.env.read_txn()?;
    let kept = super::UNATTACHED
        .get(&vault.store, &rtxn, &(second, second_thread))?
        .expect("second artifact row stays");
    assert_eq!(kept.snapshot.as_deref(), Some(WORDS));
    Ok(())
}
