use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    encode_claim_body,
};
use crate::code_artifact::{
    CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody, encode_code_artifact_body,
};
use crate::config::{HnswConfig, TextAnalyzerConfig, VaultConfig};
use crate::error::ErrorKind;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.text_analyzer = TextAnalyzerConfig::default();
    config
}

use crate::test_util::entity;

fn artifact_body(tag: u8) -> CodeArtifactBody {
    CodeArtifactBody::new(
        format!("Summarize code revision {tag}."),
        [tag; CODE_ARTIFACT_SUMMARY_HASH_LEN],
        "github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277",
    )
}

fn put_session(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
    vault.put_entity(
        &id,
        ENTITY_TYPE_SESSION,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        b"session",
    )
}

fn put_artifact(vault: &Vault, id: EntityId, tag: u8, learned_at: u64) -> Result<()> {
    vault.put_code_artifact(
        &id,
        &artifact_body(tag),
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )
}

fn put_claim_entity(vault: &Vault, id: EntityId, subject: EntityId, learned_at: u64) -> Result<()> {
    put_claim_entity_with_source(vault, id, subject, None, learned_at)
}

fn put_claim_entity_with_source(
    vault: &Vault,
    id: EntityId,
    subject: EntityId,
    source: Option<ClaimSource>,
    learned_at: u64,
) -> Result<()> {
    put_claim_entity_with_source_and_approval(
        vault,
        id,
        subject,
        source,
        ClaimApprovalStatus::Auto,
        learned_at,
    )
}

fn put_claim_entity_with_source_and_approval(
    vault: &Vault,
    id: EntityId,
    subject: EntityId,
    source: Option<ClaimSource>,
    approval: ClaimApprovalStatus,
    learned_at: u64,
) -> Result<()> {
    let body = ClaimBody::new(
        CODE_REVISION_CLAIM_PREDICATE,
        ClaimSubject::Entity(subject),
        Value::from("finalized"),
        0.9,
        approval,
        ClaimLifecycleStatus::Active,
    );
    let mut body = body;
    body.source = source;
    let data = encode_claim_body(&body)?;
    if approval != ClaimApprovalStatus::Auto {
        return put_claim_entity_unchecked(vault, id, learned_at, &data);
    }
    vault.put_entity(
        &id,
        ENTITY_TYPE_CLAIM,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        &data,
    )
}

fn put_claim_entity_unchecked(
    vault: &Vault,
    id: EntityId,
    learned_at: u64,
    data: &[u8],
) -> Result<()> {
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_CLAIM);
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(data);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)?;
    let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &id);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    let temporal_key = Store::encode_temporal_key(learned_at, &id);
    vault
        .store
        .temporal_occurred_start
        .put(&mut wtxn, &temporal_key, &[])?;
    vault
        .store
        .temporal_learned
        .put(&mut wtxn, &temporal_key, &[])?;
    wtxn.commit()?;
    Ok(())
}

fn replace_entity_with_header_shell(vault: &Vault, id: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let raw = vault
        .store
        .entities
        .get(&wtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?
        .to_vec();
    let shell = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    vault.store.entities.put(&mut wtxn, id.as_bytes(), &shell)?;
    wtxn.commit()?;
    Ok(())
}

fn replace_code_artifact_body_unchecked(
    vault: &Vault,
    id: &EntityId,
    body: &CodeArtifactBody,
) -> Result<()> {
    let encoded = encode_code_artifact_body(body)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let raw = vault
        .store
        .entities
        .get(&wtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let mut next = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    next.extend_from_slice(&encoded);
    vault.store.entities.put(&mut wtxn, id.as_bytes(), &next)?;
    wtxn.commit()?;
    Ok(())
}

fn corrupt_code_revision_frontier_fold(vault: &Vault, session_id: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let key = code_revision_frontier_key(session_id);
    let raw = vault
        .store
        .vault_meta
        .get(&wtxn, &key)?
        .ok_or(Error::EntityNotFound)?;
    let mut frontier = decode_code_revision_frontier_record(&raw)?;
    frontier.revision_fold[0] ^= 0x80;
    let encoded = encode_code_revision_frontier_record(&frontier)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit()?;
    Ok(())
}

fn remove_code_revision_integrity_sidecars(
    vault: &Vault,
    revision_ids: &[EntityId],
    session_id: &EntityId,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    for revision_id in revision_ids {
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, &code_revision_integrity_key(revision_id))?;
    }
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, &code_revision_frontier_key(session_id))?;
    wtxn.commit()?;
    Ok(())
}

fn delete_code_revision_session_index_row(
    vault: &Vault,
    session_id: &EntityId,
    revision_id: &EntityId,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.delete(
        &mut wtxn,
        &code_revision_session_index_key(session_id, revision_id),
    )?;
    wtxn.commit()?;
    Ok(())
}

fn corrupt_code_revision_parent_fold_self_consistent(
    vault: &Vault,
    revision_id: &EntityId,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let revision = read_code_revision_record_in_txn(&vault.store, &wtxn, revision_id)?
        .ok_or(Error::EntityNotFound)?;
    let key = code_revision_integrity_key(revision_id);
    let raw = vault
        .store
        .vault_meta
        .get(&wtxn, &key)?
        .ok_or(Error::EntityNotFound)?;
    let mut record = decode_code_revision_integrity_record(&raw)?;
    let parent_fold = record
        .parent_fold
        .as_mut()
        .ok_or(Error::InvalidCodeArtifactBody(
            "test revision must have a parent fold",
        ))?;
    parent_fold[0] ^= 0x40;
    record.revision_fold = compute_code_revision_fold(
        revision.kind,
        &record.artifact_hash,
        revision.provenance_claim_id,
        record.parent_fold,
        record.reverted_to_fold,
    );
    let encoded = encode_code_revision_integrity_record(&record)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit()?;
    Ok(())
}

fn read_code_revision_integrity_record(
    vault: &Vault,
    revision_id: &EntityId,
) -> Result<CodeRevisionIntegrityRecord> {
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .vault_meta
        .get(&rtxn, &code_revision_integrity_key(revision_id))?
        .ok_or(Error::EntityNotFound)?;
    decode_code_revision_integrity_record(&raw)
}

fn replace_code_revision_record_unchecked(vault: &Vault, revision: &CodeRevision) -> Result<()> {
    let encoded = encode_code_revision(revision)?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &code_revision_record_key(&revision.revision_id),
        &encoded,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn replace_code_revision_integrity_record_unchecked(
    vault: &Vault,
    record: &CodeRevisionIntegrityRecord,
) -> Result<()> {
    let encoded = encode_code_revision_integrity_record(record)?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &code_revision_integrity_key(&record.revision_id),
        &encoded,
    )?;
    wtxn.commit()?;
    Ok(())
}

fn corrupt_code_revision_frontier_session(
    vault: &Vault,
    session_id: &EntityId,
    corrupt_session_id: EntityId,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let key = code_revision_frontier_key(session_id);
    let raw = vault
        .store
        .vault_meta
        .get(&wtxn, &key)?
        .ok_or(Error::EntityNotFound)?;
    let mut frontier = decode_code_revision_frontier_record(&raw)?;
    frontier.session_id = corrupt_session_id;
    let encoded = encode_code_revision_frontier_record(&frontier)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit()?;
    Ok(())
}

fn corrupt_code_revision_frontier_bytes(vault: &Vault, session_id: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &code_revision_frontier_key(session_id),
        b"not-a-frontier",
    )?;
    wtxn.commit()?;
    Ok(())
}

fn corrupt_code_revision_record_bytes(vault: &Vault, revision_id: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(
        &mut wtxn,
        &code_revision_record_key(revision_id),
        b"not-a-code-revision",
    )?;
    wtxn.commit()?;
    Ok(())
}

fn code_revision_integrity_sidecars_exist(
    vault: &Vault,
    revision_ids: &[EntityId],
    session_id: &EntityId,
) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    for revision_id in revision_ids {
        if vault
            .store
            .vault_meta
            .get(&rtxn, &code_revision_integrity_key(revision_id))?
            .is_none()
        {
            return Ok(false);
        }
    }
    Ok(vault
        .store
        .vault_meta
        .get(&rtxn, &code_revision_frontier_key(session_id))?
        .is_some())
}

#[test]
fn code_revision_codec_round_trips_commit_revert_and_fork() -> Result<()> {
    let session = entity(0x60);
    let first = entity(0x21);
    let second = entity(0x22);
    let third = entity(0x23);
    let provenance = entity(0x31);

    let commit = CodeRevision::commit_child(second, session, first, 2_000)
        .with_provenance_claim_id(provenance);
    let decoded = decode_code_revision(&encode_code_revision(&commit)?)?;
    assert_eq!(decoded, commit);

    let revert = CodeRevision::revert(third, session, second, first, 3_000);
    let decoded = decode_code_revision(&encode_code_revision(&revert)?)?;
    assert_eq!(decoded, revert);

    let fork = CodeRevisionFork::new(entity(0x41), session, second, 4_000);
    let decoded = decode_code_revision_fork(&encode_code_revision_fork(&fork)?)?;
    assert_eq!(decoded, fork);
    Ok(())
}

#[test]
fn code_revision_commit_finalizes_session_revision_and_links_parent() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let first = entity(0x21);
    let second = entity(0x22);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, first, 0xA1, 20)?;
    put_artifact(&vault, second, 0xA2, 30)?;

    let first_revision = CodeRevision::commit(first, session, 100);
    let second_revision = CodeRevision::commit_child(second, session, first, 200);
    vault.commit_code_revision(&first_revision)?;
    vault.commit_code_revision(&second_revision)?;

    assert_eq!(
        vault.get_code_revision(&first)?,
        Some(first_revision.clone())
    );
    assert_eq!(
        vault.get_code_revision(&second)?,
        Some(second_revision.clone())
    );
    assert_eq!(
        vault.code_revisions_for_session(&session)?,
        vec![first_revision, second_revision.clone()]
    );
    assert_eq!(vault.child_code_revisions(&first)?, vec![second_revision]);

    let supersedes = vault.targets(&second, EdgeKind::Supersedes, None)?;
    assert!(supersedes.contains(&first));
    let derived = vault.targets(&second, EdgeKind::DerivedFrom, None)?;
    assert!(derived.contains(&session));
    Ok(())
}

#[test]
fn code_revision_session_trace_orders_same_second_child_after_parent() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let parent = entity(0x30);
    let child = entity(0x20);
    let parent_revision = CodeRevision::commit(parent, session, 100);
    let child_revision = CodeRevision::commit_child(child, session, parent, 100);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, parent, 0xA1, 20)?;
    put_artifact(&vault, child, 0xA2, 30)?;

    vault.commit_code_revision(&parent_revision)?;
    vault.commit_code_revision(&child_revision)?;

    assert_eq!(
        vault.code_revisions_for_session(&session)?,
        vec![parent_revision, child_revision]
    );
    Ok(())
}

#[test]
fn code_revision_read_inside_write_txn_uses_existing_sidecars_without_nested_write() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    let revision = CodeRevision::commit(revision_id, session, 100);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    vault.commit_code_revision(&revision)?;

    vault.with_write_txn(|_| {
        assert_eq!(vault.get_code_revision(&revision_id)?, Some(revision));
        Ok(())
    })?;
    Ok(())
}

#[test]
fn code_revision_branch_records_session_dag_fork() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let parent_session = entity(0x60);
    let fork_session = entity(0x12);
    let base_revision = entity(0x21);
    put_session(&vault, parent_session, 10)?;
    put_session(&vault, fork_session, 11)?;
    put_artifact(&vault, base_revision, 0xA1, 20)?;
    vault.commit_code_revision(&CodeRevision::commit(base_revision, parent_session, 100))?;

    let fork = CodeRevisionFork::new(fork_session, parent_session, base_revision, 150);
    vault.branch_code_revision(&fork)?;

    assert_eq!(
        vault.get_code_revision_fork(&fork_session)?,
        Some(fork.clone())
    );
    assert_eq!(
        vault.code_revision_forks_from_session(&parent_session)?,
        vec![fork]
    );
    let parents = vault.targets(&fork_session, EdgeKind::ChildOf, None)?;
    assert!(parents.contains(&parent_session));
    let base = vault.targets(&fork_session, EdgeKind::DerivedFrom, None)?;
    assert!(base.contains(&base_revision));
    Ok(())
}

#[test]
fn code_revision_branch_rejects_base_revision_from_unrelated_session() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let parent_session = entity(0x60);
    let fork_session = entity(0x12);
    let other_session = entity(0x13);
    let base_revision = entity(0x21);
    put_session(&vault, parent_session, 10)?;
    put_session(&vault, fork_session, 11)?;
    put_session(&vault, other_session, 12)?;
    put_artifact(&vault, base_revision, 0xA1, 20)?;
    vault.commit_code_revision(&CodeRevision::commit(base_revision, other_session, 100))?;

    let err = vault
        .branch_code_revision(&CodeRevisionFork::new(
            fork_session,
            parent_session,
            base_revision,
            150,
        ))
        .expect_err("fork base revision must belong to the declared parent session");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("base_revision_id must belong to parent_session_id")
    );
    assert!(vault.get_code_revision_fork(&fork_session)?.is_none());
    assert!(
        vault
            .code_revision_forks_from_session(&parent_session)?
            .is_empty()
    );
    assert!(
        vault
            .targets(&fork_session, EdgeKind::ChildOf, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_revision_branch_rejects_corrupt_child_of_edge_row() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let parent_session = entity(0x60);
    let fork_session = entity(0x12);
    let base_revision = entity(0x21);
    put_session(&vault, parent_session, 10)?;
    put_session(&vault, fork_session, 11)?;
    put_artifact(&vault, base_revision, 0xA1, 20)?;
    vault.commit_code_revision(&CodeRevision::commit(base_revision, parent_session, 100))?;

    let edge_key = Store::encode_edge_key(&fork_session, EdgeKind::ChildOf, &parent_session);
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.edges_out.put(&mut wtxn, &edge_key, b"bad")?;
    wtxn.commit()?;

    let err = vault
        .branch_code_revision(&CodeRevisionFork::new(
            fork_session,
            parent_session,
            base_revision,
            150,
        ))
        .expect_err("corrupt ChildOf rows must fail closed before logical validation");

    assert_eq!(err.kind(), ErrorKind::CorruptedIndex);
    assert!(vault.get_code_revision_fork(&fork_session)?.is_none());
    Ok(())
}

#[test]
fn code_revision_revert_appends_superseding_revision_and_keeps_history() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let original = entity(0x21);
    let current = entity(0x22);
    let reverted = entity(0x23);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, original, 0xA1, 20)?;
    put_artifact(&vault, current, 0xA2, 30)?;
    put_artifact(&vault, reverted, 0xA3, 40)?;

    let original_revision = CodeRevision::commit(original, session, 100);
    let current_revision = CodeRevision::commit_child(current, session, original, 200);
    let reverted_revision = CodeRevision::revert(reverted, session, current, original, 300);
    vault.commit_code_revision(&original_revision)?;
    vault.commit_code_revision(&current_revision)?;
    vault.revert_code_revision(&reverted_revision)?;

    assert_eq!(vault.get_code_revision(&original)?, Some(original_revision));
    assert_eq!(vault.get_code_revision(&current)?, Some(current_revision));
    assert_eq!(
        vault.get_code_revision(&reverted)?,
        Some(reverted_revision.clone())
    );
    assert_eq!(
        vault.code_revisions_for_session(&session)?,
        vec![
            CodeRevision::commit(original, session, 100),
            CodeRevision::commit_child(current, session, original, 200),
            reverted_revision,
        ]
    );

    let supersedes = vault.targets(&reverted, EdgeKind::Supersedes, None)?;
    assert!(supersedes.contains(&current));
    let derived = vault.targets(&reverted, EdgeKind::DerivedFrom, None)?;
    assert!(derived.contains(&session));
    assert!(derived.contains(&original));
    Ok(())
}

#[test]
fn code_revision_batch_delete_removes_lifecycle_sidecars() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;

    let revision = CodeRevision::commit(revision_id, session, 100);
    vault.commit_code_revision(&revision)?;
    vault.batch().delete(&revision_id).commit()?;

    assert!(vault.get_code_revision(&revision_id)?.is_none());
    assert!(vault.code_revisions_for_session(&session)?.is_empty());

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &code_revision_record_key(&revision_id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(
                &rtxn,
                &code_revision_session_index_key(&session, &revision_id)
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn code_revision_delete_corrupt_record_removes_frontier_sidecar() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    vault.commit_code_revision(&CodeRevision::commit(revision_id, session, 100))?;
    corrupt_code_revision_record_bytes(&vault, &revision_id)?;

    vault.batch().delete(&revision_id).commit()?;

    assert!(vault.code_revisions_for_session(&session)?.is_empty());
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &code_revision_frontier_key(&session))?
            .is_none()
    );
    Ok(())
}

#[test]
fn code_revision_delete_corrupt_frontier_sidecar_repairs_from_key_session() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    vault.commit_code_revision(&CodeRevision::commit(revision_id, session, 100))?;
    corrupt_code_revision_frontier_bytes(&vault, &session)?;

    vault.batch().delete(&revision_id).commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &code_revision_frontier_key(&session))?
            .is_none()
    );
    Ok(())
}

#[test]
fn code_revision_delete_frontier_head_rebuilds_predecessor_frontier() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let first = entity(0x21);
    let second = entity(0x22);
    let first_revision = CodeRevision::commit(first, session, 100);
    let second_revision = CodeRevision::commit_child(second, session, first, 200);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, first, 0xA1, 20)?;
    put_artifact(&vault, second, 0xA2, 30)?;
    vault.commit_code_revision(&first_revision)?;
    vault.commit_code_revision(&second_revision)?;

    vault.batch().delete(&second).commit()?;

    assert_eq!(
        vault.code_revisions_for_session(&session)?,
        vec![first_revision]
    );
    Ok(())
}

#[test]
fn code_revision_batch_delete_session_removes_reverse_indexes() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let parent_session = entity(0x60);
    let fork_session = entity(0x12);
    let revision_id = entity(0x21);
    put_session(&vault, parent_session, 10)?;
    put_session(&vault, fork_session, 11)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;

    let revision = CodeRevision::commit(revision_id, parent_session, 100);
    let fork = CodeRevisionFork::new(fork_session, parent_session, revision_id, 150);
    vault.commit_code_revision(&revision)?;
    vault.branch_code_revision(&fork)?;
    vault.batch().delete(&parent_session).commit()?;

    assert!(
        vault
            .code_revisions_for_session(&parent_session)?
            .is_empty()
    );
    assert!(
        vault
            .code_revision_forks_from_session(&parent_session)?
            .is_empty()
    );
    assert_eq!(vault.get_code_revision(&revision_id)?, Some(revision));
    assert_eq!(vault.get_code_revision_fork(&fork_session)?, Some(fork));

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(
                &rtxn,
                &code_revision_session_index_key(&parent_session, &revision_id)
            )?
            .is_none()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(
                &rtxn,
                &code_revision_fork_parent_index_key(&parent_session, &fork_session)
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn code_revision_batch_delete_parent_removes_child_index_rows() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let parent = entity(0x21);
    let child = entity(0x22);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, parent, 0xA1, 20)?;
    put_artifact(&vault, child, 0xA2, 30)?;

    let parent_revision = CodeRevision::commit(parent, session, 100);
    let child_revision = CodeRevision::commit_child(child, session, parent, 200);
    vault.commit_code_revision(&parent_revision)?;
    vault.commit_code_revision(&child_revision)?;
    vault.batch().delete(&parent).commit()?;

    assert!(vault.get_code_revision(&parent)?.is_none());
    let err = vault
        .get_code_revision(&child)
        .expect_err("child must fail closed when its parent revision is deleted");
    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("code revision integrity parent record missing")
    );
    assert!(vault.child_code_revisions(&parent)?.is_empty());

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &code_revision_parent_index_key(&parent, &child))?
            .is_none()
    );
    Ok(())
}

#[test]
fn code_revision_finalized_artifact_rejects_body_mutation() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;

    let revision = CodeRevision::commit(revision_id, session, 100);
    vault.commit_code_revision(&revision)?;

    let err = vault
        .put_code_artifact(
            &revision_id,
            &artifact_body(0xA2),
            TimeRange { start: 30, end: 30 },
            30,
        )
        .expect_err("finalized code revision bytes must be immutable");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert_eq!(vault.get_code_revision(&revision_id)?, Some(revision));
    assert_eq!(
        vault.get_code_artifact(&revision_id)?,
        Some(artifact_body(0xA1))
    );
    Ok(())
}

#[test]
fn code_revision_finalization_rejects_header_only_artifact_shell() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    replace_entity_with_header_shell(&vault, &revision_id)?;

    let err = vault
        .commit_code_revision(&CodeRevision::commit(revision_id, session, 100))
        .expect_err("header-only CODE_ARTIFACT shells must not be finalized");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(vault.get_code_revision(&revision_id)?.is_none());
    Ok(())
}

#[test]
fn code_integrity_revision_fold_mismatch_fails_closed() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;

    let revision = CodeRevision::commit(revision_id, session, 100);
    vault.commit_code_revision(&revision)?;
    replace_code_artifact_body_unchecked(&vault, &revision_id, &artifact_body(0xA2))?;

    let err = vault
        .get_code_revision(&revision_id)
        .expect_err("artifact bytes diverging from the stored fold must fail closed");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("code revision artifact hash mismatch")
    );
    Ok(())
}

#[test]
fn code_integrity_frontier_record_mismatch_fails_closed() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let first = entity(0x21);
    let second = entity(0x22);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, first, 0xA1, 20)?;
    put_artifact(&vault, second, 0xA2, 30)?;

    vault.commit_code_revision(&CodeRevision::commit(first, session, 100))?;
    vault.commit_code_revision(&CodeRevision::commit_child(second, session, first, 200))?;
    corrupt_code_revision_frontier_fold(&vault, &session)?;

    let err = vault
        .code_revisions_for_session(&session)
        .expect_err("frontier fold tampering must fail closed");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("code revision frontier fold mismatch")
    );
    Ok(())
}

#[test]
fn code_integrity_frontier_session_mismatch_fails_closed_on_update() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let other_session = entity(0x12);
    let first = entity(0x21);
    let second = entity(0x22);
    put_session(&vault, session, 10)?;
    put_session(&vault, other_session, 11)?;
    put_artifact(&vault, first, 0xA1, 20)?;
    put_artifact(&vault, second, 0xA2, 30)?;
    vault.commit_code_revision(&CodeRevision::commit(first, session, 100))?;
    corrupt_code_revision_frontier_session(&vault, &session, other_session)?;

    let err = vault
        .commit_code_revision(&CodeRevision::commit_child(second, session, first, 200))
        .expect_err("frontier stored under a session key must decode to the same session");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("code revision frontier session mismatch")
    );
    Ok(())
}

#[test]
fn code_integrity_parent_fold_mismatch_fails_closed() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let parent = entity(0x21);
    let child = entity(0x22);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, parent, 0xA1, 20)?;
    put_artifact(&vault, child, 0xA2, 30)?;

    vault.commit_code_revision(&CodeRevision::commit(parent, session, 100))?;
    vault.commit_code_revision(&CodeRevision::commit_child(child, session, parent, 200))?;
    corrupt_code_revision_parent_fold_self_consistent(&vault, &child)?;

    let err = vault
        .get_code_revision(&child)
        .expect_err("descendant must verify the current parent fold");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("code revision parent fold mismatch")
    );
    Ok(())
}

#[test]
fn code_integrity_parent_session_mismatch_fails_closed() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let other_session = entity(0x12);
    let parent = entity(0x21);
    let child = entity(0x22);
    let foreign_parent = entity(0x23);
    put_session(&vault, session, 10)?;
    put_session(&vault, other_session, 11)?;
    put_artifact(&vault, parent, 0xA1, 20)?;
    put_artifact(&vault, child, 0xA2, 30)?;
    put_artifact(&vault, foreign_parent, 0xA3, 40)?;
    vault.commit_code_revision(&CodeRevision::commit(parent, session, 100))?;
    vault.commit_code_revision(&CodeRevision::commit_child(child, session, parent, 200))?;
    vault.commit_code_revision(&CodeRevision::commit(foreign_parent, other_session, 150))?;

    let corrupted_child = CodeRevision::commit_child(child, session, foreign_parent, 200);
    replace_code_revision_record_unchecked(&vault, &corrupted_child)?;
    let foreign_record = read_code_revision_integrity_record(&vault, &foreign_parent)?;
    let mut child_record = read_code_revision_integrity_record(&vault, &child)?;
    child_record.parent_revision_id = Some(foreign_parent);
    child_record.parent_fold = Some(foreign_record.revision_fold);
    child_record.revision_fold = compute_code_revision_fold(
        corrupted_child.kind,
        &child_record.artifact_hash,
        corrupted_child.provenance_claim_id,
        child_record.parent_fold,
        child_record.reverted_to_fold,
    );
    replace_code_revision_integrity_record_unchecked(&vault, &child_record)?;

    let err = vault
        .get_code_revision(&child)
        .expect_err("parent from a different session must fail closed on read");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("parent_revision_id must belong to session_id")
    );
    Ok(())
}

#[test]
fn code_integrity_parent_cycle_fails_closed_without_recursive_overflow() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let first = entity(0x21);
    let second = entity(0x22);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, first, 0xA1, 20)?;
    put_artifact(&vault, second, 0xA2, 30)?;
    vault.commit_code_revision(&CodeRevision::commit(first, session, 100))?;
    vault.commit_code_revision(&CodeRevision::commit_child(second, session, first, 200))?;

    let mut corrupted_first = CodeRevision::commit_child(first, session, second, 100);
    corrupted_first.provenance_claim_id = None;
    replace_code_revision_record_unchecked(&vault, &corrupted_first)?;
    let second_record = read_code_revision_integrity_record(&vault, &second)?;
    let mut first_record = read_code_revision_integrity_record(&vault, &first)?;
    first_record.parent_revision_id = Some(second);
    first_record.parent_fold = Some(second_record.revision_fold);
    first_record.revision_fold = compute_code_revision_fold(
        corrupted_first.kind,
        &first_record.artifact_hash,
        corrupted_first.provenance_claim_id,
        first_record.parent_fold,
        first_record.reverted_to_fold,
    );
    replace_code_revision_integrity_record_unchecked(&vault, &first_record)?;

    let err = vault
        .get_code_revision(&second)
        .expect_err("corrupt parent cycles must fail closed");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("code revision parent chain contains a cycle")
    );
    Ok(())
}

#[test]
fn code_integrity_revert_target_must_remain_parent_ancestor() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let other_session = entity(0x12);
    let original = entity(0x21);
    let current = entity(0x22);
    let reverted = entity(0x23);
    let unrelated = entity(0x24);
    put_session(&vault, session, 10)?;
    put_session(&vault, other_session, 11)?;
    put_artifact(&vault, original, 0xA1, 20)?;
    put_artifact(&vault, current, 0xA2, 30)?;
    put_artifact(&vault, reverted, 0xA3, 40)?;
    put_artifact(&vault, unrelated, 0xA4, 50)?;
    vault.commit_code_revision(&CodeRevision::commit(original, session, 100))?;
    vault.commit_code_revision(&CodeRevision::commit_child(current, session, original, 200))?;
    vault.commit_code_revision(&CodeRevision::commit(unrelated, other_session, 150))?;
    vault.revert_code_revision(&CodeRevision::revert(
        reverted, session, current, original, 300,
    ))?;

    let corrupted_revert = CodeRevision::revert(reverted, session, current, unrelated, 300);
    replace_code_revision_record_unchecked(&vault, &corrupted_revert)?;
    let unrelated_record = read_code_revision_integrity_record(&vault, &unrelated)?;
    let mut revert_record = read_code_revision_integrity_record(&vault, &reverted)?;
    revert_record.reverted_to_revision_id = Some(unrelated);
    revert_record.reverted_to_fold = Some(unrelated_record.revision_fold);
    revert_record.revision_fold = compute_code_revision_fold(
        corrupted_revert.kind,
        &revert_record.artifact_hash,
        corrupted_revert.provenance_claim_id,
        revert_record.parent_fold,
        revert_record.reverted_to_fold,
    );
    replace_code_revision_integrity_record_unchecked(&vault, &revert_record)?;

    let err = vault
        .get_code_revision(&reverted)
        .expect_err("revert target must remain an ancestor of the parent revision");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("reverted_to_revision_id must be an ancestor of parent_revision_id")
    );
    Ok(())
}

#[test]
fn code_integrity_provenance_claim_id_is_fold_authenticated() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    let original_provenance = entity(0x31);
    let forged_provenance = entity(0x32);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    put_claim_entity(&vault, original_provenance, revision_id, 30)?;
    put_claim_entity(&vault, forged_provenance, revision_id, 40)?;
    let revision = CodeRevision::commit(revision_id, session, 100)
        .with_provenance_claim_id(original_provenance);
    vault.commit_code_revision(&revision)?;

    let forged_revision =
        CodeRevision::commit(revision_id, session, 100).with_provenance_claim_id(forged_provenance);
    replace_code_revision_record_unchecked(&vault, &forged_revision)?;
    let mut record = read_code_revision_integrity_record(&vault, &revision_id)?;
    record.provenance_claim_id = Some(forged_provenance);
    replace_code_revision_integrity_record_unchecked(&vault, &record)?;

    let err = vault
        .get_code_revision(&revision_id)
        .expect_err("provenance tampering must alter the authenticated fold");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(err.to_string().contains("code revision fold mismatch"));
    Ok(())
}

#[test]
fn code_integrity_provenance_claim_id_type_mismatch_fails_closed() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    let provenance_claim = entity(0x31);
    let non_claim = entity(0x32);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    put_claim_entity(&vault, provenance_claim, revision_id, 30)?;
    put_session(&vault, non_claim, 40)?;
    let revision =
        CodeRevision::commit(revision_id, session, 100).with_provenance_claim_id(provenance_claim);
    vault.commit_code_revision(&revision)?;

    let corrupted_revision =
        CodeRevision::commit(revision_id, session, 100).with_provenance_claim_id(non_claim);
    replace_code_revision_record_unchecked(&vault, &corrupted_revision)?;
    let mut record = read_code_revision_integrity_record(&vault, &revision_id)?;
    record.provenance_claim_id = Some(non_claim);
    record.revision_fold = compute_code_revision_fold(
        corrupted_revision.kind,
        &record.artifact_hash,
        corrupted_revision.provenance_claim_id,
        record.parent_fold,
        record.reverted_to_fold,
    );
    replace_code_revision_integrity_record_unchecked(&vault, &record)?;

    let err = vault
        .get_code_revision(&revision_id)
        .expect_err("non-CLAIM provenance must fail closed on read");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("provenance_claim_id must be a CLAIM entity")
    );
    Ok(())
}

#[test]
fn code_integrity_empty_session_index_with_frontier_fails_closed() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;

    vault.commit_code_revision(&CodeRevision::commit(revision_id, session, 100))?;
    delete_code_revision_session_index_row(&vault, &session, &revision_id)?;

    let err = vault
        .code_revisions_for_session(&session)
        .expect_err("frontier without session index rows must fail closed");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("code revision frontier exists without session index rows")
    );
    Ok(())
}

#[test]
fn code_integrity_orphaned_frontier_rejects_write_backfill() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let parent = entity(0x21);
    let child = entity(0x22);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, parent, 0xA1, 20)?;
    put_artifact(&vault, child, 0xA2, 30)?;

    vault.commit_code_revision(&CodeRevision::commit(parent, session, 100))?;
    delete_code_revision_session_index_row(&vault, &session, &parent)?;

    let err = vault
        .commit_code_revision(&CodeRevision::commit_child(child, session, parent, 200))
        .expect_err("orphaned frontier must reject writes before indexing a child");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("code revision frontier exists without session index rows")
    );
    assert!(vault.get_code_revision(&child)?.is_none());
    assert!(
        vault
            .targets(&child, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_integrity_legacy_revision_sidecars_remain_readable_without_read_backfill() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let first = entity(0x21);
    let second = entity(0x22);
    let first_revision = CodeRevision::commit(first, session, 100);
    let second_revision = CodeRevision::commit_child(second, session, first, 200);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, first, 0xA1, 20)?;
    put_artifact(&vault, second, 0xA2, 30)?;
    vault.commit_code_revision(&first_revision)?;
    vault.commit_code_revision(&second_revision)?;
    remove_code_revision_integrity_sidecars(&vault, &[first, second], &session)?;

    assert_eq!(
        vault.code_revisions_for_session(&session)?,
        vec![first_revision, second_revision]
    );
    assert!(!code_revision_integrity_sidecars_exist(
        &vault,
        &[first, second],
        &session
    )?);
    Ok(())
}

#[test]
fn code_integrity_divergent_root_conflicts_after_frontier_exists() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let first = entity(0x21);
    let second_root = entity(0x22);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, first, 0xA1, 20)?;
    put_artifact(&vault, second_root, 0xA2, 30)?;

    vault.commit_code_revision(&CodeRevision::commit(first, session, 100))?;
    let err = vault
        .commit_code_revision(&CodeRevision::commit(second_root, session, 200))
        .expect_err("second divergent root must report a frontier conflict");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(err.to_string().contains("code revision frontier conflict"));
    assert!(vault.get_code_revision(&second_root)?.is_none());
    Ok(())
}

#[test]
fn code_integrity_independent_trace_entries_converge_or_conflict() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let root = entity(0x21);
    let first_child = entity(0x22);
    let convergent_child = entity(0x23);
    let conflicting_child = entity(0x24);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, root, 0xA1, 20)?;
    put_artifact(&vault, first_child, 0xA2, 30)?;
    put_artifact(&vault, convergent_child, 0xA2, 40)?;
    put_artifact(&vault, conflicting_child, 0xA4, 50)?;

    vault.commit_code_revision(&CodeRevision::commit(root, session, 100))?;
    vault.commit_code_revision(&CodeRevision::commit_child(first_child, session, root, 200))?;
    vault.commit_code_revision(&CodeRevision::commit_child(
        convergent_child,
        session,
        root,
        300,
    ))?;

    let err = vault
        .commit_code_revision(&CodeRevision::commit_child(
            conflicting_child,
            session,
            root,
            400,
        ))
        .expect_err("same-parent divergent trace must report a conflict");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(err.to_string().contains("code revision frontier conflict"));
    assert_eq!(
        vault.get_code_revision(&convergent_child)?,
        Some(CodeRevision::commit_child(
            convergent_child,
            session,
            root,
            300
        ))
    );
    assert!(vault.get_code_revision(&conflicting_child)?.is_none());
    Ok(())
}

#[test]
fn code_revision_revert_rejects_unrelated_restored_revision() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let original = entity(0x21);
    let current = entity(0x22);
    let unrelated = entity(0x23);
    let reverted = entity(0x24);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, original, 0xA1, 20)?;
    put_artifact(&vault, current, 0xA2, 30)?;
    put_artifact(&vault, unrelated, 0xA2, 40)?;
    put_artifact(&vault, reverted, 0xA4, 50)?;

    vault.commit_code_revision(&CodeRevision::commit(original, session, 100))?;
    vault.commit_code_revision(&CodeRevision::commit_child(current, session, original, 200))?;
    vault.commit_code_revision(&CodeRevision::commit_child(
        unrelated, session, original, 300,
    ))?;

    let err = vault
        .revert_code_revision(&CodeRevision::revert(
            reverted, session, current, unrelated, 400,
        ))
        .expect_err("revert target must be an ancestor of the current revision");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(vault.get_code_revision(&reverted)?.is_none());
    assert!(
        vault
            .targets(&reverted, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_revision_rejects_parent_revision_from_different_session() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let other_session = entity(0x12);
    let parent = entity(0x21);
    let child = entity(0x22);
    put_session(&vault, session, 10)?;
    put_session(&vault, other_session, 11)?;
    put_artifact(&vault, parent, 0xA1, 20)?;
    put_artifact(&vault, child, 0xA2, 30)?;
    vault.commit_code_revision(&CodeRevision::commit(parent, other_session, 100))?;

    let err = vault
        .commit_code_revision(&CodeRevision::commit_child(child, session, parent, 200))
        .expect_err("parent revision must belong to the new revision session");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("parent_revision_id must belong to session_id")
    );
    assert!(vault.get_code_revision(&child)?.is_none());
    assert!(
        vault
            .targets(&child, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_revision_rejects_restored_revision_from_different_session() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let other_session = entity(0x12);
    let original = entity(0x21);
    let current = entity(0x22);
    let restored = entity(0x23);
    let reverted = entity(0x24);
    put_session(&vault, session, 10)?;
    put_session(&vault, other_session, 11)?;
    put_artifact(&vault, original, 0xA1, 20)?;
    put_artifact(&vault, current, 0xA2, 30)?;
    put_artifact(&vault, restored, 0xA3, 40)?;
    put_artifact(&vault, reverted, 0xA4, 50)?;
    vault.commit_code_revision(&CodeRevision::commit(original, session, 100))?;
    vault.commit_code_revision(&CodeRevision::commit_child(current, session, original, 200))?;
    vault.commit_code_revision(&CodeRevision::commit(restored, other_session, 300))?;

    let err = vault
        .revert_code_revision(&CodeRevision::revert(
            reverted, session, current, restored, 400,
        ))
        .expect_err("restored revision must belong to the new revision session");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("reverted_to_revision_id must belong to session_id")
    );
    assert!(vault.get_code_revision(&reverted)?.is_none());
    assert!(
        vault
            .targets(&reverted, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_revision_requires_claim_typed_provenance() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let first = entity(0x21);
    let second = entity(0x22);
    let provenance_claim = entity(0x31);
    let non_claim = entity(0x32);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, first, 0xA1, 20)?;
    put_artifact(&vault, second, 0xA2, 30)?;
    put_claim_entity(&vault, provenance_claim, first, 40)?;
    put_session(&vault, non_claim, 50)?;

    let first_revision =
        CodeRevision::commit(first, session, 100).with_provenance_claim_id(provenance_claim);
    vault.commit_code_revision(&first_revision)?;

    let err = vault
        .commit_code_revision(
            &CodeRevision::commit_child(second, session, first, 200)
                .with_provenance_claim_id(non_claim),
        )
        .expect_err("provenance_claim_id must point at a CLAIM entity");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(vault.get_code_revision(&second)?.is_none());
    Ok(())
}

#[test]
fn code_integrity_generated_apply_cannot_supersede_user_stated_revision_truth() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    let user_truth = entity(0x31);
    let generated_apply = entity(0x32);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    vault.commit_code_revision(&CodeRevision::commit(revision_id, session, 100))?;
    put_claim_entity_with_source(
        &vault,
        user_truth,
        revision_id,
        Some(ClaimSource::UserStated),
        200,
    )?;
    put_claim_entity_with_source_and_approval(
        &vault,
        generated_apply,
        revision_id,
        Some(ClaimSource::Generated),
        ClaimApprovalStatus::Proposed,
        300,
    )?;

    let err = vault
        .supersede_claim(&generated_apply, &user_truth, 400)
        .expect_err("generated apply must not supersede user-stated revision truth");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("generated code revision claim cannot supersede user-stated truth")
    );
    assert_eq!(
        vault.get_claim(&user_truth)?.expect("user claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&generated_apply, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_integrity_generated_non_code_claim_reports_user_stated_code_revision_truth() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let revision_id = entity(0x21);
    let user_truth = entity(0x31);
    let generated_non_code = entity(0x33);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    vault.commit_code_revision(&CodeRevision::commit(revision_id, session, 100))?;
    put_claim_entity_with_source(
        &vault,
        user_truth,
        revision_id,
        Some(ClaimSource::UserStated),
        200,
    )?;

    let mut generated_body = ClaimBody::new(
        "profile.lives_in",
        ClaimSubject::Entity(revision_id),
        Value::from("tokyo"),
        0.9,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    generated_body.source = Some(ClaimSource::Generated);
    let data = encode_claim_body(&generated_body)?;
    put_claim_entity_unchecked(&vault, generated_non_code, 300, &data)?;

    let err = vault
        .supersede_claim(&generated_non_code, &user_truth, 400)
        .expect_err("generated non-code claim must not supersede user-stated revision truth");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    let message = err.to_string();
    assert!(
        message.contains("generated claim cannot supersede user-stated code revision truth"),
        "{message}"
    );
    assert!(
        !message.contains("generated code revision claim cannot supersede user-stated truth"),
        "{message}"
    );
    assert_eq!(
        vault.get_claim(&user_truth)?.expect("user claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&generated_non_code, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_integrity_generated_apply_cannot_supersede_user_truth_across_revisions() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let first_revision = entity(0x21);
    let second_revision = entity(0x22);
    let user_truth = entity(0x31);
    let generated_apply = entity(0x32);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, first_revision, 0xA1, 20)?;
    put_artifact(&vault, second_revision, 0xA2, 30)?;
    vault.commit_code_revision(&CodeRevision::commit(first_revision, session, 100))?;
    vault.commit_code_revision(&CodeRevision::commit_child(
        second_revision,
        session,
        first_revision,
        200,
    ))?;
    put_claim_entity_with_source(
        &vault,
        user_truth,
        first_revision,
        Some(ClaimSource::UserStated),
        300,
    )?;
    put_claim_entity_with_source_and_approval(
        &vault,
        generated_apply,
        second_revision,
        Some(ClaimSource::Generated),
        ClaimApprovalStatus::Proposed,
        400,
    )?;

    let err = vault
        .supersede_claim(&generated_apply, &user_truth, 500)
        .expect_err("generated apply must not supersede user truth for another revision");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(
        err.to_string()
            .contains("generated code revision claim cannot supersede user-stated truth")
    );
    assert_eq!(
        vault.get_claim(&user_truth)?.expect("user claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&generated_apply, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_integrity_generated_apply_with_missing_subject_cannot_supersede_user_truth() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let revision_id = entity(0x21);
    let user_truth = entity(0x31);
    let generated_apply = entity(0x32);
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    put_claim_entity_with_source(
        &vault,
        user_truth,
        revision_id,
        Some(ClaimSource::UserStated),
        200,
    )?;
    put_claim_entity_with_source_and_approval(
        &vault,
        generated_apply,
        revision_id,
        Some(ClaimSource::Generated),
        ClaimApprovalStatus::Proposed,
        300,
    )?;
    vault.batch().delete(&revision_id).commit()?;

    let err = vault
        .supersede_claim(&generated_apply, &user_truth, 400)
        .expect_err("generated apply must not supersede user-stated truth");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert_eq!(
        vault.get_claim(&user_truth)?.expect("user claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&generated_apply, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_integrity_generated_apply_with_header_only_subject_cannot_supersede_user_truth()
-> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let revision_id = entity(0x21);
    let user_truth = entity(0x31);
    let generated_apply = entity(0x32);
    put_artifact(&vault, revision_id, 0xA1, 20)?;
    put_claim_entity_with_source(
        &vault,
        user_truth,
        revision_id,
        Some(ClaimSource::UserStated),
        200,
    )?;
    put_claim_entity_with_source_and_approval(
        &vault,
        generated_apply,
        revision_id,
        Some(ClaimSource::Generated),
        ClaimApprovalStatus::Proposed,
        300,
    )?;
    replace_entity_with_header_shell(&vault, &revision_id)?;

    let err = vault
        .supersede_claim(&generated_apply, &user_truth, 400)
        .expect_err("generated apply must not supersede user-stated truth");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert_eq!(
        vault.get_claim(&user_truth)?.expect("user claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&generated_apply, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn code_revision_rejects_unfinalized_parent_without_writing() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = entity(0x60);
    let parent = entity(0x21);
    let child = entity(0x22);
    put_session(&vault, session, 10)?;
    put_artifact(&vault, parent, 0xA1, 20)?;
    put_artifact(&vault, child, 0xA2, 30)?;

    let err = vault
        .commit_code_revision(&CodeRevision::commit_child(child, session, parent, 200))
        .expect_err("unfinalized parent revision must fail closed");

    assert_eq!(err.kind(), ErrorKind::InvalidCodeArtifactBody);
    assert!(vault.get_code_revision(&child)?.is_none());
    assert!(
        vault
            .targets(&child, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}
