//! Shared helpers for the batch white-box tests.

use super::*;

pub(super) fn open_raw_test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), embedding_test_config()).expect("open vault");
    (dir, vault)
}

pub(super) fn open_test_vault() -> (tempfile::TempDir, Vault) {
    let (tmp, vault) = open_raw_test_vault();
    clear_default_policy_manifest_for_test(&vault);
    (tmp, vault)
}

pub(super) fn clear_default_policy_manifest_for_test(vault: &Vault) {
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    vault
        .with_write_txn(|wtxn| {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
            Ok(())
        })
        .expect("clear default policy manifest");
}

pub(super) fn test_time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

pub(super) fn has_pending_embedding_marker(vault: &Vault, id: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault.store.pending_embedding_token(&rtxn, id)?.is_some())
}

pub(super) fn raw_pending_embedding_marker(
    vault: &Vault,
    id: &EntityId,
) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = Store::pending_embedding_marker_key(id);
    Ok(vault
        .store
        .sync_state
        .get(&rtxn, key.as_str())?
        .map(|value| value.to_vec()))
}

pub(super) fn overwrite_pending_embedding_marker(
    vault: &Vault,
    id: &EntityId,
    token: &[u8],
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let key = Store::pending_embedding_marker_key(id);
    vault.store.sync_state.put(&mut wtxn, key.as_str(), token)?;
    wtxn.commit()?;
    Ok(())
}

pub(super) fn pending_embedding_token(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .pending_embedding_token(&rtxn, id)?
        .ok_or(Error::InvariantViolation("pending embedding token missing"))
}

pub(super) fn seed_raw_claim_record(vault: &Vault, id: &EntityId, body: ClaimBody) -> Result<()> {
    let data = crate::claim::encode_claim_body(&body)?;
    let occurred = test_time_range(30, 30);
    let learned_at = 31_u64;
    let payload = crate::test_util::entity_record(ENTITY_TYPE_CLAIM, occurred, learned_at, &data);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)?;
    let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, id);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    vault
        .store
        .temporal_occurred_start
        .put(&mut wtxn, &occurred_start_key, &[])?;
    let learned_key = Store::encode_temporal_key(learned_at, id);
    vault
        .store
        .temporal_learned
        .put(&mut wtxn, &learned_key, &[])?;
    wtxn.commit()?;
    Ok(())
}

pub(super) fn test_write_envelope(actor: EntityId) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fixture"))?,
        ClaimApprovalStatus::Approved,
    ))
}

pub(super) fn claim_candidate_fixture(
    vault: &Vault,
    value: &str,
) -> Result<(WriteEnvelope, ClaimCandidate)> {
    let actor = EntityId::now();
    let subject = EntityId::now();
    let occurred = test_time_range(1, 1);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 1, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred, 1, b"subject")?;

    let envelope = test_write_envelope(actor)?;
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
    );
    Ok((envelope, candidate))
}

pub(super) fn commit_claim_candidate_with_value(
    vault: &Vault,
    claim: EntityId,
    value: &str,
) -> Result<()> {
    let (envelope, candidate) = claim_candidate_fixture(vault, value)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()
}

pub(super) fn commit_claim_candidate_fixture(vault: &Vault, claim: EntityId) -> Result<()> {
    commit_claim_candidate_with_value(vault, claim, "Alice")
}
