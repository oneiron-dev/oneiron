//! Doors for `tests/digest_erase_scrubs_stored_copies.rs` (PROACTIVITY-DIGEST-COPY-ERASURE).

use crate::dreamer_runner::maintenance::digest::{
    claim_digests_indexed_for_test, forget_claim_digest_index_for_test,
};

/// Clears the digest memberships and backfill marker without changing the digest rows.
///
/// # Errors
/// Returns a transaction, scan, or delete error.
pub fn forget_claim_digest_index(vault: &crate::Vault) -> crate::Result<()> {
    vault.with_write_txn_grouped(|txn| forget_claim_digest_index_for_test(&vault.store, txn))
}

/// Reads whether the digest membership backfill is marked complete.
///
/// # Errors
/// Returns a transaction or marker read error.
pub fn claim_digests_indexed(vault: &crate::Vault) -> crate::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    claim_digests_indexed_for_test(&vault.store, &txn)
}

/// Lands the Dreamer's Proposed CLAIM `predicate` about `subject` holding
/// `value` and citing `evidence`: Active, Proposed, Generated and signed by
/// the Dreamer, as `test_doors::curator_finding::land_stale_consolidation`
/// lands an Auto one, so the owner's next digest carries it. Unlike the
/// curator finding, its value may be a map, which a value-field redaction
/// reaches. Returns its id.
///
/// # Errors
/// The vault's, and the write door's.
pub fn land_dreamer_proposal(
    vault: &crate::Vault,
    subject: crate::EntityId,
    predicate: &str,
    value: rmpv::Value,
    evidence: crate::EntityId,
) -> crate::Result<crate::EntityId> {
    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::write_envelope::{WriteEnvelope, WriteProvenance};
    use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange};
    use rmpv::Value;

    let dreamer = vault.dreamer_authority()?;
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    let candidate = ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, 1.0)
        .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
            &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
                refs: vec![evidence],
                chain: Vec::new(),
                source_meet: ClaimSource::Generated,
            },
        ));
    vault.with_write_txn_grouped(|txn| {
        let mut envelope = WriteEnvelope::new(
            dreamer,
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![(
                Value::from("surface"),
                Value::from("test.dreamer_proposal"),
            )]))?,
            ClaimApprovalStatus::Proposed,
        );
        vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
        vault
            .batch_in()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(id)
}

/// Writes a pending Dreamer proposal with the given value through the signed claim door.
///
/// # Errors
/// Returns a claim, authorization, or storage error.
pub fn put_digest_proposal(vault: &crate::Vault, value: &str) -> crate::Result<crate::EntityId> {
    put_digest_proposal_with_predicate(vault, "dreamer.proactivity.follow_up", value)
}

/// Writes a pending Dreamer proposal with the given predicate and value.
///
/// # Errors
/// Returns a claim, authorization, or storage error.
pub fn put_digest_proposal_with_predicate(
    vault: &crate::Vault,
    predicate: &str,
    value: &str,
) -> crate::Result<crate::EntityId> {
    use crate::{
        ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EntityId, TimeRange,
        WriteEnvelope, WriteProvenance,
    };
    use rmpv::Value;

    let actor = vault.dreamer_authority()?;
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    let candidate = ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(actor.entity_ref()),
        Value::from(value),
        0.7,
    );
    let mut envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("surface"),
            Value::from("dreamer"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    );
    vault.with_write_txn_grouped(|txn| {
        vault.sign_retained_machine_claim_in_txn(txn, &id, &candidate, &mut envelope)?;
        vault
            .batch_in()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(id)
}

/// Reads the exact stored digest bytes under a valid locator.
///
/// # Errors
/// Returns a transaction or storage error, or `EntityNotFound` if the digest is absent.
pub fn stored_digest_bytes(vault: &crate::Vault, locator: [u8; 32]) -> crate::Result<Vec<u8>> {
    use crate::side_table::SideTableDbs;

    let txn = vault.store.env.read_txn()?;
    vault
        .store
        .side_vault_meta()
        .get(&txn, &digest_storage_key(locator))?
        .map(std::borrow::Cow::into_owned)
        .ok_or(crate::Error::EntityNotFound)
}

fn digest_storage_key(locator: [u8; 32]) -> Vec<u8> {
    let mut key = crate::side_table::DREAMER_PROACTIVITY_DIGEST
        .prefix
        .to_vec();
    key.extend_from_slice(&locator);
    key
}

/// Finds the active custody id for a handle lifted from this digest, not another row.
///
/// # Errors
/// Returns an origin, authorization, or storage error.
pub fn digest_custody_id(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    locator: [u8; 32],
    handle: &str,
) -> crate::Result<Option<crate::EntityId>> {
    let place = format!(
        "side:{}",
        crate::side_table::DREAMER_PROACTIVITY_DIGEST.name
    );
    let origin = crate::batch::secret_scan::side_row_origin(&place, &digest_storage_key(locator))?;
    let found = vault.found_keys(owner, false, 100)?;
    let Some(key) = found
        .into_iter()
        .find(|notice| notice.record == origin)
        .and_then(|notice| {
            notice
                .keys
                .into_iter()
                .find(|key| key.handle == handle && key.place == place)
        })
    else {
        return Ok(None);
    };
    vault.resolve_secret_ref(&key.name)
}

/// Checks for any non-revoked custody minted from the digest at this locator.
///
/// # Errors
/// Returns an origin, authorization, or storage error.
pub fn digest_has_live_custody(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    locator: [u8; 32],
) -> crate::Result<bool> {
    let place = format!(
        "side:{}",
        crate::side_table::DREAMER_PROACTIVITY_DIGEST.name
    );
    let origin = crate::batch::secret_scan::side_row_origin(&place, &digest_storage_key(locator))?;
    let notices = vault.found_keys(owner, false, usize::MAX)?;
    if let Some(notice) = notices.into_iter().find(|notice| notice.record == origin) {
        for key in notice.keys.into_iter().filter(|key| key.place == place) {
            if let Some(id) = vault.resolve_secret_ref(&key.name)?
                && vault.get_secret_metadata(&id)?.is_some_and(|metadata| {
                    metadata.status != crate::secret_custody::SecretCustodyStatus::Revoked
                })
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Copies the stored digest verbatim to a damaged key missing the locator's last byte.
///
/// # Errors
/// Returns a transaction or storage error, or `EntityNotFound` if the digest is absent.
pub fn copy_digest_under_malformed_key(
    vault: &crate::Vault,
    locator: [u8; 32],
) -> crate::Result<()> {
    use crate::side_table::SideTableDbs;

    let (key, malformed) = digest_storage_keys(locator);
    vault.with_write_txn_grouped(|txn| {
        let db = vault.store.side_vault_meta();
        let bytes = db
            .get(txn, &key)?
            .ok_or(crate::Error::EntityNotFound)?
            .into_owned();
        db.put(txn, &malformed, &bytes)
    })
}

/// Reads the exact damaged row without decoding its key or value.
///
/// # Errors
/// Returns a transaction or storage error.
pub fn malformed_digest_bytes(
    vault: &crate::Vault,
    locator: [u8; 32],
) -> crate::Result<Option<Vec<u8>>> {
    use crate::side_table::SideTableDbs;

    let (_, key) = digest_storage_keys(locator);
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .side_vault_meta()
        .get(&txn, &key)?
        .map(std::borrow::Cow::into_owned))
}

fn digest_storage_keys(locator: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let key = digest_storage_key(locator);
    let malformed = key[..key.len() - 1].to_vec();
    (key, malformed)
}
