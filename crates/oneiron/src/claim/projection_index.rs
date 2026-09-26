//! Rebuildable claim projections maintained at the shared put chokepoint.
use super::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::side_table::{self, LegacyCompact, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Error, Result};

/// Posting-list row of one claim under its predicate's projection index.
/// Key: bytes32 (blake3 of predicate) + id16.
const PREDICATE_INDEX: SideTable<([u8; 32], EntityId), String, Raw> =
    SideTable::new(&side_table::CLAIM_PREDICATE_INDEX);

/// Posting-list row of one pending session-generated claim under its producing actor.
/// Key: id16 (producer) + id16.
const PENDING_PRODUCER: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::CLAIM_PENDING_PRODUCER);

/// Catalog marker recording that at least one claim uses this predicate. Key: string.
const PREDICATE_NAME: SideTable<String, (), Raw> =
    SideTable::new(&side_table::CLAIM_PREDICATE_NAME);

/// Reverse index: the projection-index keys written for one claim, so they can be removed
/// together. Key: id16.
const PROJECTION_REVERSE: SideTable<EntityId, Vec<Vec<u8>>, LegacyCompact> =
    SideTable::new(&side_table::CLAIM_PROJECTION_REVERSE);

fn predicate_hash(predicate: &str) -> [u8; 32] {
    *blake3::hash(predicate.as_bytes()).as_bytes()
}

pub(crate) fn remove_claim_projection_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let Some(keys) = PROJECTION_REVERSE.get(store, txn, &id)? else {
        return Ok(());
    };
    for key in keys {
        let orphan_check = if let Some(tail) = key.strip_prefix(PREDICATE_INDEX.decl().prefix) {
            let (hash, tail_id) = tail
                .split_at_checked(32)
                .ok_or(Error::CorruptedIndex("claim projection reverse key"))?;
            let hash: [u8; 32] = hash
                .try_into()
                .map_err(|_| Error::CorruptedIndex("claim projection reverse key"))?;
            let tail_id = EntityId::from_bytes(
                tail_id
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("claim projection reverse key"))?,
            )?;
            if tail_id != id {
                return Err(Error::CorruptedIndex("claim projection reverse key"));
            }
            let predicate = PREDICATE_INDEX
                .get(store, txn, &(hash, tail_id))?
                .ok_or(Error::CorruptedIndex("claim predicate index value"))?;
            PREDICATE_INDEX.delete(store, txn, &(hash, tail_id))?;
            Some((hash, predicate))
        } else if let Some(tail) = key.strip_prefix(PENDING_PRODUCER.decl().prefix) {
            let (producer, tail_id) = tail
                .split_at_checked(16)
                .ok_or(Error::CorruptedIndex("claim projection reverse key"))?;
            let producer = EntityId::from_bytes(
                producer
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("claim projection reverse key"))?,
            )?;
            let tail_id = EntityId::from_bytes(
                tail_id
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("claim projection reverse key"))?,
            )?;
            if tail_id != id {
                return Err(Error::CorruptedIndex("claim projection reverse key"));
            }
            PENDING_PRODUCER.delete(store, txn, &(producer, tail_id))?;
            None
        } else {
            return Err(Error::CorruptedIndex("claim projection reverse key"));
        };
        if let Some((hash, predicate)) = orphan_check {
            let any = PREDICATE_INDEX
                .iter_from(store, txn, &hash)?
                .next()
                .transpose()?
                .is_some();
            if !any {
                PREDICATE_NAME.delete(store, txn, &predicate)?;
            }
        }
    }
    PROJECTION_REVERSE.delete(store, txn, &id)?;
    Ok(())
}
pub(crate) fn maintain_claim_projection_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
) -> Result<()> {
    remove_claim_projection_index(store, txn, id)?;
    let hash = predicate_hash(&body.predicate);
    let mut reverse_keys = vec![PREDICATE_INDEX.key_bytes(&(hash, id))];
    PREDICATE_INDEX.put(store, txn, &(hash, id), &body.predicate)?;
    if body.approval == ClaimApprovalStatus::Proposed
        && body.lifecycle == ClaimLifecycleStatus::Active
        && body.source == Some(ClaimSource::Generated)
        && let Some(producer) = super::session_claim_producer(body)
    {
        reverse_keys.push(PENDING_PRODUCER.key_bytes(&(producer, id)));
        PENDING_PRODUCER.put(store, txn, &(producer, id), &())?;
    }
    PREDICATE_NAME.put(store, txn, &body.predicate, &())?;
    PROJECTION_REVERSE.put(store, txn, &id, &reverse_keys)?;
    Ok(())
}
fn predicate_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    hash: [u8; 32],
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for row in PREDICATE_INDEX.iter_from(store, txn, &hash)? {
        let (key, _) = row?;
        ids.push(key.1);
        if ids.len() > 10_000 {
            return Err(Error::IndexOverflow("claim projection query"));
        }
    }
    Ok(ids)
}
fn producer_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    producer: EntityId,
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for row in PENDING_PRODUCER.iter_from(store, txn, producer.as_bytes())? {
        let (key, _) = row?;
        ids.push(key.1);
        if ids.len() > 10_000 {
            return Err(Error::IndexOverflow("claim projection query"));
        }
    }
    Ok(ids)
}
pub(crate) fn claim_ids_for_predicate_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    predicate: &str,
) -> Result<Vec<EntityId>> {
    predicate_ids_in_txn(store, txn, predicate_hash(predicate))
}
pub(crate) fn pending_claim_ids_for_producer_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    producer: EntityId,
) -> Result<Vec<EntityId>> {
    producer_ids_in_txn(store, txn, producer)
}

/// Classify distinct stored predicates under live policy before reading any
/// claim bodies. The catalog and its posting lists co-commit with claim writes.
pub(super) fn pinned_claim_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
) -> Result<Vec<EntityId>> {
    let mut candidates = Vec::new();
    for predicate in PREDICATE_NAME.scan_keys(store, txn, &[])? {
        if policy.pins_predicate(&predicate) {
            candidates.extend(claim_ids_for_predicate_in_txn(store, txn, &predicate)?);
            if candidates.len() > 10_000 {
                return Err(Error::IndexOverflow("pinned claim projection"));
            }
        }
    }
    Ok(candidates)
}

#[cfg(test)]
mod tests;
