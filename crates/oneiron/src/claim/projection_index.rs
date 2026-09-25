//! Rebuildable claim projections maintained at the shared put chokepoint.
use super::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::store::Store;
use crate::{EntityId, Error, Result};

fn predicate_prefix(predicate: &str) -> Vec<u8> {
    [
        b"claim:predicate:v1:".as_slice(),
        blake3::hash(predicate.as_bytes()).as_bytes(),
    ]
    .concat()
}
fn predicate_name_key(predicate: &str) -> Vec<u8> {
    [b"claim:predicate_name:v1:".as_slice(), predicate.as_bytes()].concat()
}
fn producer_prefix(producer: EntityId) -> Vec<u8> {
    [
        b"claim:pending_producer:v1:".as_slice(),
        producer.as_bytes(),
    ]
    .concat()
}
fn keys(id: EntityId, body: &ClaimBody) -> Vec<Vec<u8>> {
    let mut prefixes = vec![predicate_prefix(&body.predicate)];
    if body.approval == ClaimApprovalStatus::Proposed
        && body.lifecycle == ClaimLifecycleStatus::Active
        && body.source == Some(ClaimSource::Generated)
        && let Some(producer) = super::session_claim_producer(body)
    {
        prefixes.push(producer_prefix(producer));
    }
    prefixes
        .into_iter()
        .map(|mut prefix| {
            prefix.extend_from_slice(id.as_bytes());
            prefix
        })
        .collect()
}
fn reverse_key(id: EntityId) -> Vec<u8> {
    [b"claim:projection_reverse:v1:".as_slice(), id.as_bytes()].concat()
}
pub(crate) fn remove_claim_projection_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let reverse = reverse_key(id);
    let Some(raw) = store.vault_meta.get(txn, &reverse)? else {
        return Ok(());
    };
    let keys: Vec<Vec<u8>> = rmp_serde::from_slice(&raw)
        .map_err(|_| Error::CorruptedIndex("claim projection reverse index"))?;
    for key in keys {
        if !(key.starts_with(b"claim:predicate:v1:")
            || key.starts_with(b"claim:pending_producer:v1:"))
            || !key.ends_with(id.as_bytes())
        {
            return Err(Error::CorruptedIndex("claim projection reverse key"));
        }
        let predicate = if key.starts_with(b"claim:predicate:v1:") {
            Some(
                store
                    .vault_meta
                    .get(txn, &key)?
                    .ok_or(Error::CorruptedIndex("claim predicate index value"))?
                    .to_vec(),
            )
        } else {
            None
        };
        store.vault_meta.delete(txn, &key)?;
        if let Some(predicate) = predicate {
            let predicate = std::str::from_utf8(&predicate)
                .map_err(|_| Error::CorruptedIndex("claim predicate name"))?;
            let prefix = predicate_prefix(predicate);
            let any = store
                .vault_meta
                .prefix_iter(txn, &prefix)?
                .next()
                .transpose()?
                .is_some();
            if !any {
                store
                    .vault_meta
                    .delete(txn, &predicate_name_key(predicate))?;
            }
        }
    }
    store.vault_meta.delete(txn, &reverse)?;
    Ok(())
}
pub(crate) fn maintain_claim_projection_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
) -> Result<()> {
    remove_claim_projection_index(store, txn, id)?;
    let keys = keys(id, body);
    for key in &keys {
        let value = if key.starts_with(b"claim:predicate:v1:") {
            body.predicate.as_bytes()
        } else {
            b""
        };
        store.vault_meta.put(txn, key, value)?;
    }
    store
        .vault_meta
        .put(txn, &predicate_name_key(&body.predicate), b"")?;
    let encoded =
        rmp_serde::to_vec(&keys).map_err(|_| Error::CorruptedIndex("claim projection encoding"))?;
    store.vault_meta.put(txn, &reverse_key(id), &encoded)?;
    Ok(())
}
fn ids(store: &Store, txn: &heed::RoTxn<'_>, prefix: &[u8]) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, prefix)? {
        let (key, _) = row?;
        ids.push(EntityId::from_bytes(
            key[prefix.len()..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("claim projection index"))?,
        )?);
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
    ids(store, txn, &predicate_prefix(predicate))
}
pub(crate) fn pending_claim_ids_for_producer_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    producer: EntityId,
) -> Result<Vec<EntityId>> {
    ids(store, txn, &producer_prefix(producer))
}

/// Classify distinct stored predicates under live policy before reading any
/// claim bodies. The catalog and its posting lists co-commit with claim writes.
pub(super) fn pinned_claim_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
) -> Result<Vec<EntityId>> {
    let prefix = b"claim:predicate_name:v1:";
    let mut candidates = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, prefix)? {
        let (key, _) = row?;
        let predicate = std::str::from_utf8(&key[prefix.len()..])
            .map_err(|_| Error::CorruptedIndex("claim predicate catalog"))?;
        if policy.pins_predicate(predicate) {
            candidates.extend(claim_ids_for_predicate_in_txn(store, txn, predicate)?);
            if candidates.len() > 10_000 {
                return Err(Error::IndexOverflow("pinned claim projection"));
            }
        }
    }
    Ok(candidates)
}

#[cfg(test)]
mod tests;
