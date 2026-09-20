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
        store.vault_meta.delete(txn, &key)?;
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
        store.vault_meta.put(txn, key, b"")?;
    }
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

#[cfg(test)]
mod tests;
