//! Host-derived phonetic codes publish with the same indexed text frontier.
use super::RevisionRef;
use super::storage::{key, state};
use crate::store::{ManifestDbs, Store};
use crate::{EntityId, Error, Result};
const PENDING: &[u8] = b"entity_revision:phonetic:";
#[derive(serde::Serialize, serde::Deserialize)]
struct Pending {
    revision: RevisionRef,
    codes: Vec<String>,
}

pub(crate) fn defer_phonetic(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    codes: &[String],
) -> Result<bool> {
    let Some(current) = state(store, txn, id)? else {
        return Ok(false);
    };
    if current.live == current.indexed {
        return Ok(false);
    }
    if codes
        .iter()
        .any(|code| code.is_empty() || code.as_bytes().contains(&0))
    {
        return Err(Error::InvalidKey);
    }
    let key = key(PENDING, id);
    let mut pending = store
        .vault_meta
        .get(txn, &key)?
        .map(|bytes| {
            rmp_serde::from_slice::<Pending>(&bytes)
                .map_err(|_| Error::CorruptedIndex("pending phonetic"))
        })
        .transpose()?
        .filter(|pending| pending.revision == current.live)
        .unwrap_or(Pending {
            revision: current.live,
            codes: Vec::new(),
        });
    pending.codes.extend_from_slice(codes);
    pending.codes.sort();
    pending.codes.dedup();
    let bytes = rmp_serde::to_vec_named(&pending)
        .map_err(|_| Error::InvariantViolation("pending phonetic codec"))?;
    store.vault_meta.put(txn, &key, &bytes)?;
    Ok(true)
}
pub(super) fn take_phonetic(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<Vec<String>> {
    let key = key(PENDING, id);
    let pending = store
        .vault_meta
        .get(txn, &key)?
        .map(|bytes| {
            rmp_serde::from_slice::<Pending>(&bytes)
                .map_err(|_| Error::CorruptedIndex("pending phonetic"))
        })
        .transpose()?;
    store.vault_meta.delete(txn, &key)?;
    Ok(pending
        .filter(|pending| pending.revision == revision)
        .map(|pending| pending.codes)
        .unwrap_or_default())
}
pub(super) fn clear_phonetic(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store.vault_meta().delete(txn, &key(PENDING, id))?;
    Ok(())
}
