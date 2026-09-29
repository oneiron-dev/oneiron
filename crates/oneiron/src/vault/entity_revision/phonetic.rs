//! Host-derived phonetic codes publish with the same indexed text frontier.
use super::RevisionRef;
use super::storage::state;
use crate::side_table::{self, Named, SideTable};
use crate::store::{ManifestDbs, Store};
use crate::{EntityId, Error, Result};
const PENDING: SideTable<EntityId, Pending, Named> =
    SideTable::new(&side_table::ENTITY_REVISION_PENDING_PHONETIC);
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
    let mut pending = PENDING
        .get(store, txn, id)?
        .filter(|pending| pending.revision == current.live)
        .unwrap_or(Pending {
            revision: current.live,
            codes: Vec::new(),
        });
    pending.codes.extend_from_slice(codes);
    pending.codes.sort();
    pending.codes.dedup();
    PENDING.put(store, txn, id, &pending)?;
    Ok(true)
}
pub(super) fn take_phonetic(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<Vec<String>> {
    let pending = PENDING.get(store, txn, id)?;
    PENDING.delete(store, txn, id)?;
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
    PENDING.delete(store, txn, id)?;
    Ok(())
}

/// Keeps staged work attached when only record metadata changes.
pub(super) fn retarget_revision(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    prior: RevisionRef,
    next: RevisionRef,
) -> Result<()> {
    let Some(mut pending) = PENDING.get(store, txn, id)? else {
        return Ok(());
    };
    if pending.revision == prior {
        pending.revision = next;
        PENDING.put(store, txn, id, &pending)?;
    }
    Ok(())
}
