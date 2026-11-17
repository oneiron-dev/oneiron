//! Supplied and generated name codes publish with the indexed text frontier.
use super::RevisionRef;
use super::storage::state;
use crate::side_table::{self, Named, SideTable};
use crate::store::ManifestDbs;
use crate::{EntityId, Error, Result};
pub(super) mod checkpoint;
const PENDING: SideTable<EntityId, Pending, Named> =
    SideTable::new(&side_table::ENTITY_REVISION_PENDING_PHONETIC);
#[derive(serde::Serialize, serde::Deserialize)]
struct Pending {
    revision: RevisionRef,
    codes: Vec<String>,
}

/// Puts staged phonetic codes for the checkpoint-pins door: `id`'s codes
/// for `revision`, sorted as `defer_phonetic` keeps them.
#[cfg(oneiron_test_support)]
pub(crate) fn put_pins_pending_phonetic_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    revision: [u8; 16],
    codes: Vec<String>,
) -> Result<()> {
    let mut sorted = codes;
    sorted.sort();
    sorted.dedup();
    PENDING.put(
        store,
        txn,
        id,
        &Pending {
            revision: RevisionRef(revision),
            codes: sorted,
        },
    )
}

/// Births publish immediately. Edits are generated from the exact body that
/// the idle indexer later publishes, not from the live name ahead of it.
pub(crate) fn index_name_phonetic(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<()> {
    if state(store, txn, id)?.is_some_and(|current| current.live != current.indexed) {
        return Ok(());
    }
    let codes = crate::batch::phonetic_codes::codes_for_body(entity_type, body);
    if !codes.is_empty() {
        crate::batch::apply_phonetic(store, txn, *id, &codes)?;
    }
    Ok(())
}

pub(crate) fn defer_phonetic(
    store: &impl ManifestDbs,
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
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
    entity_type: u8,
    body: &[u8],
) -> Result<Vec<String>> {
    let pending = PENDING.get(store, txn, id)?;
    PENDING.delete(store, txn, id)?;
    let mut codes = crate::batch::phonetic_codes::codes_for_body(entity_type, body);
    if let Some(pending) = pending.filter(|pending| pending.revision == revision) {
        codes.extend(pending.codes);
    }
    codes.sort();
    codes.dedup();
    Ok(codes)
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
