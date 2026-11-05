//! Core half of `batch::phonetic_apply`: its store-layer items live in `oneiron_store::batch::phonetic_apply` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::phonetic_apply::*;

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result, StoreError};
use crate::side_table::{self, Named, SideTable};
use crate::store::ManifestDbs;
use heed::RwTxn;
use std::collections::HashSet;
use std::str;

pub(crate) mod checkpoint;

/// Published supplied and generated phonetic codes retained for delete/reindex
/// reconciliation. Key: id16.
const PHONETIC_SOURCE: SideTable<EntityId, Vec<String>, Named> =
    SideTable::new(&side_table::BATCH_PHONETIC_INDEX_SOURCE);

/// Stages one entity's phonetic postings and its forward code row.
///
/// Pure-accessor body, so ONE-1728 K11 parameterizes it by write target by
/// signature alone: a session witness stages the identical postings into the
/// overlay and the base path is byte-identical because it is the same code.
pub(crate) fn apply_phonetic(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    codes: &[String],
) -> Result<()> {
    let mut forward_codes = match store.phonetic_forward().get(wtxn, id.as_bytes())? {
        Some(raw) => match decode_phonetic_forward_codes(&raw) {
            Ok(codes) => codes,
            Err(Error::CorruptedIndex(_)) => Vec::new(),
            Err(err) => return Err(err),
        },
        None => Vec::new(),
    };
    let mut forward_changed = false;

    let mut seen_codes = HashSet::new();
    for code in codes {
        validate_phonetic_code(code)?;
        if !seen_codes.insert(code.as_str()) {
            continue;
        }

        let key = phonetic_posting_key(code);
        let existing = store.phonetic_index().get(wtxn, &key)?;
        let mut posting =
            existing.map_or_else(|| Vec::with_capacity(ENTITY_ID_LEN), |bytes| bytes.to_vec());
        if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
            return Err(Error::CorruptedIndex("phonetic posting"));
        }

        if posting
            .chunks_exact(ENTITY_ID_LEN)
            .any(|chunk| chunk == id.as_bytes())
        {
            if !forward_codes.iter().any(|known| known == code) {
                forward_codes.push(code.clone());
                forward_changed = true;
            }
            continue;
        }

        posting.extend_from_slice(id.as_bytes());
        store.phonetic_index().put(wtxn, &key, &posting)?;

        if !forward_codes.iter().any(|known| known == code) {
            forward_codes.push(code.clone());
            forward_changed = true;
        }
    }

    // Retain published codes, not posting-list/cache bytes.
    let mut source = PHONETIC_SOURCE.get(store, wtxn, &id)?.unwrap_or_default();
    source.extend_from_slice(codes);
    source.sort();
    source.dedup();
    PHONETIC_SOURCE.put(store, wtxn, &id, &source)?;
    if forward_changed {
        forward_codes.sort();
        forward_codes.dedup();
        let encoded = encode_phonetic_forward_codes(&forward_codes);
        store
            .phonetic_forward()
            .put(wtxn, id.as_bytes(), &encoded)?;
    }

    Ok(())
}

pub(crate) fn delete_from_phonetic_postings(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    PHONETIC_SOURCE.delete(store, wtxn, id)?;
    if let Some(raw) = store.phonetic_forward().get(wtxn, id.as_bytes())? {
        match decode_phonetic_forward_codes(&raw) {
            Ok(codes) => match delete_from_known_phonetic_codes(store, wtxn, id, &codes) {
                Ok(()) => {
                    if reconcile_phonetic_postings(store, wtxn, id)? {
                        log_phonetic_forward_fallback(id, "stale_forward_row");
                    }
                    store.phonetic_forward().delete(wtxn, id.as_bytes())?;
                    return Ok(());
                }
                Err(Error::Store(StoreError::MissingPostingEntry)) => {
                    log_phonetic_forward_fallback(id, "missing_posting_entry");
                }
                Err(err) => return Err(err),
            },
            Err(Error::CorruptedIndex(_)) => {
                log_phonetic_forward_fallback(id, "corrupted_forward_row");
            }
            Err(err) => return Err(err),
        }
    }

    scan_and_strip_phonetic_postings(store, wtxn, id)?;
    store.phonetic_forward().delete(wtxn, id.as_bytes())?;
    Ok(())
}

/// Scan the entire phonetic posting index, drop `id` from every row that
/// contains it, persist the updates, and report whether any row changed.
/// Shared by the full-scan fallback in `delete_from_phonetic_postings` and
/// the reconcile pass that runs after a forward-row-driven delete to catch
/// stale references.
pub(super) fn scan_and_strip_phonetic_postings(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let mut repaired = false;
    let mut updates = Vec::new();
    let mut deletes = Vec::new();

    for entry in store.phonetic_index().iter(wtxn)? {
        let (code, posting) = entry?;
        let Some(updated) = posting_without_entity(&posting, id)? else {
            continue;
        };

        repaired = true;
        if updated.is_empty() {
            deletes.push(code.to_vec());
        } else {
            updates.push((code.to_vec(), updated));
        }
    }

    for code in deletes {
        store.phonetic_index().delete(wtxn, &code)?;
    }

    for (code, posting) in updates {
        store.phonetic_index().put(wtxn, &code, &posting)?;
    }

    Ok(repaired)
}

pub(super) fn delete_from_known_phonetic_codes(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    codes: &[String],
) -> Result<()> {
    for code in codes {
        let key = phonetic_posting_key(code);
        let posting = store
            .phonetic_index()
            .get(wtxn, &key)?
            .ok_or(Error::Store(StoreError::MissingPostingEntry))?;
        let updated = posting_without_entity(&posting, id)?
            .ok_or(Error::Store(StoreError::MissingPostingEntry))?;

        if updated.is_empty() {
            store.phonetic_index().delete(wtxn, &key)?;
        } else {
            store.phonetic_index().put(wtxn, &key, &updated)?;
        }
    }

    Ok(())
}

pub(super) fn reconcile_phonetic_postings(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    scan_and_strip_phonetic_postings(store, wtxn, id)
}
