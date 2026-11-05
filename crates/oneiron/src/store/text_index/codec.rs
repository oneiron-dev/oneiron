//! Core half of `store::text_index::codec`: its store-layer items live in `oneiron_store::text_index::codec` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::text_index::codec::*;

use super::diagnostics::{Bm25DiagnosticKind, Bm25Diagnostics};
use super::{
    ENTITY_ID_LEN, FIELD_LENGTH_LEN, FIELD_STATS_LEN, FIELD_TF_LEN, FORWARD_FIELD_ID_LEN,
    FORWARD_TERM_LEN_LEN, TOTAL_DOCS_KEY, TOTAL_LENGTH_KEY,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::short_id_prefix;
use crate::store::ManifestDbs;
use heed::{RoTxn, RwTxn};
use std::collections::{BTreeMap, HashMap};

/// Finds the posting duplicate item for `id` under `term` with a
/// prefix-ranged cursor walk: LMDB keeps duplicate items bytewise sorted
/// and every item starts with the 16-byte entity id, so the scan stops at
/// the first item whose prefix exceeds `id`. Fails closed when two
/// duplicate items share one entity prefix — that breaks the
/// one-dup-per-(term, entity) invariant and would drift `df`.
pub(crate) fn find_posting_dup(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    term: &str,
    id: &EntityId,
) -> Result<PostingLookup> {
    let diagnostics = &store.diagnostics().bm25;
    let Some(dups) = store
        .text_postings()
        .get_duplicates(txn, posting_key(term).as_bytes())?
    else {
        return Ok(PostingLookup::RowMissing);
    };
    let mut found: Option<Vec<u8>> = None;
    for item in dups {
        let (_, dup) = item?;
        if dup.len() < ENTITY_ID_LEN + 1 {
            return Err(corrupted_with_diagnostic(
                diagnostics,
                "posting entry truncated at header",
                Bm25DiagnosticKind::MalformedPostingAlignment,
            ));
        }
        match dup[..ENTITY_ID_LEN].cmp(id.as_bytes()) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                if found.is_some() {
                    return Err(corrupted_with_diagnostic(
                        diagnostics,
                        "duplicate posting entries for one entity",
                        Bm25DiagnosticKind::MalformedPostingAlignment,
                    ));
                }
                found = Some(dup.to_vec());
                // Keep scanning one step: an adjacent item with the same
                // prefix is the duplicate-entity corruption case above.
            }
            std::cmp::Ordering::Greater => break,
        }
    }
    Ok(match found {
        Some(entry) => PostingLookup::Found(entry),
        None => PostingLookup::EntityMissing,
    })
}

pub(crate) fn read_field_stats(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    field_id: u16,
) -> Result<(u32, u64)> {
    let key = field_id.to_be_bytes();
    let Some(raw) = store.text_bm25_field_stats().get(txn, &key)? else {
        return Ok((0, 0));
    };
    if raw.len() != FIELD_STATS_LEN {
        return Err(corrupted("field stats has invalid byte length"));
    }
    let doc_count = u32::from_le_bytes(
        raw[..4]
            .try_into()
            .map_err(|_| corrupted("field stats doc_count slice"))?,
    );
    let total_length = u64::from_le_bytes(
        raw[4..]
            .try_into()
            .map_err(|_| corrupted("field stats total_length slice"))?,
    );
    Ok((doc_count, total_length))
}

pub(crate) fn write_field_stats(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    field_id: u16,
    doc_count: u32,
    total_length: u64,
) -> Result<()> {
    let mut value = [0_u8; FIELD_STATS_LEN];
    value[..4].copy_from_slice(&doc_count.to_le_bytes());
    value[4..].copy_from_slice(&total_length.to_le_bytes());
    let key = field_id.to_be_bytes();
    store.text_bm25_field_stats().put(wtxn, &key, &value)?;
    Ok(())
}

pub(crate) fn read_total_docs(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u32> {
    match store.text_meta().get(txn, &TOTAL_DOCS_KEY)? {
        Some(raw) => {
            Ok(u32::from_le_bytes(raw.as_ref().try_into().map_err(
                |_| corrupted("total_docs sentinel has invalid length"),
            )?))
        }
        None => Ok(0),
    }
}

pub(crate) fn write_total_docs(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    total_docs: u32,
) -> Result<()> {
    store
        .text_meta()
        .put(wtxn, &TOTAL_DOCS_KEY, &total_docs.to_le_bytes())?;
    Ok(())
}
