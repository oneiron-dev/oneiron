//! A mask change's index copies (FIX 7608 slice 3): when a writer adds
//! marks or mask spans to blobs, every index copy those blobs derive is
//! replaced or requeued in that same writer, so no input made from an older
//! copy, or from stored bytes, stays searchable or lands later.
//!
//! The copies are found from the marked blobs' whole BLAKE3 alone, through
//! the links derivation used: the snapshot ASSET id it derives (and the
//! document and revisions that row owns), every inline media envelope whose
//! inner bytes are the blob's, and every snapshot listing the blob, whose
//! symbol graph is derived again from projected full sources. A record's
//! published text, phonetic codes and vectors are replaced through the
//! existing batch door, refill and pending stores; no canonical revision,
//! live pointer or snapshot moves, and no table, census cap or detector is
//! added. Equal mark ids prove nothing: a copy is compared by its bytes.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::RepoIndexMarks;
use crate::Vault;
use crate::codebase::snapshot_asset_entity_id;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;

/// Replaces or requeues every index copy derived from a blob whose whole
/// BLAKE3 is in `sources` and that a mark covers, in `wtxn`, the writer
/// that changed its marks or spans.
///
/// It is an invalidation in the caller's transaction (L04 condition 1): it
/// fails only with that transaction's storage error, and never refuses or
/// rolls back the write that calls it for an index-side reason. Any other
/// failure is logged, and the copy is derived again by its next pass.
///
/// # Errors
/// A storage error of `wtxn`.
pub(crate) fn refresh_repo_index_projection_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    sources: &[[u8; 32]],
) -> Result<()> {
    if sources.is_empty() {
        return Ok(());
    }
    match refresh(vault, wtxn, sources) {
        Err(error) if !is_storage_error(&error) => {
            tracing::warn!(
                error = %error,
                "repo index copies are left for their next derivation"
            );
            Ok(())
        }
        other => other,
    }
}

fn refresh(vault: &Vault, wtxn: &mut RwTxn<'_>, sources: &[[u8; 32]]) -> Result<()> {
    let marks = RepoIndexMarks::read_in_txn(vault, wtxn)?;
    let sources = sources
        .iter()
        .copied()
        .filter(|source| marks.is_marked(source))
        .collect::<BTreeSet<_>>();
    if sources.is_empty() {
        return Ok(());
    }
    let mut entities = BTreeSet::new();
    for source in &sources {
        let entity = snapshot_asset_entity_id(source)?;
        if vault.store.port_entity_record(wtxn, &entity)?.is_some() {
            entities.insert(entity);
        }
    }
    entities.extend(crate::embed::repo_envelope_copies_in_txn(
        vault, wtxn, &sources,
    )?);
    for entity in &entities {
        if !crate::vault::entity_revision::refresh_repo_revision_projection_in_txn(
            vault, wtxn, &marks, entity,
        )? {
            crate::entity_doc::reindex_repo_document_in_txn(vault, wtxn, entity)?;
        }
        crate::embed::requeue_repo_embedding_in_txn(vault, wtxn, entity)?;
    }
    vault.refresh_repo_symbol_graphs_in_txn(wtxn, &marks, &sources)
}

/// Whether `error` is the transaction's own storage failure, the one kind an
/// invalidation passes on.
fn is_storage_error(error: &Error) -> bool {
    matches!(error, Error::Storage(_) | Error::Io(_) | Error::MapFull)
}
