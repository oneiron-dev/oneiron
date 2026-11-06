//! Reconstruct the retained transport in the actual applying transaction.

use heed::{RoTxn, RwTxn};
use loro::LoroDoc;

use super::{PairDigest, SelectedRecordDocument};
use crate::error::{Error, Result, SyncError};
use crate::store::window_record_sources::{self, RetainedRecordDocumentSource};
use crate::sync::ingest::entity::IngestCtx;
use crate::sync::loro_support::map_get_bytes;
use crate::sync::skill_docs::selected_record_document;
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

/// This is the stored carrier, not the caller's live or scratch LoroDoc.
/// Pending updates are read through the same transaction as its snapshot.
pub(super) fn durable_window_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    window: &WindowKey,
) -> Result<LoroDoc> {
    use crate::sync::window::{apply_pending_window_updates_in_txn, load_window_from_state_in_txn};

    match load_window_from_state_in_txn(vault, txn, window) {
        Ok(doc) => Ok(doc),
        Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
            let doc = LoroDoc::new();
            apply_pending_window_updates_in_txn(vault, txn, &doc, window)?;
            Ok(doc)
        }
        Err(error) => Err(error),
    }
}

fn matches_durable_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    window: &WindowKey,
    entity: &EntityId,
    raw: &[u8],
    expected: &PairDigest,
) -> Result<bool> {
    let durable = durable_window_in_txn(vault, txn, window)?;
    if map_get_bytes(&durable.get_map("entities"), &entity.to_hex()).as_deref() != Some(raw) {
        return Ok(false);
    }
    let Some((head, snapshot, refinement)) = selected_record_document(&durable, entity, raw)?
    else {
        return Ok(false);
    };
    if PairDigest::of(raw, &head, &snapshot, refinement.as_ref())? != *expected {
        return Ok(false);
    }
    crate::sync::ingest::carried_origin_in_txn(vault, txn, &durable, window.as_str(), entity, raw)?;
    Ok(!crate::sync::ingest::peer_row_in_txn(
        vault,
        txn,
        window.as_str(),
        entity,
        raw,
    )?)
}

pub(super) fn select_in_txn(
    ctx: &IngestCtx<'_>,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    raw: &[u8],
    expected: &PairDigest,
) -> Result<Option<RetainedRecordDocumentSource>> {
    let Some(source) = window_record_sources::retained_in_txn(
        &ctx.vault.store,
        txn,
        ctx.window_key,
        entity,
        expected,
    )?
    else {
        return Ok(None);
    };
    let Some(window) = WindowKey::try_new(ctx.window_key) else {
        return Ok(None);
    };
    if !matches_durable_in_txn(ctx.vault, txn, &window, entity, raw, expected)? {
        return Ok(None);
    }
    Ok(Some(source))
}

pub(super) fn recheck_in_txn(
    selected: &SelectedRecordDocument<'_>,
    source: &RetainedRecordDocumentSource,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    expected: &PairDigest,
) -> Result<bool> {
    let vault = selected.vault;
    if source.machine() != selected.machine
        || !source.recheck_in_txn(&vault.store, txn, &selected.window, entity, expected)?
    {
        return Ok(false);
    }
    let Some(window) = WindowKey::try_new(&selected.window) else {
        return Ok(false);
    };
    matches_durable_in_txn(vault, txn, &window, entity, &selected.raw, expected)
}
