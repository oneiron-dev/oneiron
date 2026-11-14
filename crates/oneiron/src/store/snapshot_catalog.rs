//! The catalog of the inference snapshots a vault keeps sealed on disk
//! (DESIGN-V2 §7, V2-R3): one row per snapshot under a random catalog id,
//! carrying what the snapshot was computed from and under, never what it
//! holds. The sealed body and its wrapped key live apart from the row; a
//! restore checks the row first, and its absence denies an open.
//!
//! A row keeps ids, digests, enums, counts and pins only: no prompt text,
//! tokens, tensors, credentials or keys. Its manifest names every field the
//! design binds: the vault and the read it was admitted under, the branch
//! and its frontier, the token digest, and the model, quant, tokenizer,
//! template, state schema, attention, build and cache precision it ran
//! with. A field the producer could not name is `None`, and a row with one
//! is never reused. Its compatibility leaves out the backend epoch: a
//! restore binds the new incarnation's own.
//!
//! An erase scans every row's dependency set (its conversation and branch
//! tip, its sources, worlds, authors and erase subjects, and the quoted or
//! folded records it derives from), not the requester's session alone, and
//! takes every row of each conversation it reaches: a later state of the
//! same session carries what an earlier one did. A row whose dependency set
//! is not precise, that does not decode, or whose key is no catalog id goes
//! on any erase.
use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::side_table::{self, FixedSideKey, Named, Raw, SideKey, SideTable, SideTableDbs};
use crate::store::Store;
use oneiron_model::llm::{
    CacheDigest, CacheIdentity, ConditioningDigest, ScopeDigest, TokenDigest, VaultRef,
};

#[doc(hidden)]
pub use oneiron_records::store::snapshot_catalog::{
    SNAPSHOT_RECORD_SCHEMA, SnapshotClass, SnapshotCompatibility, SnapshotDependencies, SnapshotId,
    SnapshotManifest, SnapshotPins, SnapshotRecord,
};

/// Key: the catalog id (16 random bytes).
pub(crate) const CATALOG: SideTable<SnapshotId, SnapshotRecord, Named> =
    SideTable::new(&side_table::INFERENCE_SNAPSHOT_CATALOG);

/// Key: the conversation id plus the catalog id (16 + 16 bytes), empty
/// markers, so a restore lists one conversation's rows without reading the
/// whole catalog. Written in the row's own transaction; startup reconcile
/// heals rows that predate it.
pub(crate) const CONVERSATION_INDEX: SideTable<(EntityId, SnapshotId), (), Raw> =
    SideTable::new(&side_table::INFERENCE_SNAPSHOT_CONVERSATION_INDEX);

/// Records the conversation index entry of the row `id` names under
/// `conversation`, in `wtxn`.
pub(crate) fn put_conversation_entry(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    conversation: &EntityId,
    id: &SnapshotId,
) -> Result<()> {
    CONVERSATION_INDEX.put(store, wtxn, &(*conversation, *id), &())
}

/// Drops the conversation index entry of the row `id` named under
/// `conversation`, in `wtxn`.
pub(crate) fn delete_conversation_entry(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    conversation: &EntityId,
    id: &SnapshotId,
) -> Result<()> {
    CONVERSATION_INDEX
        .delete(store, wtxn, &(*conversation, *id))
        .map(|_| ())
}

/// One catalog row as read: its id, and its record, `None` when the row
/// does not decode.
pub(crate) type CatalogRow = (SnapshotId, Option<SnapshotRecord>);

/// One catalog row as an erase reads it: its key bytes after the table's
/// prefix, and the row as read when those bytes are a catalog id.
type RawRow = (Vec<u8>, Option<CatalogRow>);

/// Every row of the catalog, in key order, each with its raw key. A key of
/// the wrong width, which no writer here makes, has no id.
fn raw_rows(store: &Store, txn: &RoTxn<'_>) -> Result<Vec<RawRow>> {
    let mut out = Vec::new();
    for row in CATALOG.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let row = SnapshotId::decode_key(&key).map(|id| (id, CATALOG.decode_value(&bytes).ok()));
        out.try_reserve(1).map_err(std::io::Error::from)?;
        out.push((key, row));
    }
    Ok(out)
}

/// Every row of the catalog, in id order. A key of the wrong width, which
/// no writer here makes, is skipped.
pub(crate) fn rows(store: &Store, txn: &RoTxn<'_>) -> Result<Vec<CatalogRow>> {
    let mut out = Vec::new();
    for row in raw_rows(store, txn)?.into_iter().filter_map(|(_, row)| row) {
        out.try_reserve(1).map_err(std::io::Error::from)?;
        out.push(row);
    }
    Ok(out)
}

/// Every row of `conversation` that decodes and may serve a restore, by the
/// conversation index: no other row is read. A dangling entry, whose row is
/// gone, is skipped; the row's own transaction never leaves one.
pub(crate) fn rows_of_conversation(
    store: &Store,
    txn: &RoTxn<'_>,
    conversation: &EntityId,
) -> Result<Vec<SnapshotRecord>> {
    let mut out = Vec::new();
    for (_, id) in CONVERSATION_INDEX.scan_keys(store, txn, conversation.as_bytes())? {
        // Lenient: one damaged row must not hide every healthy snapshot.
        if let Some(record) = CATALOG.get_lenient(store, txn, &id)? {
            if record.reusable() {
                out.push(record);
            }
        }
    }
    Ok(out)
}

/// The rows an erase of `id` takes: every row whose dependency set names
/// it, whose set is not precise, that does not decode or whose key is no
/// catalog id, and every other row of each conversation those reach.
fn erased_rows<'r>(rows: &'r [RawRow], id: &EntityId) -> Vec<&'r RawRow> {
    let reached = |row: &RawRow| match row {
        (_, Some((_, Some(record)))) => !record.dependencies.precise || record.depends_on(id),
        _ => true,
    };
    let conversations: BTreeSet<EntityId> = rows
        .iter()
        .filter(|row| reached(*row))
        .filter_map(|(_, row)| row.as_ref()?.1.as_ref())
        .map(|record| record.manifest.conversation)
        .collect();
    rows.iter()
        .filter(|row| {
            reached(*row)
                || matches!(row, (_, Some((_, Some(record))))
                    if conversations.contains(&record.manifest.conversation))
        })
        .collect()
}

/// Deletes the catalog row stored under `key`, the bytes after the table's
/// prefix, whatever their width; `true` when a row was there.
fn delete_raw(store: &Store, wtxn: &mut RwTxn<'_>, key: &[u8]) -> Result<bool> {
    let full = [CATALOG.decl().prefix, key].concat();
    store.side_vault_meta().delete(wtxn, &full)
}

/// The erase of `id` takes every snapshot it reaches (FIX 10466), in the
/// erase's own transaction at both delete doors: every row whose
/// dependency set names it, whose set is not precise, that does not decode
/// or whose key is no catalog id, and the rest of each conversation those
/// reach. Each row goes by its raw key; a key's retirement is staged with
/// its row's delete wherever the key is a catalog id. Bodies, custody
/// entries and live copies go after the commit.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_in_txn(store: &Store, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    // Inside the erase's writer: a publish waiting behind it sees the move.
    store.inference_snapshots.erased();
    let rows = raw_rows(store, &*wtxn)?;
    for (key, row) in erased_rows(&rows, id) {
        match row {
            Some((snapshot, _)) => retire_in_txn(store, wtxn, snapshot)?,
            None => delete_raw(store, wtxn, key)?,
        };
    }
    Ok(())
}

/// An erase of `actor` takes every snapshot it authored or is a subject of,
/// as [`erase_in_txn`] does for any id: a row records an actor as an id in
/// its dependency set, never apart from it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    erase_in_txn(&vault.store, wtxn, actor)
}

/// Takes the row `id` out of the catalog and stages its key's retirement,
/// both in `wtxn`: from the commit on no open finds it, and a restored
/// earlier image cannot open its key. The body file and the custody entry
/// go after the commit. `true` when a row was there.
///
/// # Errors
/// Custody and storage faults.
pub(crate) fn retire_in_txn(store: &Store, wtxn: &mut RwTxn<'_>, id: &SnapshotId) -> Result<bool> {
    // Lenient: a damaged row still retires. Its conversation index entry
    // goes only when the row decodes; a damaged row must not abort the
    // erase or reconcile that found it.
    if let Some(record) = CATALOG.get_lenient(store, wtxn, id)? {
        delete_conversation_entry(store, wtxn, &record.manifest.conversation, id)?;
    }
    let gone = CATALOG.delete(store, wtxn, id)?;
    store.stage_inference_snapshot_retirement_in_txn(wtxn, &id.0)?;
    Ok(gone)
}
