//! Exact-known-source and actor erasure of workflow tool checkpoints.

use heed::RwTxn;

use super::{CheckpointContent, CheckpointRow, TABLE, release_in_txn};
use crate::side_table::{Erased, SideKey};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

fn erase_matching_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    matches: impl Fn(&CheckpointContent) -> bool,
) -> Result<()> {
    let mut erased: Vec<(EntityId, CheckpointRow)> = Vec::new();
    for row in TABLE.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <EntityId as SideKey>::decode_key(&key) else {
            continue;
        };
        let Ok(row) = TABLE.decode_value(&bytes) else {
            continue;
        };
        if row.content.as_ref().is_some_and(&matches) {
            erased.push((key, row));
        }
    }
    for (key, row) in erased {
        if let Some(content) = &row.content {
            release_in_txn(store, txn, content)?;
        }
        // Keep an erased form so a late checkpoint cannot revive this leaf.
        TABLE.put_erased(store, txn, &key, Erased::of(row)?)?;
    }
    Ok(())
}

/// Both entity-delete doors call this before the source body goes. An
/// incomplete source set still matches every positive id it retained; it
/// never makes an unrelated source erase every unknown checkpoint.
pub(crate) fn erase_source_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    erase_matching_in_txn(store, txn, |content| {
        content.actor == *source
            || content.room == Some(*source)
            || content.progress.known_sources.contains(source)
    })
}

/// The independently registered hard-actor erase/restore scrub.
pub(crate) fn erase_actor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    erase_matching_in_txn(&vault.store, txn, |content| content.actor == *actor)
}
