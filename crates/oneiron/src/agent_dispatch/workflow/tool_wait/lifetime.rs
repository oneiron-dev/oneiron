//! Exact-known-source and actor erasure of workflow tool checkpoints.

use heed::RwTxn;

use super::{
    CheckpointBinding, CheckpointRow, TABLE, body_owner, fence, invalid, key, release_in_txn,
};
use crate::side_table::{Erased, SideKey};
use crate::store::Store;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::retirement::{PayloadDisposition, settle_owner_in_txn};
use crate::{EntityId, Result, Vault};

fn erase_matching_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    matches: impl Fn(&CheckpointBinding) -> bool,
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
        if row.binding().as_ref().is_some_and(&matches) {
            if key != super::key(row.attempt)? {
                return Err(invalid("workflow checkpoint binding has foreign key"));
            }
            fence::require(store, txn, row.attempt, row.generation)?;
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
    erase_matching_in_txn(store, txn, |content| depends_on(content, source))
}

fn depends_on(binding: &CheckpointBinding, source: &EntityId) -> bool {
    binding.actor == *source
        || binding.room == Some(*source)
        || binding.known_sources.contains(source)
}

/// The native delete reason is still available here, before either the
/// actor scrub or derived-row tear clears the positive source binding.
/// A dedicated checkpoint owner holds only this attempt's transcript:
/// settle all its occurrences, not just the last saved revision, while
/// another owner's identical bytes keep their independent compartment.
pub(crate) fn settle_payloads_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
    disposition: PayloadDisposition,
) -> Result<()> {
    let mut owners = Vec::new();
    for found in TABLE.iter_raw_from(store, txn, &[])? {
        let (raw_key, bytes) = found?;
        let Some(row_key) = <EntityId as SideKey>::decode_key(&raw_key) else {
            continue;
        };
        let Ok(row) = TABLE.decode_value(&bytes) else {
            continue;
        };
        let Some(content) = row.binding() else {
            continue;
        };
        if !depends_on(&content, source) {
            continue;
        }
        if row_key != key(row.attempt)? || content.body_owner != body_owner(row.attempt)? {
            return Err(invalid("workflow checkpoint payload has foreign owner"));
        }
        owners.push(content.body_owner);
    }
    for owner in owners {
        settle_owner_in_txn(
            store,
            txn,
            Subtype::AttachmentOccurrence,
            owner.as_bytes(),
            disposition,
        )?;
    }
    Ok(())
}

/// The independently registered hard-actor erase/restore scrub.
pub(crate) fn erase_actor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    erase_matching_in_txn(&vault.store, txn, |content| content.actor == *actor)
}
