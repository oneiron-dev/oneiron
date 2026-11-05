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
    retain_binding: bool,
    matches: impl Fn(&CheckpointBinding) -> bool,
) -> Result<()> {
    let mut erased: Vec<(EntityId, CheckpointRow, CheckpointBinding)> = Vec::new();
    for row in TABLE.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <EntityId as SideKey>::decode_key(&key) else {
            continue;
        };
        let Ok(row) = TABLE.decode_value(&bytes) else {
            continue;
        };
        let Some(binding) = row.binding().filter(&matches) else {
            continue;
        };
        if key != super::key(row.attempt)? {
            return Err(invalid("workflow checkpoint binding has foreign key"));
        }
        fence::require(store, txn, row.attempt, row.generation)?;
        erased.push((key, row, binding));
    }
    for (key, mut row, binding) in erased {
        if retain_binding && binding.body_owner != body_owner(row.attempt)? {
            return Err(invalid("workflow checkpoint payload has foreign owner"));
        }
        if let Some(content) = row.content.take() {
            release_in_txn(store, txn, &content)?;
        }
        if retain_binding {
            // A source delete does not erase its keys or lose the binding
            // needed by a later, actual erase of that same source.
            row.retained = Some(binding);
            TABLE.put(store, txn, &key, &row)?;
        } else {
            TABLE.put_erased(store, txn, &key, Erased::of(row)?)?;
        }
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
    erase_matching_in_txn(store, txn, true, |content| depends_on(content, source))
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
    let mut matched = Vec::new();
    for found in TABLE.iter_raw_from(store, txn, &[])? {
        let (raw_key, bytes) = found?;
        let Some(row_key) = <EntityId as SideKey>::decode_key(&raw_key) else {
            continue;
        };
        let Ok(row) = TABLE.decode_value(&bytes) else {
            continue;
        };
        let Some(binding) = row.binding() else {
            continue;
        };
        if !depends_on(&binding, source) {
            continue;
        }
        if row_key != key(row.attempt)? || binding.body_owner != body_owner(row.attempt)? {
            return Err(invalid("workflow checkpoint payload has foreign owner"));
        }
        matched.push((row_key, row, binding));
    }
    for (row_key, row, binding) in matched {
        if matches!(disposition, PayloadDisposition::Erase)
            && let Some(content) = &row.content
        {
            release_in_txn(store, txn, content)?;
        }
        settle_binding_in_txn(store, txn, source, &binding, disposition)?;
        if matches!(disposition, PayloadDisposition::Erase) {
            TABLE.put_erased(store, txn, &row_key, Erased::of(row)?)?;
        }
    }
    Ok(())
}

fn settle_binding_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    erase_source: &EntityId,
    binding: &CheckpointBinding,
    disposition: PayloadDisposition,
) -> Result<()> {
    #[cfg(not(unix))]
    let _ = erase_source;
    #[cfg(unix)]
    if matches!(disposition, PayloadDisposition::Erase) {
        crate::store::erase_bodies_for_owner_in_txn(
            store,
            txn,
            erase_source,
            &binding.body_owner,
            &binding.published_digests,
            false,
        )?;
    }
    settle_owner_in_txn(
        store,
        txn,
        Subtype::AttachmentOccurrence,
        binding.body_owner.as_bytes(),
        disposition,
    )
}

/// The independently registered hard-actor erase/restore scrub.
pub(crate) fn erase_actor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    erase_matching_in_txn(&vault.store, txn, false, |content| content.actor == *actor)
}
