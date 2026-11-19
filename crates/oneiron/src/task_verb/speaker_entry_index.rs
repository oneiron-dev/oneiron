//! The voice speakers' entry facts by the container they entered
//! (PLAN-RUN-RESULT-GUARD-SPEAKER-ENTRIES). An entry fact's id is derived
//! from its speaker, so no stored row finds a container's speakers; yet each
//! one reads the container's records from its entry on
//! (`conversation::attendee::speaker_entry_covers_in`) and holds no seat on
//! its ledger. A reader that asks who reads a room asks here as well.
//!
//! The index is derived and a prefilter only: every hit is re-read as its
//! entry fact, and a hit whose row is gone or a withdrawn Shell with no body
//! names no one. The entity row's staging keeps it, a peer's synced row too,
//! and every row removal drops its row; writable open and a checkpoint
//! restore rebuild it whole. Until a whole rebuild has committed it answers
//! nothing, and a reader takes any container as one a speaker entered.

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_TASK;
use crate::side_table::{self, Raw, SideTable};
use crate::store::{ManifestDbs, Store};

/// `(container, entry fact) -> ()` for each speaker's entry fact.
const SPEAKER_ENTRY_BY_CONTAINER: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::TASK_SPEAKER_ENTRY_BY_CONTAINER);

/// `Some(INDEX_VERSION)` once a whole rebuild of the index has committed.
const SPEAKER_ENTRY_INDEX_STATE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::TASK_SPEAKER_ENTRY_INDEX_STATE);

const INDEX_VERSION: u64 = 1;

/// Keeps the index in the transaction that writes or removes one entity
/// row. `replacement` is the row's new type and body; `None` is a removal,
/// which drops the row the stored entry fact files. An entry fact is
/// immutable (the put door's ask-fact guard refuses any other bytes under
/// its id), so a put only adds. Runs before the row changes.
pub(crate) fn reindex_speaker_entry(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    replacement: Option<(u8, &[u8])>,
) -> Result<()> {
    match replacement {
        Some((entity_type, body)) => {
            if entity_type == ENTITY_TYPE_TASK
                && let Some(container) = super::ask_record::speaker_entry_container(body)
            {
                SPEAKER_ENTRY_BY_CONTAINER.put(store, txn, &(container, *id), &())?;
            }
        }
        None => {
            if let Some(raw) = EntityStoreRead::port_entity_raw_wiped(store, txn, id)?
                && EntityMetadataHeader::parse(&raw)
                    .is_some_and(|header| header.entity_type == ENTITY_TYPE_TASK)
                && let Some(container) = raw
                    .get(ENTITY_METADATA_HEADER_LEN..)
                    .and_then(super::ask_record::speaker_entry_container)
            {
                SPEAKER_ENTRY_BY_CONTAINER.delete(store, txn, &(container, *id))?;
            }
        }
    }
    Ok(())
}

fn index_complete_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(SPEAKER_ENTRY_INDEX_STATE.get(store, txn, &())? == Some(INDEX_VERSION))
}

/// Whether a voice speaker entered `container`: one of the index's rows for
/// it names an entry fact that still reads, in the caller's snapshot, as a
/// speaker's entry into `container`. `None` while no whole rebuild of the
/// index has committed, when any container may hold one.
pub(crate) fn speaker_entered_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    container: EntityId,
) -> Result<Option<bool>> {
    if !index_complete_in_txn(&vault.store, txn)? {
        return Ok(None);
    }
    for row in SPEAKER_ENTRY_BY_CONTAINER.iter_from(&vault.store, txn, container.as_bytes())? {
        let ((_, entry), ()) = row?;
        // A withdrawn entry's Shell keeps its TASK header and no body, and
        // its row here: a dead hit, which names no attendee.
        if vault
            .store
            .port_entity_record(txn, &entry)?
            .is_none_or(|record| record.body.is_empty())
        {
            continue;
        }
        let Some(fact) = super::read_attendee_entry_in(vault, txn, entry)? else {
            continue;
        };
        if fact.container == container
            && matches!(
                fact.attendee,
                crate::conversation::ContainerAttendee::Speaker { .. }
            )
        {
            return Ok(Some(true));
        }
    }
    Ok(Some(false))
}

/// Rebuilds the index from every TASK row when no whole rebuild has
/// committed, or always with `force`, in one write transaction (a crash
/// leaves nothing or everything). Runs at writable open and after a
/// checkpoint restore (`force`), whose rows came back without a put.
pub(crate) fn backfill_speaker_entry_index(vault: &Vault, force: bool) -> Result<()> {
    // At open (`force` false) a failed rebuild of this derived index never
    // refuses the open: the flag stays unset, and readers take every
    // container as one a speaker entered. The restore rebuild propagates its
    // errors like its siblings.
    match rebuild_speaker_entry_index(&vault.store, force) {
        Err(error) if !force => {
            tracing::warn!(
                %error,
                "speaker-entry index rebuild failed; no room reads as its owner's alone"
            );
            Ok(())
        }
        other => other,
    }
}

fn rebuild_speaker_entry_index(store: &Store, force: bool) -> Result<()> {
    let mut wtxn = store.env.write_txn()?;
    if !force && index_complete_in_txn(store, &wtxn)? {
        return Ok(());
    }
    let mut rows = Vec::new();
    for entry in store.port_entity_ids_by_type(&wtxn, ENTITY_TYPE_TASK, None)? {
        let id = entry?;
        let Some(record) = store.port_entity_record(&wtxn, &id)? else {
            continue;
        };
        if record.entity_type != ENTITY_TYPE_TASK {
            continue;
        }
        if let Some(container) = super::ask_record::speaker_entry_container(&record.body) {
            rows.push((container, id));
        }
    }
    SPEAKER_ENTRY_BY_CONTAINER.delete_from(store, &mut wtxn, &[])?;
    for key in &rows {
        SPEAKER_ENTRY_BY_CONTAINER.put(store, &mut wtxn, key, &())?;
    }
    SPEAKER_ENTRY_INDEX_STATE.put(store, &mut wtxn, &(), &INDEX_VERSION)?;
    wtxn.commit()?;
    Ok(())
}

/// Test door (`test_doors::room_speaker_entries`): drops the whole index and
/// its flag, as a vault file older than the index holds neither.
#[cfg(oneiron_test_support)]
pub(crate) fn forget_speaker_entry_index(vault: &Vault) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    SPEAKER_ENTRY_BY_CONTAINER.delete_from(&vault.store, &mut wtxn, &[])?;
    SPEAKER_ENTRY_INDEX_STATE.delete(&vault.store, &mut wtxn, &())?;
    wtxn.commit()?;
    Ok(())
}
