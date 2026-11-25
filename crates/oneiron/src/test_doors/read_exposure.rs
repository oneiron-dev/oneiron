//! Doors for `tests/actor_read_exposure.rs` (census L8-65): the record rows a reader's read
//! exposure keeps, and a credentialed read inside an off-record room.

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::BatchOp;
use crate::claim::{PointRead, ScopedReadActorKey};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::off_record::OffRecordSession;
use crate::ports::EntityStoreRead as _;
use crate::session_overlay::{JournalEntry, JournalRole, JournalScope};

/// The records `reader`'s kept rows name, as the vault's last write left them: one row per
/// record ever served to it that no erase has taken.
pub fn exposed_records(vault: &Vault, reader: &EntityId) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::claim::exposed_records_in(&vault.store, &txn, reader)
}

/// A read on `key`'s lane inside `session`'s room, which reads the room's overlay ∪ base as a
/// credentialed agent's read there does. The room first stages a copy of `copied`'s base row
/// under a fresh id, a record of the room's own that base never holds; the lane then
/// point-reads that id and `records`. Returns the fresh id and the ids the lane served.
pub fn read_in_room(
    vault: &Vault,
    session: &OffRecordSession<'_>,
    key: ScopedReadActorKey,
    copied: &EntityId,
    records: &[EntityId],
) -> Result<(EntityId, Vec<EntityId>)> {
    let row = {
        let txn = vault.store.env.read_txn()?;
        vault
            .port_entity_record(&txn, copied)?
            .ok_or(crate::Error::EntityNotFound)?
    };
    let staged = EntityId::now();
    let route = session.write_route()?;
    session.overlay_write_routed(&route, |wtxn, apply| {
        apply(
            wtxn,
            JournalEntry {
                scope: JournalScope::new(EntityId::now(), staged),
                role: JournalRole::TurnPut,
                learned_at: row.learned_at,
                occurred: row.occurred,
                op: BatchOp::Put {
                    id: staged,
                    entity_type: row.entity_type,
                    occurred: row.occurred,
                    learned_at: row.learned_at,
                    row_version: None,
                    data: row.body.clone(),
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
                source_run: None,
            },
        )
    })?;
    let view = session.read_view()?;
    let mut reads = vec![PointRead::id(staged)];
    reads.extend(records.iter().map(|id| PointRead::id(*id)));
    let read = vault
        .scoped_read_in_session(key, &view)
        .read(&reads, None)?;
    let served = read.value.iter().flatten().map(|row| row.id).collect();
    Ok((staged, served))
}
