//! The own-device replay of chosen rows from one vault into another, for the
//! test that a host's taint mark reaches a synced replica (census L6-32).
//! Each row goes through the sync replay door with its stored header, as an
//! own device takes it; the replicated put itself stays crate-private.
use crate::error::Error;
use crate::ports::EntityStoreRead;
use crate::sync::client::ImportTier;
use crate::sync::replay::{ReplicatedEntity, replay_entity};
use crate::{EntityId, Result, Vault};

/// Replays each row of `ids`, as `from` stores it now, into `to`.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for an id `from` holds no row for, or the
/// replay door's refusal.
pub fn replicate_entities(from: &Vault, to: &Vault, ids: &[EntityId]) -> Result<()> {
    let rows = {
        let rtxn = from.store.env.read_txn()?;
        ids.iter()
            .map(|id| {
                from.store
                    .port_entity_record(&rtxn, id)?
                    .map(|row| (*id, row))
                    .ok_or(Error::EntityNotFound)
            })
            .collect::<Result<Vec<_>>>()?
    };
    for (id, row) in &rows {
        replay_entity(
            to,
            ReplicatedEntity {
                id: *id,
                entity_type: row.entity_type,
                occurred: row.occurred,
                learned_at: row.learned_at,
                row_version: row.row_version,
                body: &row.body,
            },
            ImportTier::OwnDevice,
        )?;
    }
    Ok(())
}
