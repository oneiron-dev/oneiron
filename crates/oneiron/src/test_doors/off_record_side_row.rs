//! Door for `tests/off_record_side_row_custody.rs` (FIX 2329,
//! ROOM-LOCAL-CUSTODY): one row of an authored side table, a code run's
//! replay table, written as a code run's checkpoint writes it: on a room's
//! write route, through the vault, which holds the custody door, or through a
//! bare store; and read back in a room or in base. The room's own custody is
//! read by its handles, past the room's close too, and base custody by its
//! records and its known-value index.

use std::sync::Arc;

use crate::error::Result;
use crate::off_record::OffRecordSession;
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::session_overlay::SessionOverlay;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

/// The replay table, read as raw bytes: every masked copy decodes.
const REPLAY_ROWS: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::CODE_RUN_REPLAY);

/// Writes `body` as the replay row of `run` on `session`'s current write
/// route: staged into the room's overlay while the room is off record.
///
/// # Errors
///
/// The side-row wall's refusal, a closing session, or storage errors.
pub fn put_room_replay_row(
    session: &OffRecordSession<'_>,
    run: EntityId,
    body: &[u8],
) -> Result<()> {
    let route = session.write_route()?;
    session.routed_side_txn(&route, |wtxn, _read, write| {
        REPLAY_ROWS.put(&write, wtxn, &run, &body.to_vec())
    })
}

/// Writes `body` as the replay row of `run` through `vault`'s bare store,
/// which holds no custody door and is no room's view.
///
/// # Errors
///
/// The side-row wall's refusal, or storage errors.
pub fn put_bare_store_replay_row(vault: &Vault, run: EntityId, body: &[u8]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    REPLAY_ROWS.put(&vault.store, &mut wtxn, &run, &body.to_vec())?;
    wtxn.commit()?;
    Ok(())
}

/// Writes `body` as the replay row of `run` through `vault`, whose custody
/// door mints a record for each fresh secret the side-row wall places.
///
/// # Errors
///
/// The side-row wall's refusal, or storage errors.
pub fn put_vault_replay_row(vault: &Vault, run: EntityId, body: &[u8]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    REPLAY_ROWS.put(vault, &mut wtxn, &run, &body.to_vec())?;
    wtxn.commit()?;
    Ok(())
}

/// The replay row of `run` as `session` reads it, over its overlay and base.
///
/// # Errors
///
/// A participant no longer in the room, or storage errors.
pub fn room_replay_row(session: &OffRecordSession<'_>, run: EntityId) -> Result<Option<Vec<u8>>> {
    session.routed_side_read(|rtxn, read| REPLAY_ROWS.get(&read, rtxn, &run))
}

/// The replay row of `run` in base alone, as a bare store reads it.
///
/// # Errors
///
/// Storage errors.
pub fn base_replay_row(vault: &Vault, run: EntityId) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    REPLAY_ROWS.get(&vault.store, &rtxn, &run)
}

/// An off-record room's own custody (ROOM-LOCAL-CUSTODY), held past the
/// room's close, so a test reads what the close left of it.
pub struct RoomCustody(Arc<SessionOverlay>);

impl RoomCustody {
    /// The custody of the room `session` is a stretch of.
    #[must_use]
    pub fn of(session: &OffRecordSession<'_>) -> Self {
        Self(session.overlay())
    }

    /// The value the room keeps under `handle`: bare (`r1`) or as a row
    /// holds it (`[secret r1]`).
    ///
    /// # Errors
    ///
    /// A poisoned lock.
    pub fn secret(&self, handle: &str) -> Result<Option<Vec<u8>>> {
        // RED: a room keeps no custody of its own before
        // ROOM-LOCAL-CUSTODY; the fix reads the room's store here.
        let _ = (&self.0, handle);
        Ok(None)
    }

    /// How many secrets the room keeps now.
    ///
    /// # Errors
    ///
    /// A poisoned lock.
    pub fn count(&self) -> Result<usize> {
        // RED: see `secret`.
        Ok(0)
    }
}

/// How many custody records base holds.
///
/// # Errors
///
/// Storage errors.
pub fn vault_custody_record_count(vault: &Vault) -> Result<usize> {
    Ok(vault.entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)?.len())
}

/// Whether base's known-value index holds `value`'s fingerprint, whole.
///
/// # Errors
///
/// Storage and custody errors.
pub fn vault_knows_value(vault: &Vault, value: &[u8]) -> Result<bool> {
    Ok(vault
        .known_values_now()?
        .is_some_and(|known| known.is_exact_value(value)))
}
