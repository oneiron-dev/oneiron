//! Door for `tests/off_record_side_row_custody.rs` (FIX 2329): one row of an
//! authored side table, a code run's replay table, written as a code run's
//! checkpoint writes it, on a room's write route or through a bare store.

use crate::error::Result;
use crate::off_record::OffRecordSession;
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
