//! Core half of `store::pending_custody_revoke`: its store-layer items live in `oneiron_store::pending_custody_revoke` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::pending_custody_revoke::*;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::vault::Vault;
use oneiron_authority::authority::ActSurface;
use serde::{Deserialize, Serialize};

/// Each revoke this install still owes the owner's other machines, by
/// custody record id.
pub(crate) const PENDING: SideTable<EntityId, PendingRevoke, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_PENDING_REVOKE);

/// Erasing `actor` (FIX 3520): a revoke still owed for him is dropped, so
/// no act is carried in his name. One-way, in the erase's own transaction.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_pending_revoke_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (id, pending) in PENDING.scan(&vault.store, wtxn)? {
        if pending.owner == *actor {
            PENDING.delete(&vault.store, wtxn, &id)?;
        }
    }
    Ok(())
}
