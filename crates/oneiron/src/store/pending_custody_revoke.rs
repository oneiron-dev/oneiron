//! The custody revokes this install still owes the owner's other machines
//! (CALLS CUSTODY_REVOKE_PENDING_CARRY): one value-free row per custody
//! record. Custody's revoke carry (`secret_custody::control`) writes and
//! settles them; an erase of the owner drops his.

use oneiron_authority::authority::ActSurface;
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::vault::Vault;

/// Each revoke this install still owes the owner's other machines, by
/// custody record id.
pub(crate) const PENDING: SideTable<EntityId, PendingRevoke, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_PENDING_REVOKE);

/// One revoke this install has not carried yet. It holds no value and no
/// proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingRevoke {
    /// The owner PERSON the revoke is by.
    pub(crate) owner: EntityId,
    /// Where he decided it: audit only.
    pub(crate) surface: ActSurface,
    /// The second the revoke was made at: its transition's.
    pub(crate) at: u64,
    /// The generation it revoked.
    pub(crate) generation: u32,
}

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
