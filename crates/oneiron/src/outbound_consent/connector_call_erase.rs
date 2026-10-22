//! An actor's erase reaches every connector call row that keeps what the
//! actor asked (FIX 9159): the held or pending row with the caller's exact
//! arguments, and the acknowledged caller a status read keeps.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::connector_call::{ACKNOWLEDGED_CALLS, PENDING_CALLS};

/// Erasing `actor` from the connector calls (FIX 9159): every call row the
/// actor made goes, held, pending delivery, awaiting input or settled, and
/// with it the request it kept; so does every acknowledged caller that names
/// the actor. A send stays in the intent ledger, so dropping its row never
/// sends it again, and a held call of the actor's is never resumed. Runs in
/// the erase's own transaction.
pub(crate) fn erase_connector_call_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let principal = actor.to_hex();
    let pending: Vec<EntityId> = PENDING_CALLS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, row)| row.principal_ref == principal)
        .map(|(call_ref, _)| call_ref)
        .collect();
    for call_ref in pending {
        PENDING_CALLS.delete(&vault.store, wtxn, &call_ref)?;
    }
    let acknowledged: Vec<EntityId> = ACKNOWLEDGED_CALLS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, row)| row.principal_ref == principal)
        .map(|(call_ref, _)| call_ref)
        .collect();
    for call_ref in acknowledged {
        ACKNOWLEDGED_CALLS.delete(&vault.store, wtxn, &call_ref)?;
    }
    Ok(())
}
