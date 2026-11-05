//! Native agent attribution retained when a call receipt's value is damaged.
use serde::{Deserialize, Serialize};

use super::{CALL_RECEIPTS, CallReceipt};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

const WITNESSES: SideTable<EntityId, AgentWitness, Named> =
    SideTable::new(&side_table::CALL_RECEIPT_AGENT_WITNESS);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentWitness {
    actor: EntityId,
    at: u64,
}

impl AgentWitness {
    fn actor(&self) -> Result<EntityId> {
        EntityId::from_bytes(*self.actor.as_bytes())
    }
}

/// Copies only the identity the primary's side-row wall actually stored.
pub(super) fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    receipt: &CallReceipt,
) -> Result<()> {
    let actor = (receipt.actor_class == "agent")
        .then(|| EntityId::from_hex(&receipt.actor_ref).ok())
        .flatten()
        .filter(|actor| actor.to_hex() == receipt.actor_ref);
    let actor = match actor {
        Some(actor) if vault.local_hard_delete_marker_exists_in_txn(txn, &actor)? => None,
        actor => actor,
    };
    if let Some(actor) = actor {
        WITNESSES.put(
            vault,
            txn,
            id,
            &AgentWitness {
                actor,
                at: receipt.at,
            },
        )?;
    } else {
        WITNESSES.delete(&vault.store, txn, id)?;
    }
    Ok(())
}

/// An unread primary's native agent; an orphan witness never answers alone.
/// Errors leave the caller's original global uncertainty intact.
pub(crate) fn unread_call_receipt_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    if !CALL_RECEIPTS.contains(&vault.store, txn, id)? {
        return Ok(None);
    }
    WITNESSES
        .get(&vault.store, txn, id)?
        .map(|witness| witness.actor())
        .transpose()
}

/// The primary actor scrub calls this only after its own loop succeeds.
pub(super) fn erase_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut erased = Vec::new();
    for row in WITNESSES.iter_from(&vault.store, txn, &[])? {
        let (id, witness) = row?;
        if witness.actor()? == *actor {
            erased.push(id);
        }
    }
    for id in erased {
        WITNESSES.delete(&vault.store, txn, &id)?;
    }
    Ok(())
}
