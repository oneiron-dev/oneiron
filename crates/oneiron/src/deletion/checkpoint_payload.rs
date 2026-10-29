//! The deletion side of the checkpoint payload compartments (KS7-4, FIX
//! 5688): which compartments a deleted entity owns, and what its delete
//! reason does to them.
//!
//! An entity owns its own tree's compartment and the compartment of every
//! attachment occurrence it holds (owner: its id, then the occurrence's). An
//! outbound call's compartment belongs to the call, not to an entity, and
//! goes with its payload's erase in the intent ledger. A code document has
//! no owner erase door yet, so its compartments stay until one exists
//! (Engine 10-20 08:4x, ruling 4). Nothing here refuses: the delete commits
//! as it does today, and while KS-7 is off nothing is touched.

use heed::RwTxn;

use super::tombstone::TombstoneReason;
use super::topology_delete_intent::topology_delete_reservation_in_txn;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::retirement::{PayloadDisposition, settle_owner_in_txn};

/// The compartment kinds an entity owns, each found by the entity's id at
/// the start of its owner bytes.
const ENTITY_OWNED: [Subtype; 2] = [Subtype::EntityTree, Subtype::AttachmentOccurrence];

/// What a delete under `reason` does to its owner's compartments. A reason
/// that did not decode (a legacy, reserved or unknown wire byte) keeps them:
/// an erase is never inferred (Engine 10-20 08:4x, ruling 1).
const fn disposition(reason: Option<TombstoneReason>) -> PayloadDisposition {
    match reason {
        Some(reason) if reason.erases_checkpoint_payloads() => PayloadDisposition::Erase,
        _ => PayloadDisposition::Retain,
    }
}

/// Settles the compartments `id` owns in `wtxn`, the erase transaction that
/// tears it, by the reason its topology delete reservation names: the
/// reservation of `request_id` when the purge knows its request, else the
/// one standing for `id`, which the door wrote earlier in this transaction.
/// An erase marks every incarnation erased and stages each leaf's retirement
/// for the finisher after the commit
/// ([`Store::finish_checkpoint_payload_retirements_after_commit`]); any
/// other delete, and one with no reservation (a remote tombstone's replay),
/// keeps the leaves and retains the active incarnation.
///
/// # Errors
///
/// Storage faults, a reservation or an incarnation row that does not decode.
pub(crate) fn settle_checkpoint_payloads_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    request_id: Option<&[u8; 16]>,
) -> Result<()> {
    let reason = topology_delete_reservation_in_txn(store, wtxn, id)?
        .filter(|reserved| request_id.is_none_or(|request| reserved.request_id == *request))
        .map(|reserved| reserved.reason);
    let disposition = disposition(reason);
    for subtype in ENTITY_OWNED {
        settle_owner_in_txn(store, wtxn, subtype, id.as_bytes(), disposition)?;
    }
    Ok(())
}
