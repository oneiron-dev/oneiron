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
#![allow(
    dead_code,
    reason = "the erase doors' purge calls these (KS7-4a); CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

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

/// Settles the compartments `id` owns for its delete under `reason`, in
/// `wtxn`, the transaction that tears it: an erase marks every incarnation
/// erased and stages each leaf's retirement for the finisher after the
/// commit ([`Store::finish_checkpoint_payload_retirements_after_commit`]);
/// an ordinary delete keeps the leaves and retains the active incarnation.
/// Runs whether or not live rows remained, since old checkpoints may still
/// hold the owner.
///
/// # Errors
///
/// Storage faults, and an incarnation row that does not decode.
pub(crate) fn settle_deleted_owner_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    reason: Option<TombstoneReason>,
) -> Result<()> {
    let disposition = disposition(reason);
    for subtype in ENTITY_OWNED {
        settle_owner_in_txn(store, wtxn, subtype, id.as_bytes(), disposition)?;
    }
    Ok(())
}

/// The reason a local delete of `id` committed under `request_id`, read from
/// the topology delete reservation the delete's door writes in its own
/// transaction before it tears: for a purge that knows its request but not
/// its reason. `None` when no reservation of that request stands (a remote
/// tombstone's replay names its reason itself).
///
/// # Errors
///
/// Storage faults, and a reservation that does not decode.
pub(crate) fn reserved_delete_reason_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    request_id: Option<&[u8; 16]>,
) -> Result<Option<TombstoneReason>> {
    let Some(request_id) = request_id else {
        return Ok(None);
    };
    Ok(topology_delete_reservation_in_txn(store, txn, id)?
        .filter(|reserved| reserved.request_id == *request_id)
        .map(|reserved| reserved.reason))
}
