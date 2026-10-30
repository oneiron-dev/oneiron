//! The store-only lineage step the Gate's delegation-chain read takes at each
//! write of a delegated run (FIX 10537, L09 s50 10:4x): the same reads
//! [`super::AgentDispatcher`]'s dispatch-time chain walk takes, with no
//! dispatcher bound.

use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// The attempt above `row`, whose dispatch targets `target`, on its
/// delegation chain: the target's pinned delegation parent, else the
/// attempt's recorded parent, a workflow wrapper crossed to the wrapper's own
/// recorded parent (which the wrapper's admission keeps equal to its
/// intent's). `None` where the chain ends: no parent, or a recorded parent
/// that is gone.
///
/// # Errors
///
/// Storage errors reading the pin or the parent's row.
pub(crate) fn delegation_lineage_parent_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
    target: EntityId,
) -> Result<Option<AttemptId>> {
    if let Some(parent) = crate::agent_def::delegation_parent_in_txn(store, txn, &target)? {
        return Ok(Some(parent));
    }
    let Some(recorded) = recorded_parent(row) else {
        return Ok(None);
    };
    let Some(parent_row) = AttemptQueue::from_store(store).get_in_txn(txn, recorded)? else {
        return Ok(None);
    };
    if !super::workflow_record::is_wrapper(&parent_row) {
        return Ok(Some(recorded));
    }
    Ok(recorded_parent(&parent_row))
}

/// The parent `row`'s payload records, `None` when it records none or does
/// not decode.
fn recorded_parent(row: &AttemptRecord) -> Option<AttemptId> {
    decode_dreamer_attempt_payload(&row.payload)
        .ok()
        .and_then(|payload| payload.parent_attempt)
}
