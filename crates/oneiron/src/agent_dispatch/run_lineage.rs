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

/// Where a settling-lineage walk starts: an actor, or a try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineageStart {
    /// An actor id: an agent's walks up its chains, any other actor's is
    /// itself alone.
    Actor(EntityId),
    /// A try: the agent it dispatched, and the chain above it.
    Attempt(AttemptId),
}

/// The most actors and tries one settling-lineage walk reads before it
/// gives up and answers that the lineage is unknown.
const SETTLING_LINEAGE_LIMIT: usize = 256;

/// Every actor on the chains above `starts`, in `txn` (DEC-0006: "the
/// opener's lineage and its forks never settle their own proposal"): each
/// actor itself; for an agent, the definition its id was born forked from,
/// as the id's pin keeps it across a delete, and the try whose dispatch
/// spawned it as an attenuated fork (FIX 9559); for a try, the agent it
/// dispatched and the try its payload records above it. Two lineages that
/// share an actor are one: a parent, a child and two forks of one parent all
/// meet. No agent's chain reaches the owner, so the owner's lineage is the
/// owner alone.
///
/// `None` when the engine cannot read the lineage whole: a shell's pin that
/// has not named its parent, a try the chain names that the queue no longer
/// holds or whose payload does not decode, or more than
/// [`SETTLING_LINEAGE_LIMIT`] actors and tries. A caller counts an unknown
/// lineage as the opener's, as FIX 10693 does for frozen credential chains.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn settling_lineage_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    starts: &[LineageStart],
) -> Result<Option<std::collections::BTreeSet<EntityId>>> {
    let queue = AttemptQueue::new(vault);
    let mut actors = std::collections::BTreeSet::new();
    let mut tries = std::collections::BTreeSet::new();
    let mut pending = starts.to_vec();
    while let Some(next) = pending.pop() {
        match next {
            LineageStart::Actor(actor) => {
                if !actors.insert(actor) {
                    continue;
                }
                match crate::agent_def::born_lineage_in_txn(&vault.store, txn, &actor)? {
                    crate::agent_def::BornLineage::Born(parent) => {
                        pending.extend(parent.map(LineageStart::Actor));
                    }
                    crate::agent_def::BornLineage::NoAgent => {}
                    crate::agent_def::BornLineage::Unread => return Ok(None),
                }
                if let Some(spawn) =
                    crate::agent_def::delegation_parent_in_txn(&vault.store, txn, &actor)?
                {
                    pending.push(LineageStart::Attempt(spawn));
                }
            }
            LineageStart::Attempt(attempt) => {
                if !tries.insert(attempt) {
                    continue;
                }
                let Some(row) = queue.get_in_txn(txn, attempt)? else {
                    return Ok(None);
                };
                let Ok(payload) = decode_dreamer_attempt_payload(&row.payload) else {
                    return Ok(None);
                };
                if let Some(target) = super::record_dispatch_input(&row)
                    .and_then(|input| input.target.agent_definition_ref().ok())
                {
                    pending.push(LineageStart::Actor(target));
                }
                pending.extend(payload.parent_attempt.map(LineageStart::Attempt));
            }
        }
        if actors.len() + tries.len() > SETTLING_LINEAGE_LIMIT {
            return Ok(None);
        }
    }
    Ok(Some(actors))
}
