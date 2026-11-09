//! Doors for `tests/run_hold_doors.rs` (RUN-HOLD): the hook hold the verb-hook
//! runtime writes, the hold override record, and the row deletion and actor
//! scrub that override records join.

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResumePoint, HoldAttemptForHook,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// Parks the leased row `id` on the verb hook `invocation`, as the hook
/// runtime does when a hook asks before the step runs.
pub fn hold_for_hook(
    vault: &Vault,
    id: AttemptId,
    lease_owner: &str,
    attempt_count: u32,
    invocation: [u8; 16],
    resume_point: AttemptResumePoint,
    now: u64,
) -> Result<AttemptRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let record = AttemptQueue::new(vault).hold_for_hook_in_txn(
        &mut wtxn,
        HoldAttemptForHook {
            id,
            lease_owner: lease_owner.to_owned(),
            attempt_count,
            invocation,
            resume_point,
            now,
        },
    )?;
    wtxn.commit()?;
    Ok(record)
}

/// The actor of `id`'s hold override record; `None` when it has none.
pub fn hold_override_actor(vault: &Vault, id: AttemptId) -> Result<Option<String>> {
    let rtxn = vault.store.env.read_txn()?;
    crate::attempt_queue::hold_override_actor_in_txn(&vault.store, &rtxn, id)
}

/// Deletes every row of `kind` with its entries, as an open drops a kind no
/// executor serves. Returns how many rows went.
pub fn drop_kind(vault: &Vault, kind: &str) -> Result<usize> {
    let mut wtxn = vault.store.env.write_txn()?;
    let dropped = AttemptQueue::new(vault).drop_kind_in_txn(&mut wtxn, kind)?;
    wtxn.commit()?;
    Ok(dropped)
}

/// The override records' part of an actor erasure: every record `actor`
/// made loses its actor.
pub fn scrub_hold_override_actor(vault: &Vault, actor: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    crate::attempt_queue::scrub_hold_override_actor_in_txn(&vault.store, &mut wtxn, actor)?;
    wtxn.commit()?;
    Ok(())
}
