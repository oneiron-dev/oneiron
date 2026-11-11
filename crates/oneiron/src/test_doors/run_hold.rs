//! Doors for `tests/run_hold_doors.rs` (RUN-HOLD): the hook hold the verb-hook
//! runtime writes, the override records, and the row deletion and actor
//! erasure those records join.

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptResumePoint,
    HoldAttemptForHook, InterveneAttempt, InterveneOutcome,
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

/// A `kind` intervention on `id` by `actor`, a caller other than the vault
/// owner, as run control runs one for a TASK's owner or the host (Fable 5.2
/// item 2): `Ok(Err(code))` when a hold refuses it, the reason code of the
/// signal the row waits on; nothing is written then.
pub fn intervene_as_caller(
    vault: &Vault,
    id: AttemptId,
    kind: AttemptInterventionKind,
    actor: &str,
    now: u64,
) -> Result<std::result::Result<InterveneOutcome, &'static str>> {
    let mut wtxn = vault.store.env.write_txn()?;
    match AttemptQueue::new(vault).intervene_as_caller_in_txn(
        &mut wtxn,
        InterveneAttempt {
            id,
            kind,
            actor: actor.to_owned(),
            note: None,
            now,
        },
    )? {
        Ok(outcome) => {
            wtxn.commit()?;
            Ok(Ok(outcome))
        }
        Err(signal) => Ok(Err(signal.reason_code())),
    }
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

/// The tables whose rows record who overrode a hold.
const RUN_HOLD_TABLES: [&str; 3] = [
    "ATTEMPT_HOLD_OVERRIDE",
    "TASK_FANOUT_LAUNCH",
    "AGENT_DISPATCH_PLAN_HOLD",
];

/// The part of `actor`'s erase that runs over the override records: the
/// actor scrub each of [`RUN_HOLD_TABLES`] registers, as an erase and a
/// restore's rerun run it. Returns how many of those tables registered one.
pub fn erase_actor_in_run_hold_tables(vault: &Vault, actor: &EntityId) -> Result<usize> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut ran = 0;
    for (decl, scrub) in crate::side_table::actor_scrubs() {
        if RUN_HOLD_TABLES.contains(&decl.name) {
            scrub(vault, &mut wtxn, actor)?;
            ran += 1;
        }
    }
    wtxn.commit()?;
    Ok(ran)
}

/// The actors of the planner releases recorded on the fan-out launch
/// `launch_ref`, in order.
pub fn launch_override_actors(vault: &Vault, launch_ref: EntityId) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    crate::task_verb::launch_override_actors_in_txn(vault, &rtxn, launch_ref)
}
