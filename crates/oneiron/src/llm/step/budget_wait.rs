//! Waking typed budget trap parks in the spend scope top-up transaction.

use crate::Vault;
use crate::agent_dispatch::{AgentDispatcher, SpendScopeId};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::{DreamerParkWait, PARKED, ParkResumer, TRAP_PARK_OWNER_PREFIX};
use crate::entity_id::EntityId;
use crate::error::Result;

use super::codec::invalid_trap;
use super::trap::{TrapConsumePrecheck, trap_consume_precheck_in_txn, wake_trap_in_txn};
use super::trap_binding::trap_binding_read_in_txn;
use super::types::{DreamerTrapKind, TrapRef};

/// Signals and consumes budget traps whose named scope now covers the units their reservation
/// asked of it.
pub(crate) fn wake_budget_traps_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &SpendScopeId,
    now_ms: u64,
) -> Result<Vec<AttemptId>> {
    let dispatcher = AgentDispatcher::new(vault);
    let queue = AttemptQueue::new(vault);
    let mut resumed = Vec::new();
    // Materialize the scan before waking: consuming a trap deletes its parked row.
    for (_, record) in PARKED.scan(&vault.store, wtxn)? {
        let Some(wait) = &record.wait else {
            continue;
        };
        let DreamerParkWait::Budget {
            scope: waiting_scope,
            asked_units,
        } = &wait.wait
        else {
            continue;
        };
        if waiting_scope != scope {
            continue;
        }
        if !record.resumable_by(ParkResumer::BudgetTopUp) {
            tracing::info!(attempt = ?record.attempt_id, "budget top-up skipped a park that does not admit it");
            continue;
        }
        let Some(attempt) = queue.get_in_txn(wtxn, record.attempt_id)? else {
            tracing::info!(attempt = ?record.attempt_id, "budget top-up skipped an orphan park");
            continue;
        };
        if !attempt.state.is_running() || attempt.attempt_count != wait.lease_generation {
            tracing::info!(attempt = ?record.attempt_id, "budget top-up skipped a stale park lease");
            continue;
        }
        if dispatcher.available_units_in_txn(wtxn, scope)? < *asked_units {
            tracing::info!(attempt = ?record.attempt_id, "budget top-up left too little room for the parked reservation");
            continue;
        }
        let Some(anchor) = trap_anchor(&record.park_owner) else {
            tracing::info!(attempt = ?record.attempt_id, park_owner = %record.park_owner, "budget top-up skipped an invalid trap park owner");
            continue;
        };
        let binding = trap_binding_read_in_txn(vault, wtxn, &anchor)?
            .ok_or_else(|| invalid_trap("dreamer trap binding missing"))?;
        let trap = TrapRef {
            trap_claim_id: anchor,
            kind: DreamerTrapKind::Budget,
            step_hash: binding.step_hash,
        };
        if let Some(attempt) = wake_budget_trap_in_txn(vault, wtxn, &trap, now_ms)? {
            resumed.push(attempt);
        }
    }
    Ok(resumed)
}

/// Signals and consumes one budget trap in the caller's write, after the
/// read-only consume precheck: the top-up's wake of each covered park, and a
/// park's own wake when its cap moved before it landed. `None` for a trap an
/// earlier wake reached, or a broken park the precheck skips.
pub(super) fn wake_budget_trap_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    trap: &TrapRef,
    now_ms: u64,
) -> Result<Option<AttemptId>> {
    match trap_consume_precheck_in_txn(vault, wtxn, trap)? {
        TrapConsumePrecheck::Proceed => wake_trap_in_txn(vault, wtxn, trap, now_ms),
        TrapConsumePrecheck::Skip {
            reason,
            attempt_id,
            park_owner,
        } => {
            tracing::info!(?reason, attempt = ?attempt_id, %park_owner, "budget trap wake skipped a broken trap park");
            Ok(None)
        }
    }
}

fn trap_anchor(park_owner: &str) -> Option<EntityId> {
    let hex = park_owner.strip_prefix(TRAP_PARK_OWNER_PREFIX)?;
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    EntityId::from_hex(hex).ok()
}
