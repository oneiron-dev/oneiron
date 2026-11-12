//! Waking typed budget trap parks: in the spend scope top-up transaction, at a wake pass's start,
//! in the owner's resident share write, and at the owner's release of the park.

use crate::Vault;
use crate::agent_dispatch::{AgentDispatcher, SpendScopeId};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::{DreamerParkWait, PARKED, ParkResumer, TRAP_PARK_OWNER_PREFIX};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::budget::resident_share_frees;
use crate::llm::run_admission::ResidentShare;

use super::codec::invalid_trap;
use super::trap::{TrapConsumePrecheck, trap_consume_precheck_in_txn, wake_trap_in_txn};
use super::trap_binding::trap_binding_read_in_txn;
use super::types::{DreamerTrapKind, TrapRef};

/// Signals and consumes budget traps whose named scope now covers the units their reservation
/// asked of it: a spend scope's `Budget` wait, and a `PassBudget` wait that names the scope (a
/// free-time item's step, whose pass also wakes it).
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
        let (waiting_scope, asked_units) = match &wait.wait {
            DreamerParkWait::Budget { scope, asked_units }
            | DreamerParkWait::PassBudget {
                scope: Some(scope),
                asked_units,
            } => (scope, asked_units),
            _ => continue,
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

/// Wakes, at a wake pass's start, the pass budget parks of the tries `lease_owner` holds that the
/// pass's guard has room for: `room_units` is that guard's remaining units. Parks are taken oldest
/// first, and each woken park takes its asked units from the room, so the pass wakes no more than
/// it can hold. A park the room no longer covers, a stale or broken park, or one under another
/// lease owner stays parked; none fails the pass. Returns the tries woken, as the same tries,
/// admissible in this pass (BUDGET-TRAP-UNTYPED-NO-SENDER).
pub(crate) fn wake_pass_budget_traps(
    vault: &Vault,
    lease_owner: &str,
    room_units: u64,
    now_ms: u64,
) -> Result<Vec<AttemptId>> {
    let woken = vault.with_write_txn_grouped(|wtxn| {
        wake_pass_budget_traps_in_txn(vault, wtxn, lease_owner, room_units, now_ms)
    })?;
    if !woken.is_empty() {
        vault.store.notify_attempt_observers();
        vault.store.notify_proactivity_changes();
    }
    Ok(woken)
}

fn wake_pass_budget_traps_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    lease_owner: &str,
    room_units: u64,
    now_ms: u64,
) -> Result<Vec<AttemptId>> {
    let queue = AttemptQueue::new(vault);
    // Materialize the scan before waking: consuming a trap deletes its parked row.
    let mut parks = Vec::new();
    for (_, record) in PARKED.scan(&vault.store, wtxn)? {
        let Some(wait) = &record.wait else {
            continue;
        };
        let DreamerParkWait::PassBudget { asked_units, .. } = &wait.wait else {
            continue;
        };
        parks.push((*asked_units, wait.lease_generation, record));
    }
    parks.sort_by_key(|(_, _, record)| (record.parked_at, *record.attempt_id.as_bytes()));
    let mut room = room_units;
    let mut woken = Vec::new();
    for (asked_units, lease_generation, record) in parks {
        if asked_units > room {
            continue;
        }
        if !record.resumable_by(ParkResumer::PassStart) {
            tracing::info!(attempt = ?record.attempt_id, "pass start skipped a park that does not admit it");
            continue;
        }
        let Some(attempt) = queue.get_in_txn(wtxn, record.attempt_id)? else {
            tracing::info!(attempt = ?record.attempt_id, "pass start skipped an orphan park");
            continue;
        };
        if attempt.lease_owner.as_deref() != Some(lease_owner) {
            continue;
        }
        if !attempt.state.is_running() || attempt.attempt_count != lease_generation {
            tracing::info!(attempt = ?record.attempt_id, "pass start skipped a stale park lease");
            continue;
        }
        match wake_budget_trap_of_park_in_txn(vault, wtxn, &record.park_owner, now_ms)? {
            Some(attempt) => {
                room = room.saturating_sub(asked_units);
                woken.push(attempt);
            }
            None => {
                tracing::info!(attempt = ?record.attempt_id, park_owner = %record.park_owner, "pass start found no trap to wake for a park");
            }
        }
    }
    Ok(woken)
}

/// Wakes, in the owner's share write for `resident`, the budget traps of the resident's steps
/// parked on its spent pinned share that `share` frees (D3): an unpinned share, the default
/// split, or a pinned share in units from the share the refused call needed. A share still
/// short, another resident's park, and a stale or broken park stay parked; none fails the
/// owner's write. Returns the tries woken.
pub(crate) fn wake_resident_share_traps_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    resident: EntityId,
    share: ResidentShare,
    now_ms: u64,
) -> Result<Vec<AttemptId>> {
    let queue = AttemptQueue::new(vault);
    let mut woken = Vec::new();
    // Materialize the scan before waking: consuming a trap deletes its parked row.
    for (_, record) in PARKED.scan(&vault.store, wtxn)? {
        let Some(wait) = &record.wait else {
            continue;
        };
        let DreamerParkWait::ResidentShare {
            resident: waiting,
            needed_units,
        } = &wait.wait
        else {
            continue;
        };
        if *waiting != resident || !resident_share_frees(share, *needed_units) {
            continue;
        }
        if !record.resumable_by(ParkResumer::ResidentShareRaise) {
            tracing::info!(attempt = ?record.attempt_id, "resident share write skipped a park that does not admit it");
            continue;
        }
        let Some(attempt) = queue.get_in_txn(wtxn, record.attempt_id)? else {
            tracing::info!(attempt = ?record.attempt_id, "resident share write skipped an orphan park");
            continue;
        };
        if !attempt.state.is_running() || attempt.attempt_count != wait.lease_generation {
            tracing::info!(attempt = ?record.attempt_id, "resident share write skipped a stale park lease");
            continue;
        }
        match wake_budget_trap_of_park_in_txn(vault, wtxn, &record.park_owner, now_ms)? {
            Some(attempt) => woken.push(attempt),
            None => {
                tracing::info!(attempt = ?record.attempt_id, park_owner = %record.park_owner, "resident share write found no trap to wake for a park");
            }
        }
    }
    Ok(woken)
}

/// Wakes the budget trap a park under `park_owner` waits at, in the caller's write: the owner's
/// release of a trap-owned budget park, and a pass start's wake. `None` for a park owner that
/// names no trap, a trap whose binding is gone, a trap an earlier wake reached, or a broken park.
pub(crate) fn wake_budget_trap_of_park_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    park_owner: &str,
    now_ms: u64,
) -> Result<Option<AttemptId>> {
    let Some(anchor) = trap_anchor(park_owner) else {
        return Ok(None);
    };
    let Some(binding) = trap_binding_read_in_txn(vault, wtxn, &anchor)? else {
        return Ok(None);
    };
    let trap = TrapRef {
        trap_claim_id: anchor,
        kind: DreamerTrapKind::Budget,
        step_hash: binding.step_hash,
    };
    wake_budget_trap_in_txn(vault, wtxn, &trap, now_ms)
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
