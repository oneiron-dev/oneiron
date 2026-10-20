//! FIX 5661 C2b (FIX 6212): the old home's drain. Once its election moves
//! the home away, the old home arms no MACRO timer pass of its own, so a
//! free-time try it already started (a retry, a lease handed back, a park it
//! resumes) would never settle there, and its tables would never go
//! quiescent for the freeze. The host timer arms exactly these tries without
//! its home gate; they run in the host's own pass, under its budgets, the
//! claim's backoff and placement and the operator's pauses, to their own
//! terminal settlement. An item whose try never started stays queued for the
//! move to carry. The connection worker only rechecks quiescence in the
//! final writer and freezes ([`super::freeze_export`]).
//!
//! MACRO consolidation's bucket rule is not a free-time try's, on any node:
//! the timer arms each try this node's admission takes by the claim's own
//! readiness, and never one admission holds back here, so no deadline stands
//! due for work no pass admits.

use std::collections::HashSet;

use super::transfer::draining;
use super::{HomeWrite, store, takes_home_write_in_txn};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::dreamer_runner::{
    DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND, DREAMER_RESIDENT_DREAM_ATTEMPT_KIND,
    free_time_item_waits_unstarted, free_time_line,
};
use crate::error::Result;

/// The free-time tries the host timer arms here, and the ones among them it
/// arms without its home gate. The first set is every free-time try that
/// has not ended, bound to a cycle here (by itself or the try it retries),
/// that this node's admission takes now: one that never started only while
/// C1's guard takes a new admission here. The second is this node's own
/// started tries while it drains its state toward a home move: its election
/// moved the home from this node to another, and it still holds its state.
/// Both are empty where no free-time try waits.
///
/// # Errors
///
/// Storage errors; a retry chain past its bound.
pub(crate) fn free_time_arming(vault: &Vault) -> Result<(HashSet<AttemptId>, HashSet<AttemptId>)> {
    let (candidates, drains) = {
        let txn = vault.store.env.read_txn()?;
        let head = store::head_in_txn(vault, &txn)?;
        let admits = takes_home_write_in_txn(vault, &txn, HomeWrite::Admit)?;
        let drains = head.holds_state() && draining(vault, &txn, &head)?;
        let candidates: Vec<(AttemptId, bool)> = AttemptQueue::new(vault)
            .list_in_txn(&txn)?
            .iter()
            .filter(|record| free_time_try(record))
            .map(|record| (record.id, !free_time_item_waits_unstarted(record)))
            .filter(|(_, started)| *started || admits)
            .collect();
        (candidates, drains)
    };
    let mut tries = HashSet::with_capacity(candidates.len());
    let mut drain = HashSet::new();
    for (attempt, started) in candidates {
        if vault.free_time_item_binding(attempt)?.is_none() {
            continue;
        }
        tries.insert(attempt);
        if started && drains {
            drain.insert(attempt);
        }
    }
    Ok((tries, drain))
}

/// A free-time item's try that has not ended.
fn free_time_try(record: &AttemptRecord) -> bool {
    (record.kind == DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND
        || record.kind == DREAMER_RESIDENT_DREAM_ATTEMPT_KIND)
        && !record.state.is_terminal()
        && free_time_line(record).is_some()
}
