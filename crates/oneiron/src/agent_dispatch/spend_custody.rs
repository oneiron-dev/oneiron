//! The custody machine's settlement of handed-over runs (FIX 4889).
//!
//! A run whose launch this machine's tree funded keeps its scope here while
//! it runs elsewhere (canon ARCH-0026: the budget counter is single-writer
//! and home-node-owned; a move carries no budget). When the run ends on
//! another machine, its TASK carries the outcome and every machine's share;
//! the custody machine folds what the other machines spent into the scope
//! and settles it. Its own try's stand-down does that when it finds the run
//! settled elsewhere; the reconcile pass on the server's housekeeping tick,
//! before the agent run reaper, does it for a run with no try left here.
//! Both are idempotent: a second pass finds the scope settled and does
//! nothing.
//!
//! A hold is no spend (REVIEW-7890): while the run's last executor still
//! holds units for children that outlived the run, the scope stays open and
//! its parent goes on holding the carve. Those children settle on that
//! machine, whose reconcile pass stamps its shares on the settled TASK again
//! (it is the TASK's one writer), and the custody machine settles once no
//! such hold is left.

use super::run_handover::local_agent_run_tries_in;
use super::run_task::{
    AgentRunSpendCarry, attempt_id_from_hex, own_spend_shares_stale_in, settled_agent_runs_in,
    update_agent_run_task_body_in_txn,
};
use super::spend_record::{SCOPE, SpendScope, SpendState};
use super::{AgentDispatchInput, AgentDispatcher};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;

/// What reserving a handed-over launch came to (FIX 4889): whether the take
/// may run here, and how much of what the other machines committed it folded
/// into the kept scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandedOverLaunchReserve {
    /// This machine cannot fund the run as its launch was stated: the take
    /// writes nothing, and the run waits.
    Unfunded,
    /// The run is funded here. `folded` is what the take folded into the kept
    /// scope, 0 for a new scope or a kept scope that needed no fold.
    Reserved { folded: u64 },
}

/// How the custody machine settles its scope of a run that ended (FIX 4889).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CustodySettle {
    /// The scope folds the `fold` units the other machines spent of the run
    /// that it has not folded yet, and settles into its parent.
    Now { fold: u64 },
    /// The run's last executor, another machine, still holds units for
    /// children that outlived the run (REVIEW-7890): the scope stays open, so
    /// its parent goes on holding the carve, until that machine's stamp
    /// shows them settled.
    Waits,
}

/// A run the reconcile pass settles (FIX 4889): the try whose scope is the
/// custody scope, and what the other machines spent of it that is not folded
/// yet.
struct CustodySettlement {
    attempt: AttemptId,
    fold: u64,
}

/// What one reconcile pass writes, read in one snapshot (FIX 4889).
#[derive(Default)]
struct ReconcileDue {
    /// The settled runs in this machine's custody whose scope here settles.
    settle: Vec<CustodySettlement>,
    /// The settled runs in another machine's custody that this machine ran
    /// last, whose shares here moved since its last stamp (REVIEW-7890).
    restamp: Vec<EntityId>,
}

/// What the reconcile pass owes the settled runs, read in `txn` (FIX 4889):
/// each run in this machine's custody whose scope here is still open, with
/// no try pending here and no hold its last executor keeps for children that
/// outlived it, settles; a run with a try pending here settles at that try's
/// own stand-down instead. Each run in another machine's custody that this
/// machine ran last stamps its shares again once a scope here moved
/// (REVIEW-7890), as a child that outlived it settled.
fn reconcile_due_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ReconcileDue> {
    let mut due = ReconcileDue::default();
    let Some(node) = crate::identity::read_client_id_in_txn(vault, txn)? else {
        return Ok(due);
    };
    let settled = settled_agent_runs_in(vault, txn)?;
    if settled.is_empty() {
        return Ok(due);
    }
    let local = local_agent_run_tries_in(vault, txn)?;
    let dispatcher = AgentDispatcher::new(vault);
    for (task_ref, body) in settled {
        let Some(carry) = body.spend.as_ref() else {
            continue;
        };
        if carry.custody_node != node {
            if body.executor.node_id == node && own_spend_shares_stale_in(vault, txn, &body)? {
                due.restamp.push(task_ref);
            }
            continue;
        }
        if local.contains_key(&task_ref) {
            continue;
        }
        let Some(attempt) = attempt_id_from_hex(&body.attempt_ref) else {
            continue;
        };
        let open = dispatcher
            .attempt_spend_scope_in_txn(txn, attempt)?
            .is_some_and(|scope| scope.state == SpendState::Open);
        if !open {
            continue;
        }
        if let CustodySettle::Now { fold } = carry.custody_settle(node, body.executor.node_id) {
            due.settle.push(CustodySettlement { attempt, fold });
        }
    }
    Ok(due)
}

impl AgentDispatcher<'_> {
    /// Judges for a take the open scope `kept` that `attempt` spends under
    /// here through its retry chain (FIX 4889). On the custody machine
    /// (`carry` names `node`) the scope folds what the other machines spent
    /// of the run and it did not fold yet, and the take waits when that, with
    /// what their open children hold (REVIEW-7890: a hold fills the room but
    /// never folds), fills its cap. Elsewhere the run may commit under `kept` what its
    /// launch reserved less what was committed outside it, this machine's
    /// other scopes included: the take waits when `kept` committed that
    /// already, and a pinned scope's cap comes down to it (a carve keeps its
    /// cap, which its parent holds).
    pub(super) fn keep_handed_over_scope_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        kept: SpendScope,
        input: &AgentDispatchInput,
        carry: Option<&AgentRunSpendCarry>,
        node: u64,
    ) -> Result<HandedOverLaunchReserve> {
        if let Some(carry) = carry.filter(|carry| carry.custody_node == node) {
            let fold = carry.unfolded_spend_elsewhere(node);
            let held_elsewhere = carry.held_elsewhere(node);
            return Ok(
                match self.fold_handed_over_spend_in_txn(txn, attempt, fold)? {
                    Some(folded)
                        if folded
                            .spent_units
                            .saturating_add(folded.held_units)
                            .saturating_add(held_elsewhere)
                            >= folded.cap_units =>
                    {
                        HandedOverLaunchReserve::Unfunded
                    }
                    Some(_) => HandedOverLaunchReserve::Reserved { folded: fold },
                    None => HandedOverLaunchReserve::Reserved { folded: 0 },
                },
            );
        }
        let base = input.launch.as_ref().and_then(|statement| {
            if statement.parent_scope.is_some() {
                Some(statement.reserved_units)
            } else {
                statement.cap_units
            }
        });
        let Some(base) = base else {
            return Ok(HandedOverLaunchReserve::Reserved { folded: 0 });
        };
        let committed_outside = carry.map_or(0, |carry| carry.committed_except(node, &kept.scope));
        let remaining = base.saturating_sub(committed_outside);
        if remaining <= kept.spent_units.saturating_add(kept.held_units) {
            return Ok(HandedOverLaunchReserve::Unfunded);
        }
        if kept.parent.is_none() && remaining < kept.cap_units {
            let mut lowered = kept;
            lowered.cap_units = remaining;
            SCOPE.put(&self.vault.store, txn, &lowered.scope.0, &lowered)?;
        }
        Ok(HandedOverLaunchReserve::Reserved { folded: 0 })
    }

    /// Settles the custody scope of the run whose try is `attempt`, in the
    /// caller's write (FIX 4889): folds the `fold` units the other machines
    /// spent of it into the scope and settles the scope into its parent. A
    /// scope that is no longer open takes no fold. The settled run TASK is
    /// left as it is (REVIEW-7890): its last executor is its one writer, as
    /// a TASK two machines write resolves by whole-row LWW, and the closed
    /// scope takes no second fold.
    pub(super) fn settle_custody_scope_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        fold: u64,
        now: u64,
    ) -> Result<()> {
        self.fold_handed_over_spend_in_txn(txn, attempt, fold)?;
        self.settle_child_in_txn(txn, &attempt, now)?;
        Ok(())
    }
}

impl Vault {
    /// Settles each handed-over run this machine holds custody of that ended
    /// on another machine and has no try left here (FIX 4889): its scope
    /// folds what the other machines spent and settles into its parent. A
    /// run whose last executor still holds units for children that outlived
    /// it waits (REVIEW-7890). Each settled run in another machine's custody
    /// that this machine ran last gets this machine's shares stamped again
    /// once a scope here moved, so its custody machine reads what such a
    /// child spent. A read finds the runs first; the write runs only when one
    /// is due, and judges each again. Returns how many runs it settled or
    /// stamped. Idempotent: a second pass finds the scopes settled and the
    /// shares stamped, and does nothing.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn reconcile_handed_over_spend(&self) -> Result<usize> {
        let due = {
            let rtxn = self.store.env.read_txn()?;
            reconcile_due_in(self, &rtxn)?
        };
        if due.settle.is_empty() && due.restamp.is_empty() {
            return Ok(0);
        }
        let now = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let due = reconcile_due_in(self, &*txn)?;
            let dispatcher = AgentDispatcher::new(self);
            for run in &due.settle {
                dispatcher.settle_custody_scope_in_txn(txn, run.attempt, run.fold, now)?;
            }
            for task_ref in &due.restamp {
                // An update that changes nothing else: the executor's own
                // stamp in it writes the moved shares (FIX 4889).
                update_agent_run_task_body_in_txn(self, txn, *task_ref, now, |_| Ok(()))?;
            }
            Ok(due.settle.len().saturating_add(due.restamp.len()))
        })
    }
}
