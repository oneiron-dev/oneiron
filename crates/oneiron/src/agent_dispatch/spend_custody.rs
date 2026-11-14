//! The custody machine's settlement of handed-over runs (FIX 4889).
//!
//! A run whose launch this machine's tree funded keeps its scope here while
//! it runs elsewhere (canon ARCH-0026: the budget counter is single-writer
//! and home-node-owned; a move carries no budget). When the run ends on
//! another machine, its TASK carries the outcome and every machine's share;
//! the custody machine folds the other shares into the scope, settles it,
//! and records the fold on the TASK. Its own try's stand-down does that when
//! it finds the run settled elsewhere; the reconcile pass on the server's
//! housekeeping tick, before the agent run reaper, does it for a run with no
//! try left here. Both are idempotent: a second pass finds the scope settled
//! and does nothing.

use super::run_handover::local_agent_run_tries_in;
use super::run_task::{
    AgentRunSpendCarry, attempt_id_from_hex, settled_agent_runs_in,
    update_agent_run_task_body_in_txn,
};
use super::spend_record::{SCOPE, SpendScope, SpendState};
use super::{AgentDispatchInput, AgentDispatcher};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;

/// What reserving a handed-over launch came to (FIX 4889): whether the take
/// may run here, and how much of the other machines' spend it folded into the
/// kept scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandedOverLaunchReserve {
    /// This machine cannot fund the run as its launch was stated: the take
    /// writes nothing, and the run waits.
    Unfunded,
    /// The run is funded here. `folded` is what the take folded into the kept
    /// scope, 0 for a new scope or a kept scope that needed no fold.
    Reserved { folded: u64 },
}

/// A run the reconcile pass settles (FIX 4889): its TASK, the try whose
/// scope is the custody scope, and what the other machines spent of it that
/// is not folded yet.
struct CustodySettlement {
    task_ref: EntityId,
    attempt: AttemptId,
    fold: u64,
}

/// The settled runs in this machine's custody whose scope here is still
/// open and with no try pending here, read in `txn` (FIX 4889). A run with
/// a try pending here settles at that try's own stand-down instead.
fn custody_settlements_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<CustodySettlement>> {
    let Some(node) = crate::identity::read_client_id_in_txn(vault, txn)? else {
        return Ok(Vec::new());
    };
    let settled = settled_agent_runs_in(vault, txn)?;
    if settled.is_empty() {
        return Ok(Vec::new());
    }
    let local = local_agent_run_tries_in(vault, txn)?;
    let dispatcher = AgentDispatcher::new(vault);
    let mut due = Vec::new();
    for (task_ref, body) in settled {
        let Some(carry) = body.spend.as_ref() else {
            continue;
        };
        if carry.custody_node != node || local.contains_key(&task_ref) {
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
        due.push(CustodySettlement {
            task_ref,
            attempt,
            fold: carry
                .spent_elsewhere(node)
                .saturating_sub(carry.custody_folded_units),
        });
    }
    Ok(due)
}

impl AgentDispatcher<'_> {
    /// Judges for a take the open scope `kept` that `attempt` spends under
    /// here through its retry chain (FIX 4889). On the custody machine
    /// (`carry` names `node`) the scope folds what the other machines spent
    /// of the run and it did not fold yet, and the take waits when that
    /// fills its cap. Elsewhere the run may spend here what its launch
    /// reserved less what the other machines spent: the take waits when this
    /// machine spent that already, and a pinned scope's cap comes down to it
    /// (a carve keeps its cap, which its parent holds).
    pub(super) fn keep_handed_over_scope_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        kept: SpendScope,
        input: &AgentDispatchInput,
        carry: Option<&AgentRunSpendCarry>,
        node: u64,
    ) -> Result<HandedOverLaunchReserve> {
        let spent_elsewhere = carry.map_or(0, |carry| carry.spent_elsewhere(node));
        if let Some(carry) = carry.filter(|carry| carry.custody_node == node) {
            let fold = spent_elsewhere.saturating_sub(carry.custody_folded_units);
            return Ok(
                match self.fold_handed_over_spend_in_txn(txn, attempt, fold)? {
                    Some(folded) if folded.spent_units >= folded.cap_units => {
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
        let remaining = base.saturating_sub(spent_elsewhere);
        if remaining <= kept.spent_units {
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
    /// spent of it into the scope, settles the scope into its parent, and
    /// records the fold on the run TASK `task_ref`. A scope that is no longer
    /// open takes no fold, so none is recorded.
    pub(super) fn settle_custody_scope_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        task_ref: EntityId,
        fold: u64,
        now: u64,
    ) -> Result<()> {
        let folded = self.fold_handed_over_spend_in_txn(txn, attempt, fold)?;
        self.settle_child_in_txn(txn, &attempt, now)?;
        if fold != 0 && folded.is_some() {
            update_agent_run_task_body_in_txn(self.vault, txn, task_ref, now, |body| {
                if let Some(carry) = body.spend.as_mut() {
                    carry.custody_folded_units = carry.custody_folded_units.saturating_add(fold);
                }
                Ok(())
            })?;
        }
        Ok(())
    }
}

impl Vault {
    /// Settles each handed-over run this machine holds custody of that ended
    /// on another machine and has no try left here (FIX 4889): its scope
    /// folds the other machines' shares, settles into its parent, and the
    /// fold lands on its TASK. A read finds the runs first; the write runs
    /// only when one is due, and judges each again. Returns how many runs it
    /// settled. Idempotent: a second pass finds the scopes settled and does
    /// nothing.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn reconcile_handed_over_spend(&self) -> Result<usize> {
        let due = {
            let rtxn = self.store.env.read_txn()?;
            custody_settlements_in(self, &rtxn)?
        };
        if due.is_empty() {
            return Ok(0);
        }
        let now = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let due = custody_settlements_in(self, &*txn)?;
            let dispatcher = AgentDispatcher::new(self);
            for run in &due {
                dispatcher.settle_custody_scope_in_txn(
                    txn,
                    run.attempt,
                    run.task_ref,
                    run.fold,
                    now,
                )?;
            }
            Ok(due.len())
        })
    }
}
