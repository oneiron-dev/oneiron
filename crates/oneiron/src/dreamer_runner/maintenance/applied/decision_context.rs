//! The context an applied write's receipt and its revert carry (FIX 7499,
//! 7500): the attempt that wrote it, as its authority stamp names it, and
//! the project a fork is about. A revert answers the apply it reverts and
//! carries that receipt's context. Read only; nothing here refuses, and a
//! row that does not read leaves the context without it.

use super::MaintenanceTarget;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::authority::{BaseAgent, base_agent_for_facet};
use crate::store::{
    GateDecisionContext, GateDecisionId, GateDecisionReadContext, GateLoopLink, GateLoopOrigin,
    GateLoopSource,
};

/// The context of `attempt`'s applied write on `target`. A finding's claim
/// is stored, so its row is what a reader is judged against; a fork names
/// no claim, so the project it is about is kept.
pub(super) fn applied(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: MaintenanceTarget,
    attempt: Option<AttemptId>,
) -> GateDecisionContext {
    let read = match target {
        MaintenanceTarget::ProjectTreeFork { project, fork } => {
            GateDecisionReadContext::about(Some(fork), vec![project])
        }
        MaintenanceTarget::Finding(_) | MaintenanceTarget::IdentityAsk(_) => None,
    };
    GateDecisionContext {
        read: read.into_iter().collect(),
        links: attempt
            .map(|attempt| vault.attempt_action_link_in_txn(txn, attempt))
            .into_iter()
            .collect(),
        analysis: None,
    }
}

/// The context of a background identity disposition its `facet` recorded:
/// the base agent that facet runs as. The pass records no attempt or run
/// with it, so none is kept, and an ask names no row to read it by.
pub(super) fn disposition(facet: &str) -> GateDecisionContext {
    let source = match base_agent_for_facet(facet) {
        BaseAgent::Dreamer => GateLoopSource::Dreamer,
        BaseAgent::Coach => GateLoopSource::Coach,
    };
    GateDecisionContext::linked(
        GateLoopLink::action(source, None, None, GateLoopOrigin::Unresolved),
        None,
    )
}

/// The context of a revert of the write whose receipt is `applied`: that
/// receipt's own, answered by the revert.
pub(super) fn answering(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    applied: GateDecisionId,
) -> GateDecisionContext {
    vault
        .store
        .gate_decision_in_txn(txn, applied)
        .ok()
        .flatten()
        .map(|original| GateDecisionContext::answering(&original))
        .unwrap_or_default()
}
