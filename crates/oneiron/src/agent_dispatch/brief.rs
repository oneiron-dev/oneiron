//! The self brief's reads of a run's own dispatch (FIX 17594, Engine ruling
//! 21:47): the parent ceiling, each delegation ancestor's live bounds.
//!
//! Each read takes one snapshot of the exact attempt the host bound the run
//! to, and only while that attempt dispatched the host's own agent; it never
//! picks one of the agent's dispatches by its id. It evaluates no Gate and
//! writes nothing: no approval, notice, receipt or scan count.

use std::collections::HashSet;

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::context_board::{
    BriefBranchBound, BriefContextBound, BriefParentBound, BriefParentCeiling,
};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::gate::PolicyApprovalCeiling;
use crate::policy_manifest_doors::PolicyCeiling;
use crate::write_envelope::WriteActor;

use super::codec::agent_dispatch_actor;
use super::comm::dispatch_input;
use super::types::AgentDispatchInput;
use super::widen_record::invalid;

impl Vault {
    /// The parent ceiling of the run the host bound to dispatch attempt
    /// `attempt` for its agent `actor`, read in one snapshot: each
    /// delegation ancestor, nearest first, with the branch bound and the
    /// projection descriptor its own dispatch stored and the approval
    /// ceiling its live definition holds it at. A root run has none. `None`
    /// when `attempt` is no dispatch of `actor`'s.
    ///
    /// # Errors
    /// A store failure, a dispatch input that does not decode, an ancestor
    /// that dispatches no agent, or a lineage that comes back on itself.
    pub fn self_brief_parent_ceiling(
        &self,
        actor: WriteActor,
        attempt: AttemptId,
    ) -> Result<Option<BriefParentCeiling>> {
        let txn = self.store.env.read_txn()?;
        self.self_brief_parent_ceiling_in_txn(&txn, actor, attempt)
    }

    /// [`Self::self_brief_parent_ceiling`] in the caller's read transaction.
    /// The chain is the one the Gate's delegation read follows
    /// ([`super::delegation_lineage_parent_in_txn`]): each target's pinned
    /// delegation parent, else its attempt's recorded parent, a workflow
    /// wrapper crossed. It ends where that read ends, at no parent or at a
    /// parent whose row is gone, and at a parent that is no agent dispatch.
    ///
    /// # Errors
    /// As [`Self::self_brief_parent_ceiling`].
    pub(crate) fn self_brief_parent_ceiling_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: WriteActor,
        attempt: AttemptId,
    ) -> Result<Option<BriefParentCeiling>> {
        let Some((mut row, _)) = bound_dispatch_in_txn(self, txn, actor, attempt)? else {
            return Ok(None);
        };
        let queue = AttemptQueue::new(self);
        let mut seen = HashSet::from([row.id]);
        let mut target = actor.entity_ref();
        let mut ancestors = Vec::new();
        while let Some(parent) =
            super::delegation_lineage_parent_in_txn(&self.store, txn, &row, target)?
        {
            if !seen.insert(parent) {
                return Err(invalid("delegation lineage cycle"));
            }
            let Some(parent_row) = queue.get_in_txn(txn, parent)? else {
                break;
            };
            let Some(input) = dispatch_input(&parent_row)? else {
                break;
            };
            target = agent_dispatch_actor(&input)?.entity_ref();
            let approval = crate::gate::agent_definition_ceiling_for_actor(
                &self.store,
                txn,
                WriteActor::new(target, EdgeActorClass::Agent),
            )
            .map(policy_ceiling);
            ancestors.push(BriefParentBound {
                attempt: parent,
                actor: target,
                branch: BriefBranchBound::of_dispatch(input.scope.as_ref()),
                context: BriefContextBound::of_dispatch(input.context_spec.as_ref()),
                approval,
            });
            row = parent_row;
        }
        Ok(Some(BriefParentCeiling { ancestors }))
    }
}

/// Attempt `attempt`'s row and its strictly decoded dispatch input, while
/// it dispatches `actor`'s own agent row: `actor` is an agent, the dispatch
/// targets its row, and, when `actor` is bound to a run attempt, it is this
/// one. `None` when the row is gone, is no agent dispatch, or dispatches
/// another actor.
///
/// # Errors
/// A store failure, or a dispatch input that does not decode.
fn bound_dispatch_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    attempt: AttemptId,
) -> Result<Option<(AttemptRecord, AgentDispatchInput)>> {
    if actor.actor_class() != EdgeActorClass::Agent
        || actor
            .run_attempt()
            .is_some_and(|bound| bound != *attempt.as_bytes())
    {
        return Ok(None);
    }
    let Some(row) = AttemptQueue::new(vault).get_in_txn(txn, attempt)? else {
        return Ok(None);
    };
    let Some(input) = dispatch_input(&row)? else {
        return Ok(None);
    };
    if agent_dispatch_actor(&input)?.entity_ref() != actor.entity_ref() {
        return Ok(None);
    }
    Ok(Some((row, input)))
}

/// The public name of a live definition's approval bound.
fn policy_ceiling(ceiling: PolicyApprovalCeiling) -> PolicyCeiling {
    match ceiling {
        PolicyApprovalCeiling::Auto => PolicyCeiling::Auto,
        PolicyApprovalCeiling::Proposed => PolicyCeiling::Proposed,
    }
}
