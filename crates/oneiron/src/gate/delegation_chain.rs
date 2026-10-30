//! A delegated child's write met with its live delegation chain at the Gate
//! (FIX 10537, Engine 09:24 and 10:43). Dispatch meets the chain once and
//! forks the child only when the chain narrows it then; a write bound to the
//! child's run attempt ([`crate::WriteActor::run_attempt`]) meets every
//! ancestor's bound again as it stands at the write, in the write's own
//! transaction ([`super::definition_ceiling::delegation_chain_narrowing`]).
//! An ancestor that narrowed since holds the write for the owner's review as
//! its own bound would hold a fork of it, named
//! [`GateReasonCode::PendingDelegationChainCeiling`] and citing that
//! ancestor. A forked child keeps its row's clamp, and a child with no agent
//! parent keeps today's Auto. An external effect the run makes meets the
//! chain the same way, on the effect door's own Pending (FIX 11921,
//! [`PolicyManifestResolution::evaluate_gate_with_delegation_chain`]).

use super::ceiling::PolicyApprovalCeiling;
use super::decision::{GateDecision, GateOutcome, GateReasonCode};
use super::definition_ceiling::{DelegationNarrowing, delegation_chain_narrowing};
use super::input::{GateEvaluatorInput, GateProvenanceHandles};
use super::resolution::PolicyManifestResolution;
use crate::edge::EdgeActorClass;
use crate::store::Store;
use crate::write_envelope::{SourceLineage, WriteActor};

/// `policy`'s decision on `input`, met with the live delegation chain of the
/// run `actor` writes for, when `actor` is bound to one.
pub(in crate::gate) fn evaluate_with_delegation_chain(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    input: &GateEvaluatorInput,
    lineage: Option<&SourceLineage>,
    actor: Option<WriteActor>,
) -> GateDecision {
    let decision = policy.evaluate_gate_with_lineage(input, lineage);
    match actor.and_then(|actor| delegation_chain_narrowing(store, txn, actor)) {
        Some(narrowing) => meet_delegation_chain(decision, narrowing, input, |narrowed| {
            policy.evaluate_gate_with_lineage(narrowed, lineage)
        }),
        None => decision,
    }
}

impl PolicyManifestResolution {
    /// This policy's decision on an external effect's `input`, met with the
    /// live delegation chain of the run its provenance names (FIX 11921): an
    /// agent bound to its run meets each ancestor's live bound here as at
    /// the claim door, and an ancestor that narrowed holds the effect on the
    /// effect door's own Pending.
    pub(in crate::gate) fn evaluate_gate_with_delegation_chain(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        input: &GateEvaluatorInput,
    ) -> GateDecision {
        let actor = effect_run_actor(&input.provenance);
        evaluate_with_delegation_chain(store, txn, self, input, None, actor)
    }
}

/// The run an external effect is made for, as the claim door reads its
/// writes' (FIX 11921): the effect's audited identity bound to the attempt
/// its provenance carries. The class the effect asserts is not read: the
/// chain read itself proves the attempt dispatched that identity's own
/// AGENT_DEF row, and narrows nothing otherwise.
fn effect_run_actor(provenance: &GateProvenanceHandles) -> Option<WriteActor> {
    let actor = provenance.actor_entity_ref?;
    let attempt = provenance.run_attempt?;
    Some(WriteActor::new(actor, EdgeActorClass::Agent).with_run_attempt(attempt))
}

/// `decision` held by the ancestor `narrowing` names, where that ancestor's
/// bound clamps the write: the same input under a `Proposed` definition
/// bound pends on the actor ceiling, and `decision` itself did not. A Deny,
/// or a write its own bound already holds, stands as decided.
fn meet_delegation_chain(
    decision: GateDecision,
    narrowing: DelegationNarrowing,
    input: &GateEvaluatorInput,
    evaluate: impl FnOnce(&GateEvaluatorInput) -> GateDecision,
) -> GateDecision {
    if decision.outcome() == GateOutcome::Deny
        || decision
            .reason_codes()
            .contains(&GateReasonCode::PendingActorCeiling)
    {
        return decision;
    }
    let narrowed = evaluate(&GateEvaluatorInput {
        agent_definition_ceiling: Some(PolicyApprovalCeiling::Proposed),
        ..input.clone()
    });
    if !narrowed
        .reason_codes()
        .contains(&GateReasonCode::PendingActorCeiling)
    {
        return decision;
    }
    tracing::info!(
        target: "oneiron::gate",
        ancestor_agent = %narrowing.agent.to_hex(),
        ancestor_attempt = %crate::entity_id::bytes_to_hex_lower(narrowing.attempt.as_bytes()),
        "a delegation ancestor's live bound holds a delegated child's write",
    );
    decision.held_by_delegation_chain(narrowing)
}
