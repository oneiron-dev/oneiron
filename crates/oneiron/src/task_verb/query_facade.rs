//! Task descriptions, cancellation and proposals.
//! Entry: `Memory::cancel`.
//! Read/proposal methods live in children; cancellation stays here.

use crate::task_verb::sdk::AgentVerb;
use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptState,
    CancelRequestOutcome, CancelStanding, ForceAttemptCancel, ForceCancelAuthority,
    ForceCancelOutcome, InterveneAttempt, LandingTrigger, RequestAttemptCancel,
};
use crate::batch::{ApplyOpsGateMode, BatchOp, apply_ops_with_gate_mode};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::context_board::{
    TaskBoardStatus, TasksSectionRows, ack_task_in_txn, cancel_task_in_txn, expand_task,
    task_is_acked,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles, PolicyApprovalCeiling, check_external_effect_policy,
    resolve_policy_manifest,
};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, facade_provenance,
    verify_actor_binding,
};
use crate::run_tree::RunTreeStatus;
use crate::temporal::TimeRange;

use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::consts::{
    TASK_CANCEL_FORCE_MODE, TASK_CANCEL_GATE_CHANNEL, TASK_CANCEL_PROPOSAL_PREDICATE,
    TASK_GATE_RECEIPT_SCAN_LIMIT,
};
use super::consult_result::CancelTargetState;
use super::create_origin::{put_proposal_origin_in_txn, task_create_origin_in_txn};
use super::highway_types::HostBinding;
use super::presence_scan::{
    cancel_target_state, is_cancelable_attempt_state, is_running_attempt_state,
    superseded_attempt_ids, task_owned_by, task_owned_in, task_presence_at,
    task_presence_for_dismissal, task_presence_for_id, terminal_attempt_status,
};
use super::rate_limit::{task_create_owner_in, task_verb_contract};
use super::route_receipts::{
    DEFAULT_TASK_CANCEL_MODE, TaskCancelMode, TaskCancelReceipt, TaskCancelTarget, TaskDescription,
    TaskUpdateReceipt,
};
use super::{TaskCall, TaskReport, TaskReportBody, TaskVia, sdk};

mod cancel_effect;
mod proposal;
mod read;

impl Memory<'_> {
    /// Cancels under the own-scoped `auto` default.
    pub fn cancel(&self, target: TaskCancelTarget) -> MemoryResult<TaskCancelReceipt> {
        self.cancel_with_mode(target, DEFAULT_TASK_CANCEL_MODE)
    }

    /// Cancels under one ladder vocabulary token. `auto` and `full-access`
    /// map to the existing Auto ceiling; `manual` maps to Proposed.
    pub fn cancel_with_mode(
        &self,
        target: TaskCancelTarget,
        mode: TaskCancelMode,
    ) -> MemoryResult<TaskCancelReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let state = cancel_target_state(self.vault(), self.actor(), target)?;
        self.cancel_resolved(mode, state)
    }

    /// Crate-test seam: runs the cancel decision over a caller-supplied (and
    /// possibly deliberately stale) target snapshot, so the in-txn live-state
    /// re-read (P1-b) can be exercised without a mid-call injection point.
    #[cfg(test)]
    pub(super) fn cancel_with_injected_state_for_test(
        &self,
        mode: TaskCancelMode,
        state: CancelTargetState,
    ) -> MemoryResult<TaskCancelReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        self.cancel_resolved(mode, state)
    }

    /// RUNG 2: the owner's nonrefusable stop.
    ///
    /// Distinct verb, deliberately: [`Self::cancel`] stays SOFT — it asks
    /// a running worker to land and lets it refuse with a reason — and this is
    /// the door for the case that rung cannot answer (a worker that will not
    /// land, evidence of pathology, an owner who needs the machine back now).
    ///
    /// Three things make it unforgeable:
    ///
    /// * only a TASK whose durable `tasks.create` owner record names THIS actor
    ///   can be forced. A spawn target's parent link is peer standing, not
    ///   authority, so it is refused into the ordinary proposal path;
    /// * ownership is re-verified INSIDE the write transaction, before any row
    ///   changes, so a create-owner rewrite racing the call cannot slip through;
    /// * the terminal receipt's actor comes from the runtime-minted
    ///   [`ForceCancelAuthority`], never from caller text — the worker's own
    ///   status/notes cannot author it.
    ///
    /// Lease expiry and criticality keep their own runtime grounds and do not
    /// pass through here.
    pub fn cancel_force(
        &self,
        target: TaskCancelTarget,
        reason: Option<String>,
    ) -> MemoryResult<TaskCancelReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let state = cancel_target_state(self.vault(), self.actor(), target)?;
        let verb = task_verb_contract(AgentVerb::Cancel);
        let now = self.vault().store.clock.now_recorded_at();
        let provenance = facade_provenance(verb);

        // Not the owner, or not an owner-addressable TASK target: nothing hard
        // happens, and the caller gets the same typed proposal the soft ladder
        // gives a foreign cancel.
        let owner_task_ref = state.task_ref.filter(|_| state.owned);
        let Some(task_ref) = owner_task_ref else {
            let (proposal_ref, gate_decision_ref) = self.persist_task_proposal(
                TASK_CANCEL_PROPOSAL_PREDICATE,
                Value::Map(vec![
                    (Value::from("target_ref"), Value::from(state.target_ref)),
                    (Value::from("mode"), Value::from(TASK_CANCEL_FORCE_MODE)),
                ]),
                state.proposal_subject,
                now,
                provenance,
            )?;
            return Ok(TaskCancelReceipt {
                approval: ClaimApprovalStatus::Proposed,
                effected: false,
                proposal_ref: Some(proposal_ref),
                gate_decision_ref,
                status: None,
                cancel_requested: false,
                forced: false,
            });
        };

        let (gate_decision_ref, gate_outcome, forced_count) =
            self.with_verified_actor_write_txn(|wtxn| {
                let policy = resolve_policy_manifest(&self.vault().store, &*wtxn)?;
                let effect = self.task_cancel_gate_input(verb, &state.target_ref);
                let (decision_id, decision, _charge) = check_external_effect_policy(
                    &self.vault().store,
                    wtxn,
                    &effect,
                    &policy,
                    false,
                )?;
                let decision_ref = format!("gate:{}", decision_id.to_hex());
                if decision.outcome() != GateOutcome::Allow {
                    return Ok((decision_ref, decision.outcome(), 0usize));
                }
                // Authority re-verified against durable create provenance in
                // THIS transaction, before a single row is touched.
                if task_create_owner_in(self.vault(), &*wtxn, task_ref)? != Some(self.actor()) {
                    return Ok((decision_ref, decision.outcome(), 0usize));
                }
                let forced_count =
                    self.force_cancel_task_in(wtxn, task_ref, reason.clone(), now)?;
                Ok((decision_ref, decision.outcome(), forced_count))
            })?;

        if gate_outcome != GateOutcome::Allow {
            let (proposal_ref, _proposal_gate_decision_ref) = self.persist_task_proposal(
                TASK_CANCEL_PROPOSAL_PREDICATE,
                Value::Map(vec![
                    (Value::from("target_ref"), Value::from(state.target_ref)),
                    (Value::from("mode"), Value::from(TASK_CANCEL_FORCE_MODE)),
                ]),
                state.proposal_subject,
                now,
                provenance,
            )?;
            return Ok(TaskCancelReceipt {
                approval: ClaimApprovalStatus::Proposed,
                effected: false,
                proposal_ref: Some(proposal_ref),
                gate_decision_ref: Some(gate_decision_ref),
                status: None,
                cancel_requested: false,
                forced: false,
            });
        }

        Ok(TaskCancelReceipt {
            approval: ClaimApprovalStatus::Auto,
            effected: forced_count > 0,
            proposal_ref: None,
            gate_decision_ref: Some(gate_decision_ref),
            status: (forced_count > 0).then_some(RunTreeStatus::Cancelled),
            cancel_requested: false,
            forced: forced_count > 0,
        })
    }

    /// The one gate input both cancel rungs present, so the hard rung cannot
    /// quietly ask an easier question than the soft one.
    fn task_cancel_gate_input(&self, verb: &str, target_ref: &str) -> ExternalEffectGateInput {
        ExternalEffectGateInput {
            actor: GateActor {
                actor_class: self.actor_class().gate_actor_class().to_owned(),
                actor_ref: Some(self.actor().to_hex()),
                delegation_grant_ref: None,
            },
            provenance: GateProvenanceHandles {
                actor_entity_ref: Some(self.actor()),
                ..GateProvenanceHandles::default()
            },
            verb: verb.to_owned(),
            channel: TASK_CANCEL_GATE_CHANNEL.to_owned(),
            channel_identity_ref: None,
            counterparty: None,
            brief_ref: Some(target_ref.to_owned()),
            send_ref: None,
            standing_grant_ref: None,
            scoped_mcp_call: None,
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: true,
            has_permission: true,
            policy_risk: ExternalEffectPolicyRisk::Normal,
            send_autonomy: None,
        }
    }

    fn cancel_resolved(
        &self,
        mode: TaskCancelMode,
        state: CancelTargetState,
    ) -> MemoryResult<TaskCancelReceipt> {
        let verb = task_verb_contract(AgentVerb::Cancel);
        let now = self.vault().store.clock.now_recorded_at();
        let provenance = facade_provenance(verb);
        if !state.owned || mode.ceiling() == PolicyApprovalCeiling::Proposed {
            let (proposal_ref, gate_decision_ref) = self.persist_task_proposal(
                TASK_CANCEL_PROPOSAL_PREDICATE,
                Value::Map(vec![
                    (Value::from("target_ref"), Value::from(state.target_ref)),
                    (Value::from("mode"), Value::from(mode.as_str())),
                ]),
                state.proposal_subject,
                now,
                provenance,
            )?;
            return Ok(TaskCancelReceipt {
                approval: ClaimApprovalStatus::Proposed,
                effected: false,
                proposal_ref: Some(proposal_ref),
                gate_decision_ref,
                status: None,
                cancel_requested: false,
                forced: false,
            });
        }

        let (gate_decision_ref, gate_outcome, effected, status, cancel_requested) = self
            .with_verified_actor_write_txn(|wtxn| {
                let policy = resolve_policy_manifest(&self.vault().store, &*wtxn)?;
                let effect = self.task_cancel_gate_input(verb, &state.target_ref);
                let (decision_id, decision, _charge) = check_external_effect_policy(
                    &self.vault().store,
                    wtxn,
                    &effect,
                    &policy,
                    false,
                )?;
                let decision_ref = format!("gate:{}", decision_id.to_hex());
                if decision.outcome() != GateOutcome::Allow {
                    return Ok((decision_ref, decision.outcome(), false, None, false));
                }

                let (effected, status, cancel_requested) =
                    self.soft_cancel_in(wtxn, &state, now)?;
                Ok((
                    decision_ref,
                    decision.outcome(),
                    effected,
                    status,
                    cancel_requested,
                ))
            })?;

        if gate_outcome != GateOutcome::Allow {
            let (proposal_ref, _proposal_gate_decision_ref) = self.persist_task_proposal(
                TASK_CANCEL_PROPOSAL_PREDICATE,
                Value::Map(vec![
                    (Value::from("target_ref"), Value::from(state.target_ref)),
                    (Value::from("mode"), Value::from(mode.as_str())),
                ]),
                state.proposal_subject,
                now,
                provenance,
            )?;
            return Ok(TaskCancelReceipt {
                approval: ClaimApprovalStatus::Proposed,
                effected: false,
                proposal_ref: Some(proposal_ref),
                gate_decision_ref: Some(gate_decision_ref),
                status: None,
                cancel_requested: false,
                forced: false,
            });
        }

        // Gate allowed. `effected` is honest: true only when at least one live
        // Queued/Paused realization was cancelled. A terminal sibling keeps the
        // task visible and owns the combined status; all-cancellable work is
        // hidden. A live lease or an all-terminal target remains uneffected.
        Ok(TaskCancelReceipt {
            approval: ClaimApprovalStatus::Auto,
            effected,
            proposal_ref: None,
            gate_decision_ref: Some(gate_decision_ref),
            status,
            cancel_requested,
            // The cooperative verb never forces. Rung 2 is its own door.
            forced: false,
        })
    }
}

fn not_the_task_owner() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "only the task's owner dismisses its failure".to_owned(),
        &["A failed task stays on the board until the actor that owns it dismisses it."],
    )
}
