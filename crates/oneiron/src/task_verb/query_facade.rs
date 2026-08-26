use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptState,
    InterveneAttempt,
};
use crate::batch::{ApplyOpsGateMode, BatchOp, apply_ops_with_gate_mode};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::context_board::{
    TaskBoardStatus, TasksSection, ack_task_in_txn, cancel_task_in_txn, expand_task, task_is_acked,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles, PolicyApprovalCeiling, check_external_effect_policy,
    resolve_policy_manifest,
};
use crate::memory::{Memory, MemoryError, MemoryResult, facade_provenance, verify_actor_binding};
use crate::run_tree::RunTreeStatus;
use crate::temporal::TimeRange;
use crate::unix_seconds_now;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::consts::{
    TASK_CANCEL_GATE_CHANNEL, TASK_CANCEL_PROPOSAL_PREDICATE, TASK_GATE_RECEIPT_SCAN_LIMIT,
};
use super::consult_result::CancelTargetState;
use super::presence_scan::{
    cancel_target_state, is_cancelable_attempt_state, superseded_attempt_ids, task_presence,
    task_presence_for_id, terminal_attempt_status,
};
use super::rate_limit::task_verb_contract;
use super::route_receipts::{
    DEFAULT_TASK_CANCEL_MODE, TaskAckReceipt, TaskCancelMode, TaskCancelReceipt, TaskCancelTarget,
};
use super::verb_kind::TasksVerb;

impl Memory<'_> {
    /// Renders the current TASKS section through the existing board renderer.
    ///
    /// The TASK type-index walk is bounded and paged, so a vault past the
    /// 100k-row `entities_by_type` cliff still renders a live board (ARCH-0067
    /// §2: the board is the dynamic tail, re-rendered every turn). What the
    /// scan or the render cap left out is stated in the section's additive
    /// overflow footer, never silently dropped.
    pub fn tasks_check(&self) -> MemoryResult<TasksSection> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Check));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let snapshot = task_presence(self.vault())?;
        Ok(TasksSection::render_bounded(
            &snapshot.intents,
            &snapshot.bare_jobs,
            snapshot.source_exhausted,
        ))
    }

    /// Expands one TASK intent through the existing Context Board projection.
    ///
    /// Direct by id: a row outside the collapsed board prefix is hidden, never
    /// gone, so this never inherits `tasks.check`'s scan cap.
    pub fn tasks_expand(&self, task_ref: EntityId) -> MemoryResult<Vec<String>> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Expand));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let Some(intent) = task_presence_for_id(self.vault(), task_ref)? else {
            return Err(MemoryError::from(Error::EntityNotFound));
        };
        // An acked failure has left the TASKS surface (the renderer drops it);
        // the typed read verbs must agree, so it is not expandable by id
        // either.
        if intent.is_acked_failure() {
            return Err(MemoryError::from(Error::EntityNotFound));
        }
        Ok(expand_task(&intent))
    }

    /// Persists the free render-tier acknowledgement bit for one TASK.
    pub fn tasks_ack(&self, task_ref: EntityId) -> MemoryResult<TaskAckReceipt> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Ack));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        // Ack applies only to a currently-FAILED task: failed rows stay
        // surfaced until acked (08b §3). Acking a queued/running task would
        // pre-set the bit so the later failure is dropped from render and never
        // surfaced — so a non-failed ack is a no-op that leaves the bit unset.
        //
        // Direct by id, like `tasks.expand`: a failed row past the board scan
        // prefix must stay acknowledgeable.
        let Some(intent) = task_presence_for_id(self.vault(), task_ref)? else {
            return Err(MemoryError::from(Error::EntityNotFound));
        };
        if intent.status != TaskBoardStatus::Failed {
            return Ok(TaskAckReceipt {
                task_ref,
                acked: intent.acked,
            });
        }
        self.with_verified_actor_write_txn(|wtxn| {
            ack_task_in_txn(self.vault(), wtxn, task_ref).map_err(MemoryError::from)
        })?;
        Ok(TaskAckReceipt {
            task_ref,
            acked: task_is_acked(self.vault(), task_ref)?,
        })
    }

    /// Cancels under the own-scoped `auto` default.
    pub fn tasks_cancel(&self, target: TaskCancelTarget) -> MemoryResult<TaskCancelReceipt> {
        self.tasks_cancel_with_mode(target, DEFAULT_TASK_CANCEL_MODE)
    }

    /// Cancels under one ladder vocabulary token. `auto` and `full-access`
    /// map to the existing Auto ceiling; `manual` maps to Proposed.
    pub fn tasks_cancel_with_mode(
        &self,
        target: TaskCancelTarget,
        mode: TaskCancelMode,
    ) -> MemoryResult<TaskCancelReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let state = cancel_target_state(self.vault(), self.actor(), target)?;
        self.tasks_cancel_resolved(mode, state)
    }

    /// Crate-test seam: runs the cancel decision over a caller-supplied (and
    /// possibly deliberately stale) target snapshot, so the in-txn live-state
    /// re-read (P1-b) can be exercised without a mid-call injection point.
    #[cfg(test)]
    pub(crate) fn tasks_cancel_with_injected_state_for_test(
        &self,
        mode: TaskCancelMode,
        state: CancelTargetState,
    ) -> MemoryResult<TaskCancelReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        self.tasks_cancel_resolved(mode, state)
    }

    fn tasks_cancel_resolved(
        &self,
        mode: TaskCancelMode,
        state: CancelTargetState,
    ) -> MemoryResult<TaskCancelReceipt> {
        let verb = task_verb_contract(TasksVerb::Cancel);
        let now = unix_seconds_now();
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
            });
        }

        let (gate_decision_ref, gate_outcome, effected, status) = self
            .with_verified_actor_write_txn(|wtxn| {
                let policy = resolve_policy_manifest(&self.vault().store, &*wtxn)?;
                let effect = ExternalEffectGateInput {
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
                    brief_ref: Some(state.target_ref.clone()),
                    send_ref: None,
                    standing_grant_ref: None,
                    scoped_mcp_call: None,
                    counterparty_first_touch: None,
                    counterparty_opted_out: false,
                    counterparty_opt_out_receipt_reason: None,
                    has_opted_in: true,
                    has_permission: true,
                    policy_risk: ExternalEffectPolicyRisk::Normal,
                };
                let (decision_id, decision, _charge) = check_external_effect_policy(
                    &self.vault().store,
                    wtxn,
                    &effect,
                    &policy,
                    false,
                )?;
                let decision_ref = format!("gate:{}", decision_id.to_hex());
                if decision.outcome() != GateOutcome::Allow {
                    return Ok((decision_ref, decision.outcome(), false, None));
                }

                // P1-b (TOCTOU): decide on transaction-current attempt state,
                // not the pre-txn snapshot. A `Leased`→`Queued` requeue (lease
                // cleanup / timeout) between the snapshot and this write txn
                // must be acted on as its live state; otherwise the now-Queued
                // attempt survives a "successful" cancel and stays claimable.
                let queue = AttemptQueue::new(self.vault());
                let live_attempts: Vec<(AttemptId, AttemptState)> = match state.task_ref {
                    // Membership TOCTOU: a retry mints a NEW row under the same
                    // `task_ref` and finalizes its source as `Failed`, so
                    // re-reading only the snapshotted IDS would see the dead
                    // source, report the task terminally failed, cancel
                    // nothing, and leave the live successor to run and send. A
                    // TASK target therefore re-derives its realizing SET here,
                    // reduced to retry-chain heads.
                    Some(task_ref) => {
                        let records =
                            queue.list_task_in_write_txn(&*wtxn, task_ref.to_hex().as_str())?;
                        let superseded = superseded_attempt_ids(&records);
                        records
                            .iter()
                            .filter(|record| !superseded.contains(&record.id))
                            .map(|record| (record.id, record.state))
                            .collect()
                    }
                    // A spawn realization carries no TASK backlink to re-derive
                    // membership from, so its single row is re-read by id.
                    None => {
                        let mut attempts = Vec::with_capacity(state.attempts.len());
                        for (attempt_id, snapshot_state) in &state.attempts {
                            match queue.get_in_write_txn(&*wtxn, *attempt_id)? {
                                Some(record) => attempts.push((*attempt_id, record.state)),
                                // Preserve an already-terminal spawn snapshot
                                // when the in-txn lookup cannot surface its
                                // row; terminal states cannot transition again.
                                None if matches!(
                                    snapshot_state,
                                    AttemptState::Completed
                                        | AttemptState::Failed
                                        | AttemptState::Cancelled
                                ) =>
                                {
                                    attempts.push((*attempt_id, *snapshot_state));
                                }
                                None => {}
                            }
                        }
                        attempts
                    }
                };

                // P1-a (leased-cancel honesty): a leased realization cannot be
                // stopped in this txn (`intervene` refuses a leased attempt) and
                // its local/outbound work keeps running. Report the honest
                // partial — do NOT hide the task and do NOT claim effect while a
                // live lease remains; the task stays VISIBLE (it folds to
                // Running under its live lease) until the lease releases. A
                // Queued+Leased mix is uneffected too: nothing is intervened and
                // nothing is hidden, so the receipt never conceals live work.
                if live_attempts
                    .iter()
                    .any(|(_, attempt_state)| *attempt_state == AttemptState::Leased)
                {
                    return Ok((
                        decision_ref,
                        decision.outcome(),
                        false,
                        Some(RunTreeStatus::Running),
                    ));
                }

                // A `Scheduled` retry is live work waiting on its instant: it
                // cancels exactly like a queued one. Omitting it would report
                // the task terminal off its failed source row while the next
                // try still ran and sent.
                let terminal_status = terminal_attempt_status(&live_attempts);
                if !live_attempts
                    .iter()
                    .any(|(_, attempt_state)| is_cancelable_attempt_state(*attempt_state))
                {
                    return Ok((decision_ref, decision.outcome(), false, terminal_status));
                }

                let mut cancelled_count = 0usize;
                for (attempt_id, attempt_state) in &live_attempts {
                    if !is_cancelable_attempt_state(*attempt_state) {
                        continue;
                    }
                    let outcome = queue.intervene_in_txn(
                        wtxn,
                        InterveneAttempt {
                            id: *attempt_id,
                            kind: AttemptInterventionKind::Cancel,
                            actor: self.actor().to_hex(),
                            note: None,
                            now,
                        },
                    )?;
                    match outcome.effect {
                        AttemptInterventionEffect::Cancelled => cancelled_count += 1,
                        AttemptInterventionEffect::AlreadyCancelled => {}
                        _ => {
                            return Err(MemoryError::from(Error::InvariantViolation(
                                "tasks.cancel.effect",
                            )));
                        }
                    }
                }
                if cancelled_count == 0 {
                    return Ok((decision_ref, decision.outcome(), false, terminal_status));
                }
                // A Completed/Failed sibling remains real terminal work. Keep
                // its TASK intent visible so the unchanged job stays folded
                // exactly once, and surface that aggregate terminal status
                // instead of claiming the whole target was cancelled.
                let preserved_terminal_status = terminal_status.filter(|status| {
                    matches!(status, RunTreeStatus::Completed | RunTreeStatus::Failed)
                });
                if preserved_terminal_status.is_none()
                    && let Some(task_ref) = state.task_ref
                {
                    cancel_task_in_txn(self.vault(), wtxn, task_ref)?;
                }
                Ok((
                    decision_ref,
                    decision.outcome(),
                    true,
                    preserved_terminal_status.or(Some(RunTreeStatus::Cancelled)),
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
        })
    }

    pub(super) fn persist_task_proposal(
        &self,
        predicate: &str,
        value: Value,
        subject: EntityId,
        now: u64,
        provenance: Value,
    ) -> MemoryResult<(EntityId, Option<String>)> {
        let proposal_ref = EntityId::now();
        let candidate = ClaimCandidate::new(
            predicate.to_owned(),
            ClaimSubject::Entity(subject),
            value,
            1.0,
        );
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.actor(), self.actor_class()),
            ClaimSource::ToolOutput,
            WriteProvenance::new(provenance)?,
            ClaimApprovalStatus::Proposed,
        );
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.with_verified_actor_write_txn(|wtxn| {
            apply_ops_with_gate_mode(
                &self.vault().store,
                &self.vault().config,
                &self.vault().analyzer,
                wtxn,
                vec![BatchOp::ClaimCandidate {
                    id: proposal_ref,
                    candidate: Box::new(candidate),
                    envelope,
                    occurred,
                    learned_at: now,
                    internal_lexical_query_hint: false,
                }],
                self.vault().text_index_trusted.load(Ordering::Acquire),
                ApplyOpsGateMode::new(true, true),
            )
            .map_err(MemoryError::from)
        })?;
        let gate_decision_ref = self
            .vault()
            .gate_decisions(TASK_GATE_RECEIPT_SCAN_LIMIT)?
            .into_iter()
            .filter(|record| record.claim_id.as_ref() == Some(proposal_ref.as_bytes()))
            .max_by_key(|record| record.decision_id.to_hex())
            .map(|record| format!("gate:{}", record.decision_id.to_hex()));
        Ok((proposal_ref, gate_decision_ref))
    }
}
