//! Owner verdict settlement for plan-doc revisions.

use super::*;

impl Vault {
    /// The owner answers plan-doc `plan` at revision `expected_revision`,
    /// in one writer that rechecks the owner's proof: the verdict is stored
    /// with that revision, and one gate decision records it.
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds; [`RecordError::InvalidNoteBody`] for a
    /// NOTE that is no plan-doc, a revision that is no 64 hex characters, an
    /// `approving_turn_ref` that names no live TURN, or an
    /// `approving_thread_ref` that names no thread on the plan-doc;
    /// [`Error::ConcurrentWrite`] when the text is no longer at
    /// `expected_revision`; an approval's run that cannot land (its agent
    /// definition gone). Every refusal writes nothing.
    pub(crate) fn answer_plan_doc_as(
        &self,
        owner: &AuthenticatedOwner,
        plan: EntityId,
        expected_revision: &str,
        decision: PlanDocDecision,
        origin: PlanApprovalOrigin,
    ) -> MemoryResult<PlanDocSettlementView> {
        if expected_revision.len() != 64
            || !expected_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("a plan-doc revision is 64 hex characters").into());
        }
        let expected = expected_revision.to_ascii_lowercase();
        let settled = self.try_with_write_txn(|txn| -> MemoryResult<PlanDocSettlementView> {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let (core, markdown, mut review) = plan_doc_in_txn(self, txn, plan)?;
            let revision = revision_of(plan, &markdown);
            if revision_hex(&revision) != expected {
                return Err(Error::ConcurrentWrite("plan-doc revision changed").into());
            }
            if let Some(turn) = origin.turn {
                crate::conversation_dag::require_type(&self.store, txn, &turn, ENTITY_TYPE_TURN)
                    .map_err(|_| invalid("approving_turn_ref names no live conversation TURN"))?;
            }
            if let Some(thread) = origin.thread
                && self
                    .annotation_thread_in_txn(txn, &plan, &thread, false)?
                    .is_none()
            {
                return Err(
                    invalid("approving_thread_ref names no thread on this plan-doc").into(),
                );
            }
            let before = review.verdict.take();
            let receipt_ref = self.record_plan_doc_verdict_in_txn(
                txn,
                actor,
                plan,
                &core,
                &revision,
                decision,
                before.as_ref(),
            )?;
            review.verdict = Some(PlanDocVerdict {
                decision,
                revision: expected,
                decided_at: crate::unix_seconds_now(),
                receipt_ref: receipt_ref.clone(),
            });
            PLAN_DOC_REVIEW.put(&self.store, txn, &plan, &review)?;
            // Execute-on-approve: an approval of a plan that names its agent
            // definition lands the run in this writer, pinned at the revision
            // approved, with the budget the plan's text asks.
            let run_task_ref = match (decision, review.agent_def_ref) {
                (PlanDocDecision::Approved, Some(agent_def_ref)) => {
                    match PlanDocBody::from_markdown(&markdown) {
                        Some(body) => Some(
                            self.memory(actor, EdgeActorClass::Human)
                                .land_plan_run_in_txn(txn, plan, &revision, &body, agent_def_ref)?,
                        ),
                        None => None,
                    }
                }
                _ => None,
            };
            // Execute-on-approve hangs the run off the approving turn: the
            // run's derived SESSION, kept when the revision is approved
            // again (agent-runtime-v1.md:342).
            let sub_session_id = match (run_task_ref, origin.turn) {
                (Some(task), Some(turn)) => {
                    Some(self.plan_run_sub_session_in_txn(txn, actor, task, turn)?)
                }
                _ => None,
            };
            if let (Some(session), Some(thread)) = (sub_session_id, origin.thread) {
                let now = self.store.clock.now_recorded_at();
                self.record_thread_sub_session_in_txn(
                    txn,
                    ThreadSubSession {
                        artifact_id: plan,
                        thread_id: thread,
                        session,
                        actor: WriteActor::new(actor, EdgeActorClass::Human),
                        occurred: TimeRange {
                            start: now,
                            end: now,
                        },
                        learned_at: now,
                    },
                )?;
            }
            Ok(PlanDocSettlementView {
                plan_ref: plan,
                decision,
                revision: revision_hex(&revision),
                proposed_by: proposer(&core),
                receipt_ref,
                run_task_ref,
                sub_session_id,
            })
        })?;
        if settled.run_task_ref.is_some() {
            self.store.notify_attempt_observers();
        }
        Ok(settled)
    }
}
