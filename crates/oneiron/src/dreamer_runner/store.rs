//! The Dreamer runner store: queue lifecycle, park/resume, and readers.

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, FailAttempt, FailOutcome,
};
use crate::dreamer_wake::WakeTrigger;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};

use super::codec::{
    decode_dreamer_attempt_payload, encode_dreamer_attempt_payload, invalid_dreamer_runner,
    validate_attempt_type, validate_park_owner, validate_park_reason,
};
use super::constants::{
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DREAMER_NOTE_REVIEW_ATTEMPT_KIND,
    DREAMER_RECIPE_WAKE_ATTEMPT_KIND, DREAMER_RESIDENT_DREAM_ATTEMPT_KIND,
    DREAMER_RUNNER_ATTEMPT_KIND, DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND,
    DREAMER_TASK_REALIZE_ATTEMPT_KIND, DREAMER_VAULT_CLEANUP_ATTEMPT_KIND,
    DREAMER_WEAVE_LENS_ATTEMPT_KIND, DREAMER_WEAVE_RECIPE_ATTEMPT_KIND,
};
use super::types::{
    CompleteDreamerAttempt, CompleteDreamerAttemptOutcome, DreamerAttemptPayload,
    DreamerAttemptStatus, DreamerConsolidationScope, DreamerParkedAttemptRecord,
    DreamerRunTreeRecord, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt, EnqueueDreamerSkillOptimizeAttempt,
    EnqueueDreamerVaultCleanupAttempt, FailDreamerAttempt, FailDreamerAttemptOutcome,
    ParkDreamerAttempt,
};
use crate::error::MaintenanceError;

/// Private parent/child attempt-tree edge row, keyed by attempt id.
pub(super) const RUN_TREE: SideTable<AttemptId, DreamerRunTreeRecord, Raw> =
    SideTable::new(&side_table::DREAMER_RUN_TREE);
/// Private paused-attempt row, keyed by attempt id.
pub(super) const PARKED: SideTable<AttemptId, DreamerParkedAttemptRecord, Raw> =
    SideTable::new(&side_table::DREAMER_PARKED);

/// Private Dreamer runner store over an already-open vault.
pub struct DreamerRunnerStore<'a> {
    pub(super) vault: &'a Vault,
    pub(super) attempts: AttemptQueue<'a>,
}

impl<'a> DreamerRunnerStore<'a> {
    /// Opens a Dreamer runner store over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            attempts: AttemptQueue::new(vault),
        }
    }

    /// The vault backing this store; used by the engine's one wake scheduler.
    #[must_use]
    pub(crate) fn vault(&self) -> &'a Vault {
        self.vault
    }

    /// Enqueues a Dreamer attempt and records its private run-tree parent row in
    /// the same LMDB write transaction.
    pub fn enqueue(&self, input: EnqueueDreamerAttempt) -> Result<EnqueueDreamerAttemptOutcome> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.enqueue_with_task_ref_in_txn(&mut wtxn, input, None)?;
        wtxn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(outcome)
    }

    /// Transaction-composable enqueue carrying an owning TASK backlink, so
    /// ONE-1700's assignee routing can mint the TASK and its realizing agent
    /// dispatch in ONE transaction. Payload codec and run-tree behavior are
    /// exactly [`Self::enqueue`]'s; only `AttemptRecord.task_ref` differs.
    pub(crate) fn enqueue_with_task_ref_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueDreamerAttempt,
        task_ref: Option<String>,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        validate_attempt_type(&input.attempt_type)?;
        let payload = DreamerAttemptPayload {
            attempt_type: input.attempt_type,
            input: input.input,
            parent_attempt: input.parent_attempt,
        };
        let encoded_payload = encode_dreamer_attempt_payload(&payload)?;

        let outcome = crate::ports::JobQueue::port_job_enqueue_scoped(
            self.vault,
            wtxn,
            EnqueueAttempt {
                kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
                payload: encoded_payload,
                dedupe_key: input.dedupe_key,
                run_id: input.run_id,
                now: input.now,
            },
            crate::ports::JobScope {
                task_ref,
                dedupe_actor_ref: None,
            },
        )?;

        let record = match &outcome {
            EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record,
        };
        super::authority::stamp_attempt(self.vault, wtxn, record, &payload.attempt_type)?;

        match outcome {
            EnqueueOutcome::Enqueued(record) => {
                put_run_tree_record_in_txn(
                    self.vault,
                    wtxn,
                    &DreamerRunTreeRecord {
                        attempt_id: record.id,
                        parent_attempt: payload.parent_attempt,
                        created_at: record.created_at,
                    },
                )?;
                Ok(EnqueueDreamerAttemptOutcome::Enqueued(
                    decode_dreamer_attempt_status(record)?,
                ))
            }
            EnqueueOutcome::Existing(record) => {
                ensure_run_tree_record_in_txn(self.vault, wtxn, &record)?;
                Ok(EnqueueDreamerAttemptOutcome::Existing(
                    decode_dreamer_attempt_status(record)?,
                ))
            }
        }
    }

    /// Enqueues a local consolidation attempt on the advisory attempt-table floor.
    ///
    /// MICRO and MESO remain per-device because these queue rows are private
    /// runner state. MACRO uses the same advisory dedupe mechanics, but
    /// admission is restricted by [`Self::admit_next_consolidation`].
    pub fn enqueue_consolidation(
        &self,
        input: EnqueueDreamerConsolidationAttempt,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let macro_scope = input.scope == DreamerConsolidationScope::Macro;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.enqueue_consolidation_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.vault.store.notify_attempt_observers();
        if macro_scope {
            // A hint drives only Micro; Macro work arms through the deadline
            // lane, which re-reads on this watch.
            self.vault.store.notify_proactivity_changes();
        }
        Ok(outcome)
    }

    /// Enqueues a consolidation attempt in a caller-owned write transaction.
    pub(crate) fn enqueue_consolidation_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueDreamerConsolidationAttempt,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let requested_scope =
            crate::dreamer_consolidation::branch_scope::decode_branch_scope(&input.input)?;
        let requested_parent = input.parent_attempt;
        let outcome = self.enqueue_kind_in_txn(
            wtxn,
            input.scope.attempt_kind(),
            DreamerAttemptPayload {
                attempt_type: input.scope.as_str().to_owned(),
                input: input.input,
                parent_attempt: input.parent_attempt,
            },
            input.dedupe_key,
            input.run_id,
            input.now,
        )?;
        if let EnqueueDreamerAttemptOutcome::Existing(status) = &outcome
            && (status.payload.parent_attempt != requested_parent
                || crate::dreamer_consolidation::branch_scope::decode_branch_scope(
                    &status.payload.input,
                )? != requested_scope)
        {
            return Err(invalid_dreamer_runner(
                "consolidation dedupe cannot change branch scope or parent",
            ));
        }
        Ok(outcome)
    }

    /// Enqueues a SKILL-OPT maintenance attempt (ONE-1448) on its own queue
    /// kind, with the same advisory dedupe mechanics the consolidation lanes
    /// use.
    ///
    /// Its own kind rather than a payload discriminator on the generic queue:
    /// this is maintenance work on a wake cadence, and a kind of its own is
    /// what lets a runner admit it without racing the consolidation lanes for
    /// the same lease line.
    pub fn enqueue_skill_optimize(
        &self,
        input: EnqueueDreamerSkillOptimizeAttempt,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.enqueue_skill_optimize_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(outcome)
    }

    /// Enqueues a SKILL-OPT attempt in a caller-owned write transaction, so a
    /// wake that registers one lands it as a durable fact of the wake.
    pub(crate) fn enqueue_skill_optimize_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueDreamerSkillOptimizeAttempt,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.enqueue_kind_in_txn(
            wtxn,
            DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND,
            DreamerAttemptPayload {
                attempt_type: DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND.to_owned(),
                input: input.input,
                parent_attempt: input.parent_attempt,
            },
            input.dedupe_key,
            input.run_id,
            input.now,
        )
    }

    /// Wakes the Coach on one failure-ladder case: a `coach.heal` attempt whose
    /// input is the case ref, parented to the failing attempt and deduped per
    /// case, so a re-routed case finds the attempt it already woke.
    pub(crate) fn enqueue_coach_heal_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        case: &crate::failure_ladder::HealerCase,
        run_id: Option<String>,
        now: u64,
    ) -> Result<AttemptId> {
        let outcome = self.enqueue_kind_in_txn(
            wtxn,
            super::COACH_HEAL_ATTEMPT_KIND,
            DreamerAttemptPayload {
                attempt_type: super::COACH_HEAL_ATTEMPT_KIND.to_owned(),
                input: rmpv::Value::from(case.case_ref.as_str()),
                parent_attempt: Some(case.failing_attempt_id),
            },
            Some(format!(
                "{}:{}",
                super::COACH_HEAL_ATTEMPT_KIND,
                case.case_ref
            )),
            run_id,
            now,
        )?;
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
        Ok(status.attempt.id)
    }

    /// Queues the wake policy's receipt for `trigger`'s recipe in the
    /// policy's own commit, beside its outbox row and cursors. One receipt
    /// per decision: a receipt whose input a later one already consumed
    /// settles as nothing to do.
    pub(crate) fn enqueue_recipe_wake_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        trigger: &crate::dreamer_wake::WakePolicyTrigger,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let input = serde_json::to_string(trigger)
            .map_err(|_| invalid_dreamer_runner("dreamer recipe wake input is not encodable"))?;
        self.enqueue_kind_in_txn(
            wtxn,
            DREAMER_RECIPE_WAKE_ATTEMPT_KIND,
            DreamerAttemptPayload {
                attempt_type: DREAMER_RECIPE_WAKE_ATTEMPT_KIND.to_owned(),
                input: rmpv::Value::from(input),
                parent_attempt: None,
            },
            None,
            None,
            now,
        )
    }

    /// Co-commits a Timer/Macro wake and its cleanup attempt.
    pub(crate) fn enqueue_timer_wake(
        &self,
        payload: DreamerAttemptPayload,
        dedupe_key: Option<String>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let outcome = self.vault.with_write_txn_grouped(|wtxn| {
            crate::dreamer_wake::request_wake_in_txn(
                self,
                wtxn,
                WakeTrigger::Timer,
                payload,
                dedupe_key,
                run_id,
                now,
            )
        })?;
        // Timer work admits at Macro scope, which only the deadline lane drives.
        self.vault.store.notify_proactivity_changes();
        Ok(outcome)
    }

    /// Enqueues an ARCH-0073 vault-cleanup attempt (ONE-1931).
    ///
    /// TIMER-SCOPED registration: ARCH-0073 puts the cleanup pass on the timer
    /// wake (default scope Macro), and every other trigger is refused with
    /// [`MaintenanceError::VaultCleanupWakeTriggerRejected`](crate::error::MaintenanceError::VaultCleanupWakeTriggerRejected) rather than quietly
    /// accepted. The refusal is the registration — a maintenance scan that can
    /// be attached to any wake is a maintenance scan an interactive turn ends
    /// up paying for.
    ///
    /// # Errors
    ///
    /// [`MaintenanceError::VaultCleanupWakeTriggerRejected`](crate::error::MaintenanceError::VaultCleanupWakeTriggerRejected) for a non-timer trigger;
    /// storage errors.
    pub fn enqueue_vault_cleanup(
        &self,
        input: EnqueueDreamerVaultCleanupAttempt,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.enqueue_vault_cleanup_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(outcome)
    }

    /// Enqueues a vault-cleanup attempt in a caller-owned write transaction,
    /// so a wake that registers one lands it as a durable fact of the wake.
    ///
    /// # Errors
    ///
    /// [`MaintenanceError::VaultCleanupWakeTriggerRejected`](crate::error::MaintenanceError::VaultCleanupWakeTriggerRejected) for a non-timer trigger;
    /// storage errors.
    pub(crate) fn enqueue_vault_cleanup_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueDreamerVaultCleanupAttempt,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        if input.trigger != WakeTrigger::Timer {
            return Err(Error::Maintenance(
                MaintenanceError::VaultCleanupWakeTriggerRejected {
                    trigger: wake_trigger_name(input.trigger),
                },
            ));
        }
        self.enqueue_kind_in_txn(
            wtxn,
            DREAMER_VAULT_CLEANUP_ATTEMPT_KIND,
            DreamerAttemptPayload {
                attempt_type: DREAMER_VAULT_CLEANUP_ATTEMPT_KIND.to_owned(),
                input: input.input,
                parent_attempt: input.parent_attempt,
            },
            input.dedupe_key,
            input.run_id,
            input.now,
        )
    }

    /// Enqueues the NOTE review (OF-073) as a Nightly child in the wake's own
    /// commit. One review per wake key: the review pages through every NOTE
    /// itself, so a second one in the same night would read the same pages.
    pub(crate) fn enqueue_note_review_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<crate::attempt_queue::AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.enqueue_kind_in_txn(
            wtxn,
            DREAMER_NOTE_REVIEW_ATTEMPT_KIND,
            DreamerAttemptPayload {
                attempt_type: DREAMER_NOTE_REVIEW_ATTEMPT_KIND.to_owned(),
                input: rmpv::Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| format!("{DREAMER_NOTE_REVIEW_ATTEMPT_KIND}:{key}")),
            run_id,
            now,
        )
    }

    /// Enqueues `resident`'s own dreaming (OF-490) as a Nightly child in the
    /// wake's own commit: one per resident per wake key. The resident's
    /// stamp binds at enqueue.
    pub(crate) fn enqueue_resident_dream_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        resident: crate::EntityId,
        parent_attempt: Option<crate::attempt_queue::AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.enqueue_kind_in_txn(
            wtxn,
            DREAMER_RESIDENT_DREAM_ATTEMPT_KIND,
            DreamerAttemptPayload {
                attempt_type: DREAMER_RESIDENT_DREAM_ATTEMPT_KIND.to_owned(),
                input: crate::dreamer_consolidation::resident_dream_input(resident),
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{DREAMER_RESIDENT_DREAM_ATTEMPT_KIND}:{}:{key}",
                    resident.to_hex()
                )
            }),
            run_id,
            now,
        )
    }

    /// Enqueues the weave lens's generate step for one published digest
    /// period (OF-499), in the publication's own commit: one per period
    /// render.
    pub(crate) fn enqueue_weave_lens_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        reader: crate::claim::WeaveDigestReader,
        scheduled_for: u64,
        rendered_at: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let input = crate::claim::weave_lens_attempt_input(reader, scheduled_for, rendered_at);
        let dedupe = format!(
            "{DREAMER_WEAVE_LENS_ATTEMPT_KIND}:{}:{scheduled_for}:{rendered_at}",
            reader.id().to_hex()
        );
        self.enqueue_kind_in_txn(
            wtxn,
            DREAMER_WEAVE_LENS_ATTEMPT_KIND,
            DreamerAttemptPayload {
                attempt_type: DREAMER_WEAVE_LENS_ATTEMPT_KIND.to_owned(),
                input,
                parent_attempt: None,
            },
            Some(dedupe),
            None,
            rendered_at,
        )
    }

    /// The one enqueue law for a kind-scoped Dreamer lane: encode the payload,
    /// take the advisory dedupe floor, and co-commit the private run-tree row
    /// whichever way the queue answered.
    pub(crate) fn enqueue_kind_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        queue_kind: &str,
        payload: DreamerAttemptPayload,
        dedupe_key: Option<String>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let encoded_payload = encode_dreamer_attempt_payload(&payload)?;

        let outcome = crate::ports::JobQueue::port_job_enqueue(
            self.vault,
            wtxn,
            EnqueueAttempt {
                kind: queue_kind.to_owned(),
                payload: encoded_payload,
                dedupe_key,
                run_id,
                now,
            },
        )?;

        let record = match &outcome {
            EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record,
        };
        super::authority::stamp_attempt(self.vault, wtxn, record, &payload.attempt_type)?;

        match outcome {
            EnqueueOutcome::Enqueued(record) => {
                put_run_tree_record_in_txn(
                    self.vault,
                    wtxn,
                    &DreamerRunTreeRecord {
                        attempt_id: record.id,
                        parent_attempt: payload.parent_attempt,
                        created_at: record.created_at,
                    },
                )?;
                Ok(EnqueueDreamerAttemptOutcome::Enqueued(
                    decode_dreamer_attempt_status(record)?,
                ))
            }
            EnqueueOutcome::Existing(record) => {
                ensure_run_tree_record_in_txn(self.vault, wtxn, &record)?;
                Ok(EnqueueDreamerAttemptOutcome::Existing(
                    decode_dreamer_attempt_status(record)?,
                ))
            }
        }
    }

    pub(crate) fn defer_selection(
        &self,
        admitted: &super::DreamerAdmittedAttempt,
        budget: super::SettleDreamerBudget,
        retry_at: u64,
    ) -> Result<()> {
        let source = &admitted.status.attempt;
        if budget.child_attempt != source.id || retry_at <= budget.now {
            return Err(invalid_dreamer_runner("invalid selection retry"));
        }
        self.vault.with_write_txn_grouped(|txn| {
            self.settle_budget_in_txn(txn, budget.clone())?;
            let crate::attempt_queue::RetryOutcome::Retried(record) = self.attempts.retry_in_txn(
                txn,
                crate::attempt_queue::RetryAttempt {
                    id: source.id,
                    lease_owner: source
                        .lease_owner
                        .clone()
                        .ok_or_else(|| invalid_dreamer_runner("selection retry missing lease"))?,
                    attempt_count: source.attempt_count,
                    backoff_until: retry_at,
                    last_error: Some("consolidation selection deferred".into()),
                    now: budget.now,
                },
            )?;
            super::authority::stamp_attempt(
                self.vault,
                txn,
                &record,
                &admitted.status.payload.attempt_type,
            )?;
            crate::dreamer_consolidation::branch_scope::inherit_retry_scope_in_txn(
                self.vault, txn, source.id, record.id,
            )?;
            // The source never runs again; its retry lists afresh.
            crate::dreamer_consolidation::unpin_neighbourhood_in_txn(self.vault, txn, source.id)?;
            ensure_run_tree_record_in_txn(self.vault, txn, &record)?;
            Ok(())
        })
    }

    /// Marks a leased Dreamer attempt complete through the generic queue.
    pub fn complete(&self, input: CompleteDreamerAttempt) -> Result<CompleteDreamerAttemptOutcome> {
        self.complete_judged(input, None)
    }

    /// [`Self::complete`], with the runner's answer to its TASK's "Done means
    /// met?" ([`crate::task_verb::runner_done_question`]), asked before this
    /// write. Without one, a TASK with a brief asks up.
    pub fn complete_judged(
        &self,
        input: CompleteDreamerAttempt,
        judged: Option<crate::task_verb::RunnerDoneAnswer>,
    ) -> Result<CompleteDreamerAttemptOutcome> {
        use crate::task_verb::highway_runner::RunnerSettle;
        self.ensure_terminal_transition_target(input.id)?;
        let attempt_id = input.id;
        let outcome = self.vault.with_write_txn_grouped(|wtxn| {
            // OF-220: a TASK's durable result lands before the lease clears.
            crate::task_verb::highway_runner::report_leased_task_in_txn(
                self.vault,
                wtxn,
                attempt_id,
                judged.map_or(RunnerSettle::Done, RunnerSettle::Judged),
            )?;
            let outcome = crate::ports::JobQueue::port_job_complete(
                self.vault,
                wtxn,
                CompleteAttempt {
                    id: input.id,
                    lease_owner: input.lease_owner,
                    attempt_count: input.attempt_count,
                    now: input.now,
                },
            )?;
            self.cleanup_step_receipts_in_txn(wtxn, attempt_id)?;
            // A finished agent launch settles its spend lease (OF-532) in the
            // commit that finishes it: its parent pays what it spent and the
            // unused hold goes back. Settling twice is a no-op.
            let record = match &outcome {
                CompleteOutcome::Completed(record) | CompleteOutcome::AlreadyCompleted(record) => {
                    record
                }
            };
            if decode_dreamer_attempt_payload(&record.payload).is_ok_and(|payload| {
                payload.attempt_type == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE
            }) {
                crate::agent_dispatch::AgentDispatcher::new(self.vault).settle_child_in_txn(
                    wtxn,
                    &attempt_id,
                    input.now,
                )?;
            }
            Ok(outcome)
        })?;
        match outcome {
            CompleteOutcome::Completed(record) => {
                self.vault.store.notify_attempt_observers();
                Ok(CompleteDreamerAttemptOutcome::Completed(
                    decode_dreamer_attempt_status(record)?,
                ))
            }
            CompleteOutcome::AlreadyCompleted(record) => {
                Ok(CompleteDreamerAttemptOutcome::AlreadyCompleted(
                    decode_dreamer_attempt_status(record)?,
                ))
            }
        }
    }

    /// Routes a leased agent-dispatch failure using producer-supplied typed
    /// detector evidence. The caller supplies the real checkpoint, Q&A thread,
    /// backoff and scope policy; this door never infers a verdict from prose.
    /// Other Dreamer jobs retain the ordinary `fail` door.
    pub fn fail_agent_dispatch_with_evidence(
        &self,
        input: crate::failure_ladder::HandleAttemptFailure,
        policy: crate::failure_ladder::FailureScopePolicy,
    ) -> Result<crate::failure_ladder::FailureLadderOutcome> {
        self.ensure_terminal_transition_target(input.attempt_id)?;
        crate::failure_ladder::FailureLadder::new(self.vault).handle_attempt_failure(input, policy)
    }

    /// Atomically retries a typed agent failure together with its runner tree
    /// and authority scope. A generic queue retry alone would orphan these
    /// Dreamer-owned rows on the newly scheduled attempt.
    pub(crate) fn retry_agent_dispatch_failure(
        &self,
        input: crate::attempt_queue::RetryAttempt,
    ) -> Result<AttemptRecord> {
        self.vault.with_write_txn_grouped(|txn| {
            let source = self
                .attempts
                .get_in_write_txn(txn, input.id)?
                .ok_or(invalid_dreamer_runner("agent retry source must exist"))?;
            let payload = decode_dreamer_attempt_payload(&source.payload)?;
            if payload.attempt_type != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
                return Err(invalid_dreamer_runner(
                    "agent retry requires a dispatch attempt",
                ));
            }
            // OF-220: the TASK requeues before its try's lease clears.
            crate::task_verb::highway_runner::report_leased_task_in_txn(
                self.vault,
                txn,
                source.id,
                crate::task_verb::highway_runner::RunnerSettle::Failed {
                    error: input.last_error.as_deref().unwrap_or_default(),
                    retryable: true,
                },
            )?;
            let crate::attempt_queue::RetryOutcome::Retried(record) =
                self.attempts.retry_in_txn(txn, input)?;
            super::authority::stamp_attempt(self.vault, txn, &record, &payload.attempt_type)?;
            crate::dreamer_consolidation::branch_scope::inherit_retry_scope_in_txn(
                self.vault, txn, source.id, record.id,
            )?;
            ensure_run_tree_record_in_txn(self.vault, txn, &record)?;
            self.cleanup_step_receipts_in_txn(txn, source.id)?;
            Ok(record)
        })
    }

    /// Marks a leased Dreamer attempt terminally failed through the generic queue.
    pub fn fail(&self, input: FailDreamerAttempt) -> Result<FailDreamerAttemptOutcome> {
        self.ensure_terminal_transition_target(input.id)?;
        let attempt_id = input.id;
        let outcome =
            self.vault.with_write_txn_grouped(|wtxn| {
                let record = self.attempts.get_in_write_txn(wtxn, attempt_id)?.ok_or(
                    invalid_dreamer_runner("dreamer terminal transition attempt must exist"),
                )?;
                let payload = decode_dreamer_attempt_payload(&record.payload)?;
                if payload.attempt_type == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
                    return Err(invalid_dreamer_runner(
                        "agent dispatch failures require typed detector evidence",
                    ));
                }
                // OF-220: the TASK fails before its try's lease clears.
                crate::task_verb::highway_runner::report_leased_task_in_txn(
                    self.vault,
                    wtxn,
                    attempt_id,
                    crate::task_verb::highway_runner::RunnerSettle::Failed {
                        error: &input.reason,
                        retryable: false,
                    },
                )?;
                let outcome = crate::ports::JobQueue::port_job_fail(
                    self.vault,
                    wtxn,
                    FailAttempt {
                        id: input.id,
                        lease_owner: input.lease_owner,
                        attempt_count: input.attempt_count,
                        reason: input.reason,
                        now: input.now,
                    },
                )?;
                self.cleanup_step_receipts_in_txn(wtxn, attempt_id)?;
                Ok(outcome)
            })?;
        match outcome {
            FailOutcome::Failed(record) => {
                self.vault.store.notify_attempt_observers();
                Ok(FailDreamerAttemptOutcome::Failed(
                    decode_dreamer_attempt_status(record)?,
                ))
            }
            FailOutcome::AlreadyFailed(record) => Ok(FailDreamerAttemptOutcome::AlreadyFailed(
                decode_dreamer_attempt_status(record)?,
            )),
        }
    }

    fn ensure_terminal_transition_target(&self, id: AttemptId) -> Result<()> {
        let record = self.attempts.get(id)?.ok_or(invalid_dreamer_runner(
            "dreamer terminal transition attempt must exist",
        ))?;
        decode_dreamer_attempt_status(record).map(|_| ())
    }

    /// Reads one Dreamer attempt by queue id.
    pub fn status(&self, id: AttemptId) -> Result<Option<DreamerAttemptStatus>> {
        self.attempts
            .get(id)?
            .map(decode_dreamer_attempt_status)
            .transpose()
    }

    /// Reads a private Dreamer run-tree row.
    pub fn run_tree(&self, attempt_id: AttemptId) -> Result<Option<DreamerRunTreeRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        RUN_TREE.get(&self.vault.store, &rtxn, &attempt_id)
    }

    /// Parks a Dreamer attempt in private runner state without changing the
    /// generic queue row.
    ///
    /// A row already parked by a DIFFERENT owner is never overwritten
    /// (fail-closed error); the same owner may re-park to refresh the row.
    pub fn park_attempt(&self, input: ParkDreamerAttempt) -> Result<DreamerParkedAttemptRecord> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let record = self.park_attempt_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(record)
    }

    pub(crate) fn park_attempt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: ParkDreamerAttempt,
    ) -> Result<DreamerParkedAttemptRecord> {
        validate_park_reason(&input.reason)?;
        validate_park_owner(&input.park_owner)?;
        if self.status(input.attempt_id)?.is_none() {
            return Err(invalid_dreamer_runner("dreamer parked attempt must exist"));
        }

        let record = DreamerParkedAttemptRecord {
            attempt_id: input.attempt_id,
            reason: input.reason,
            cause: input.cause,
            park_owner: input.park_owner,
            parked_at: input.now,
        };
        let existing = PARKED.get(&self.vault.store, &*wtxn, &record.attempt_id)?;
        if let Some(existing) = existing
            && existing.park_owner != record.park_owner
        {
            return Err(invalid_dreamer_runner(
                "dreamer parked row is owned by a different parker",
            ));
        }
        PARKED.put(self.vault, wtxn, &record.attempt_id, &record)?;
        Ok(record)
    }

    /// Clears a parked-attempt row and queues the attempt again as the same
    /// try, so the normal admission path takes it (ONE-1288) and its step
    /// memo, keyed by its id, still holds.
    ///
    /// Returns the attempt status when a parked row was cleared. An attempt with NO
    /// parked row is an idempotent no-op: `Ok(None)`, nothing mutated
    /// (pinned). A row parked by a DIFFERENT owner than `park_owner` is a
    /// fail-closed error, nothing deleted. A park is not a running lease:
    /// whoever holds the row's lease stopped at the park, so the lease is
    /// released whoever it names. `now` is accepted for symmetry with the
    /// other transition inputs.
    pub fn resume_parked(
        &self,
        attempt_id: AttemptId,
        park_owner: &str,
        now: u64,
    ) -> Result<Option<DreamerAttemptStatus>> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let resumed = self.resume_parked_in_txn(&mut wtxn, attempt_id, park_owner, now)?;
        wtxn.commit()?;
        self.vault.store.notify_attempt_observers();
        if resumed.is_some() {
            // The deadline lane arms the queued try at once.
            self.vault.store.notify_proactivity_changes();
        }
        Ok(resumed)
    }

    /// Transaction-composable body of [`Self::resume_parked`], so the trap
    /// consume path (ONE-1343) can commit the `consumed` transition and this
    /// un-park in ONE wtxn.
    pub(crate) fn resume_parked_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        attempt_id: AttemptId,
        park_owner: &str,
        _now: u64,
    ) -> Result<Option<DreamerAttemptStatus>> {
        let Some(record) = PARKED.get(&self.vault.store, &*wtxn, &attempt_id)? else {
            return Ok(None);
        };
        if record.park_owner != park_owner {
            return Err(invalid_dreamer_runner(
                "dreamer parked row is owned by a different parker",
            ));
        }
        let status = self
            .status(attempt_id)?
            .ok_or(invalid_dreamer_runner("dreamer resumed attempt must exist"))?;
        PARKED.delete(&self.vault.store, wtxn, &attempt_id)?;
        if let Some(lease_owner) = status.attempt.lease_owner.as_deref() {
            // Callers pass their own clock (the trap layer's counts
            // milliseconds); the queue row keeps the vault's seconds.
            let at = self.vault.store.clock.now_recorded_at();
            self.attempts
                .release_lease_in_txn(wtxn, attempt_id, lease_owner, at)?;
        }
        Ok(Some(status))
    }

    /// Reads a private parked-attempt row.
    pub fn parked_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<DreamerParkedAttemptRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        PARKED.get(&self.vault.store, &rtxn, &attempt_id)
    }

    /// Whether `attempt_id` holds a parked row at `txn`'s revision.
    pub(crate) fn is_parked_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt_id: AttemptId,
    ) -> Result<bool> {
        Ok(PARKED.get(&self.vault.store, txn, &attempt_id)?.is_some())
    }

    /// Pure proposal step. This method performs no LMDB write and enqueues no
    /// attempt.
    ///
    /// It hands already-decoded claim descriptors to [`crate::cluster`] and
    /// returns the cohort assignments unchanged. A cohort is an OBSERVATION —
    /// "these claims look like they are about the same thing" — not an
    /// instruction. The Dreamer alone decides whether to merge, split,
    /// accumulate, or escalate, and this adapter deliberately offers no verb
    /// for any of those.
    pub fn propose_claim_cohorts(
        &self,
        claims: &[crate::cluster::ClusterClaim],
        options: crate::cluster::ClusterOptions,
    ) -> Result<crate::cluster::ClusterAssignments> {
        crate::cluster::cluster_claims(claims, options)
    }
}

pub(super) fn decode_dreamer_attempt_status(record: AttemptRecord) -> Result<DreamerAttemptStatus> {
    // A TASK's realization carries the TASK's bare spec, not the runner
    // envelope: its status reads that spec as its input, with no parent.
    if record.kind == DREAMER_TASK_REALIZE_ATTEMPT_KIND {
        let input = super::codec::decode_value(&record.payload)?;
        return Ok(DreamerAttemptStatus {
            attempt: record,
            payload: DreamerAttemptPayload {
                attempt_type: DREAMER_TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                input,
                parent_attempt: None,
            },
        });
    }
    if !is_dreamer_queue_kind(&record.kind) {
        return Err(invalid_dreamer_runner(
            "attempt is not a Dreamer runner attempt",
        ));
    }
    let payload = decode_dreamer_attempt_payload(&record.payload)?;
    Ok(DreamerAttemptStatus {
        attempt: record,
        payload,
    })
}

fn is_dreamer_queue_kind(kind: &str) -> bool {
    kind == super::connector_event::CONNECTOR_EVENT_QUEUE_KIND
        || kind == super::maintenance::MAINTENANCE_QUEUE_KIND
        || kind == DREAMER_RUNNER_ATTEMPT_KIND
        || kind == DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND
        || kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND
        || kind == DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND
        || kind == DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND
        || kind == DREAMER_WEAVE_RECIPE_ATTEMPT_KIND
        || kind == DREAMER_RECIPE_WAKE_ATTEMPT_KIND
        || kind == DREAMER_VAULT_CLEANUP_ATTEMPT_KIND
        || kind == DREAMER_NOTE_REVIEW_ATTEMPT_KIND
        || kind == DREAMER_RESIDENT_DREAM_ATTEMPT_KIND
        || kind == DREAMER_WEAVE_LENS_ATTEMPT_KIND
        || kind == super::COACH_HEAL_ATTEMPT_KIND
        || kind == super::maintenance::coach::COACH_HOST_QUEUE_KIND
}

/// The refusal-facing name of a wake trigger.
///
/// Its own function rather than `{:?}`: the string lands in a typed error a
/// caller may match on, so it must not drift with a derive.
const fn wake_trigger_name(trigger: WakeTrigger) -> &'static str {
    match trigger {
        WakeTrigger::Compaction => "compaction",
        WakeTrigger::SessionEnd => "session_end",
        WakeTrigger::Event => "event",
        WakeTrigger::Timer => "timer",
    }
}

fn ensure_run_tree_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    if RUN_TREE.contains(&vault.store, &*wtxn, &record.id)? {
        return Ok(());
    }
    let status = decode_dreamer_attempt_status(record.clone())?;
    put_run_tree_record_in_txn(
        vault,
        wtxn,
        &DreamerRunTreeRecord {
            attempt_id: status.attempt.id,
            parent_attempt: status.payload.parent_attempt,
            created_at: status.attempt.created_at,
        },
    )
}

fn put_run_tree_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerRunTreeRecord,
) -> Result<()> {
    RUN_TREE.put(&vault.store, wtxn, &record.attempt_id, record)
}
