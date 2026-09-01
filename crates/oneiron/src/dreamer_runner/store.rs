//! The Dreamer runner store: queue lifecycle, park/resume, and readers.

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, FailAttempt, FailOutcome,
};
use crate::error::Result;

use super::codec::{
    decode_dreamer_attempt_payload, decode_parked_record, decode_run_tree_record,
    encode_dreamer_attempt_payload, encode_parked_record, encode_run_tree_record,
    invalid_dreamer_runner, parked_key, run_tree_key, validate_attempt_type, validate_park_owner,
    validate_park_reason,
};
use super::constants::{
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DREAMER_RUNNER_ATTEMPT_KIND,
    DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND,
};
use super::types::{
    CompleteDreamerAttempt, CompleteDreamerAttemptOutcome, DreamerAttemptPayload,
    DreamerAttemptStatus, DreamerParkedAttemptRecord, DreamerRunTreeRecord, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    EnqueueDreamerSkillOptimizeAttempt, FailDreamerAttempt, FailDreamerAttemptOutcome,
    ParkDreamerAttempt,
};

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

    /// Enqueues a Dreamer attempt and records its private run-tree parent row in
    /// the same LMDB write transaction.
    pub fn enqueue(&self, input: EnqueueDreamerAttempt) -> Result<EnqueueDreamerAttemptOutcome> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.enqueue_with_task_ref_in_txn(&mut wtxn, input, None)?;
        wtxn.commit()?;
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

        let outcome = self.attempts.enqueue_with_task_ref_in_txn(
            wtxn,
            EnqueueAttempt {
                kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
                payload: encoded_payload,
                dedupe_key: input.dedupe_key,
                run_id: input.run_id,
                now: input.now,
            },
            task_ref,
        )?;

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
        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.enqueue_consolidation_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Enqueues a consolidation attempt in a caller-owned write transaction.
    pub(crate) fn enqueue_consolidation_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueDreamerConsolidationAttempt,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.enqueue_kind_in_txn(
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
        )
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

    /// The one enqueue law for a kind-scoped Dreamer lane: encode the payload,
    /// take the advisory dedupe floor, and co-commit the private run-tree row
    /// whichever way the queue answered.
    fn enqueue_kind_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        queue_kind: &str,
        payload: DreamerAttemptPayload,
        dedupe_key: Option<String>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let encoded_payload = encode_dreamer_attempt_payload(&payload)?;

        let outcome = self.attempts.enqueue_in_txn(
            wtxn,
            EnqueueAttempt {
                kind: queue_kind.to_owned(),
                payload: encoded_payload,
                dedupe_key,
                run_id,
                now,
            },
        )?;

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

    /// Marks a leased Dreamer attempt complete through the generic queue.
    pub fn complete(&self, input: CompleteDreamerAttempt) -> Result<CompleteDreamerAttemptOutcome> {
        self.ensure_terminal_transition_target(input.id)?;
        match self.attempts.complete(CompleteAttempt {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            now: input.now,
        })? {
            CompleteOutcome::Completed(record) => Ok(CompleteDreamerAttemptOutcome::Completed(
                decode_dreamer_attempt_status(record)?,
            )),
            CompleteOutcome::AlreadyCompleted(record) => {
                Ok(CompleteDreamerAttemptOutcome::AlreadyCompleted(
                    decode_dreamer_attempt_status(record)?,
                ))
            }
        }
    }

    /// Marks a leased Dreamer attempt terminally failed through the generic queue.
    pub fn fail(&self, input: FailDreamerAttempt) -> Result<FailDreamerAttemptOutcome> {
        self.ensure_terminal_transition_target(input.id)?;
        match self.attempts.fail(FailAttempt {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            reason: input.reason,
            now: input.now,
        })? {
            FailOutcome::Failed(record) => Ok(FailDreamerAttemptOutcome::Failed(
                decode_dreamer_attempt_status(record)?,
            )),
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
        let key = run_tree_key(attempt_id);
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_run_tree_record(&raw).map(Some)
    }

    /// Parks a Dreamer attempt in private runner state without changing the
    /// generic queue row.
    ///
    /// A row already parked by a DIFFERENT owner is never overwritten
    /// (fail-closed error); the same owner may re-park to refresh the row.
    pub fn park_attempt(&self, input: ParkDreamerAttempt) -> Result<DreamerParkedAttemptRecord> {
        validate_park_reason(&input.reason)?;
        validate_park_owner(&input.park_owner)?;
        if self.status(input.attempt_id)?.is_none() {
            return Err(invalid_dreamer_runner("dreamer parked attempt must exist"));
        }

        let record = DreamerParkedAttemptRecord {
            attempt_id: input.attempt_id,
            reason: input.reason,
            park_owner: input.park_owner,
            parked_at: input.now,
        };
        let encoded = encode_parked_record(&record)?;
        let key = parked_key(record.attempt_id);
        let mut wtxn = self.vault.store.env.write_txn()?;
        let existing = self
            .vault
            .store
            .vault_meta
            .get(&wtxn, &key)?
            .map(|raw| decode_parked_record(&raw))
            .transpose()?;
        if let Some(existing) = existing
            && existing.park_owner != record.park_owner
        {
            return Err(invalid_dreamer_runner(
                "dreamer parked row is owned by a different parker",
            ));
        }
        self.vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Clears a parked-attempt row so the attempt becomes admissible again through
    /// the normal admission path (ONE-1288).
    ///
    /// Returns the attempt status when a parked row was cleared. An attempt with NO
    /// parked row is an idempotent no-op: `Ok(None)`, nothing mutated
    /// (pinned). A row parked by a DIFFERENT owner than `park_owner` is a
    /// fail-closed error, nothing deleted. `now` is accepted for symmetry
    /// with the other transition inputs; the queue row is not touched —
    /// re-admission re-leases it.
    pub fn resume_parked(
        &self,
        attempt_id: AttemptId,
        park_owner: &str,
        now: u64,
    ) -> Result<Option<DreamerAttemptStatus>> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let resumed = self.resume_parked_in_txn(&mut wtxn, attempt_id, park_owner, now)?;
        wtxn.commit()?;
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
        let key = parked_key(attempt_id);
        let Some(raw) = self.vault.store.vault_meta.get(wtxn, &key)? else {
            return Ok(None);
        };
        let record = decode_parked_record(&raw)?;
        if record.park_owner != park_owner {
            return Err(invalid_dreamer_runner(
                "dreamer parked row is owned by a different parker",
            ));
        }
        let status = self
            .status(attempt_id)?
            .ok_or(invalid_dreamer_runner("dreamer resumed attempt must exist"))?;
        self.vault.store.vault_meta.delete(wtxn, &key)?;
        Ok(Some(status))
    }

    /// Reads a private parked-attempt row.
    pub fn parked_attempt(
        &self,
        attempt_id: AttemptId,
    ) -> Result<Option<DreamerParkedAttemptRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let key = parked_key(attempt_id);
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_parked_record(&raw).map(Some)
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
    kind == DREAMER_RUNNER_ATTEMPT_KIND
        || kind == DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND
        || kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND
        || kind == DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND
        || kind == DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND
}

fn ensure_run_tree_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    let key = run_tree_key(record.id);
    if vault.store.vault_meta.get(&*wtxn, &key)?.is_some() {
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
    let encoded = encode_run_tree_record(record)?;
    let key = run_tree_key(record.attempt_id);
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}
