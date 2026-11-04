//! The durable connector reply job (FIX 2405). A Dreamer pass that wakes an
//! agent on a message it should answer only hands the reply off: it queues
//! one job per (agent, event) and settles at once, spending nothing. The
//! host's reply worker claims the job off the pass, generates (or reuses the
//! kept body), dispatches through the ordinary recorded pipeline and keeps a
//! result naming what happened and what the model calls actually spent.
//!
//! The queue is the source of truth: a job survives a restart, and a rerun
//! after one reuses the kept body and replays the logical send, so it never
//! asks the model twice or sends twice. A held or failed send, and a fault
//! the job may get past on its own, wait in the queue and run again after a
//! backoff, as the Dreamer pass once resumed its parked wake; an ambiguous
//! send, or a fault that waits on the owner, ends the job failed.
//!
//! Erase reaches the job (FIX 2405): a hard erase of its agent, its
//! receiving identity, its actor or its known counterparty leaves the job's
//! event without its payload and takes the job's result with it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, CompleteAttempt, EnqueueAttempt, EnqueueOutcome, FailAttempt,
    RequeueAttempt, SetAttemptResult,
};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::connector_key::events::ConnectorEvent;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::store::Store;
use crate::surface_event::{SurfaceConnectorPayload, SurfaceCounterpartyStamp};
use crate::{EntityId, TimeRange, Vault, WriteActor};

/// The attempt kind a connector reply job is queued under.
pub const CONNECTOR_REPLY_JOB_KIND: &str = "connector.reply";
/// Every job result ref starts with this: `connector-reply-result:<artifact hex>`.
pub const CONNECTOR_REPLY_RESULT_PREFIX: &str = "connector-reply-result:";
/// Domain of a job's base dedupe and run key over (agent, event); generated
/// work uses it as is, a chosen request suffixes its reply ref (see
/// [`ConnectorReplyJob::queue_key`]).
const CONNECTOR_REPLY_JOB_KEY_DOMAIN: &[u8] = b"oneiron.connector-reply-job.v1\0";
/// Domain binding a chosen request identity to its exact words.
const CONNECTOR_REPLY_CHOSEN_REF_DOMAIN: &[u8] = b"oneiron.connector-reply-chosen-ref.v1\0";
/// Domain of a job result's artifact id: one per job attempt.
const CONNECTOR_REPLY_RESULT_DOMAIN: &[u8] = b"oneiron:connector-reply-job-result:v1";
const CONNECTOR_REPLY_RESULT_MEDIA_TYPE: &str = "application/json";
/// The lease owner the host's reply worker claims jobs as.
const CONNECTOR_REPLY_JOB_LEASE_OWNER: &str = "connector-reply-worker";
/// How old a lease must be before a pass returns it to the queue. The
/// worker holds none between passes, so any lease at least this old is
/// left behind; the queue takes no zero.
const CONNECTOR_REPLY_LEASE_RECLAIM_SECS: u64 = 1;
/// The wait before a requeued job's first rerun; each rerun after it waits
/// twice as long, up to [`CONNECTOR_REPLY_RETRY_MAX_SECS`]. The reply
/// worker's own backoff.
const CONNECTOR_REPLY_RETRY_FIRST_SECS: u64 = 1;
const CONNECTOR_REPLY_RETRY_MAX_SECS: u64 = 60;
/// The longest reason an attempt row's record holds (the queue's own
/// format bound); the whole reason stays in the job's result and the
/// worker's log.
const CONNECTOR_REPLY_QUEUE_REASON_BYTES: usize = 2048;

/// One agent's reply to one connector event: either generated off the Dreamer
/// pass that woke the agent, or the exact words a user chose for one request.
/// A chosen job names its words' kept-body slot: the body is kept first and
/// read back byte-exact before queueing (positive resume, not atomic). The
/// worker reuses the kept body and dispatches through the ordinary recorded
/// pipeline. Queueing is not delivery; the queue owns the work, the blob owns
/// the words, and the job's result names what happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorReplyJob {
    pub agent: EntityId,
    pub event: ConnectorEvent,
    /// How the reply's words arise: generated off the wake, or chosen exactly.
    pub source: ConnectorReplyJobSource,
}

/// Where one reply job's words come from (format change, no legacy reader:
/// rows written before the source split, or chosen rows that carried raw
/// text, do not decode).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConnectorReplyJobSource {
    /// The Dreamer pass that woke the agent hands the reply off; the worker
    /// generates (or reuses the kept body). Unchanged automatic behavior.
    Generated {
        /// The wake attempt that handed the reply off.
        parent_attempt: AttemptId,
        /// The 80%/95% budget messages the wake's charge fired (FIX 3761),
        /// shown to the agent's reply turn. Empty when none fired.
        budget_steering: Vec<String>,
    },
    /// The exact words a user chose for one request, kept in the request's
    /// slot before queueing; the payload names the slot, never the words.
    Chosen {
        /// Request-namespaced reply slot (`inbox:<digest>` over request
        /// identity + exact text); retries of one request share it and replay.
        reply_ref: String,
        /// The kept body the enqueue read back; cleared when event payload is erased.
        body_ref: String,
        /// When the kept body was written.
        written_at: u64,
        /// blake3 hex of the exact input bytes (mechanical id, not content).
        text_hash: String,
    },
}

impl ConnectorReplyJob {
    /// The ids the job names, whose erase takes its event payload: its
    /// agent, and the event's actor, receiving identity and known
    /// counterparty, as far as the event still decodes.
    pub(crate) fn named_ids(&self) -> Vec<EntityId> {
        let mut ids = vec![self.agent];
        if let Ok(origin) = SurfaceConnectorPayload::from_connector_event(&self.event) {
            let known = match &origin.counterparty {
                SurfaceCounterpartyStamp::Known { counterparty_ref } => {
                    EntityId::from_hex(counterparty_ref).ok()
                }
                SurfaceCounterpartyStamp::Unknown { .. }
                | SurfaceCounterpartyStamp::Unparsed { .. } => None,
            };
            ids.extend(
                [origin.actor().ok(), origin.receiving_identity().ok(), known]
                    .into_iter()
                    .flatten(),
            );
        }
        ids
    }

    /// The automatic `"reply"` slot or the chosen request's namespaced ref.
    pub fn reply_ref(&self) -> &str {
        match &self.source {
            ConnectorReplyJobSource::Generated { .. } => "reply",
            ConnectorReplyJobSource::Chosen { reply_ref, .. } => reply_ref,
        }
    }

    /// The kept body this chosen job resumes, rebuilt from its pointer.
    pub fn chosen_body(&self) -> Option<super::ConnectorReplyBody> {
        match &self.source {
            ConnectorReplyJobSource::Generated { .. } => None,
            ConnectorReplyJobSource::Chosen {
                body_ref,
                written_at,
                ..
            } => Some(super::ConnectorReplyBody {
                content_ref: body_ref.clone(),
                written_at: *written_at,
            }),
        }
    }

    /// The blake3 of the exact chosen input bytes, when this job names it.
    pub fn chosen_text_hash(&self) -> Option<&str> {
        match &self.source {
            ConnectorReplyJobSource::Generated { .. } => None,
            ConnectorReplyJobSource::Chosen { text_hash, .. } => Some(text_hash),
        }
    }

    /// The wake's budget messages for the reply turn; empty for chosen words.
    pub fn budget_steering(&self) -> &[String] {
        match &self.source {
            ConnectorReplyJobSource::Generated {
                budget_steering, ..
            } => budget_steering,
            ConnectorReplyJobSource::Chosen { .. } => &[],
        }
    }

    /// The automatic key, or that key plus the chosen request's reply ref.
    fn queue_key(&self) -> String {
        let base = connector_reply_job_key(self.agent, &self.event.event_id);
        match &self.source {
            ConnectorReplyJobSource::Generated { .. } => base,
            ConnectorReplyJobSource::Chosen { reply_ref, .. } => format!("{base}:{reply_ref}"),
        }
    }
}

/// Where a reply job ended. The outbound receipt stays the authority on
/// the send itself; this names which way the job went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorReplyStage {
    /// The event is not one the agent answers, or it wrote no reply.
    NoReply,
    /// The reply left through the recorded dispatch (delivered, degraded,
    /// suppressed or let go: see `outcome`).
    Dispatched,
    /// The Gate held the reply; the job runs again after a backoff, and
    /// the send goes once the hold is gone.
    Held,
    /// The send failed; the job runs again after a backoff.
    Failed,
    /// The send may have landed; the job ends failed and waits for a look,
    /// never a resend.
    Ambiguous,
    /// The job could not run: the agent, the model or the vault failed. It
    /// runs again after a backoff, unless the failure waits on the owner
    /// (`waits_on_owner`), which ends it failed.
    Fault,
}

/// What one reply job did, kept as its attempt's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorReplyJobResult {
    pub stage: ConnectorReplyStage,
    /// The kept reply body, when the agent wrote one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_ref: Option<String>,
    /// The dispatch outcome the outbound receipt names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gate_reason_codes: Vec<String>,
    /// Units this job's model calls spent on the agent's line, failed rungs
    /// included; zero when the body was already kept.
    pub actual_units: u64,
    /// The conversation rows the exchange was witnessed into.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_refs: Vec<String>,
    /// A witness write that did not land and is owed a repair; the send
    /// went on regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_repair: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// A fault only the owner can clear (an authority, consent, secret or
    /// disabled-agent refusal), as a parked wake once waited on the owner.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub waits_on_owner: bool,
}

impl ConnectorReplyJobResult {
    /// A job that ended at `stage` with nothing else to name.
    #[must_use]
    pub fn at(stage: ConnectorReplyStage) -> Self {
        Self {
            stage,
            body_ref: None,
            outcome: None,
            gate_reason_codes: Vec::new(),
            actual_units: 0,
            witness_refs: Vec::new(),
            witness_repair: None,
            reason: None,
            waits_on_owner: false,
        }
    }

    /// Ends the job at `Fault` on `error`, keeping what it had already done.
    pub fn fault(&mut self, error: &Error) {
        self.stage = ConnectorReplyStage::Fault;
        self.reason = Some(error.to_string());
        self.waits_on_owner = crate::dreamer_wake::waits_on_owner_act(error.kind());
    }

    /// Whether the job runs again after a backoff rather than ending here.
    fn runs_again(&self) -> bool {
        match self.stage {
            ConnectorReplyStage::Held | ConnectorReplyStage::Failed => true,
            ConnectorReplyStage::Fault => !self.waits_on_owner,
            ConnectorReplyStage::NoReply
            | ConnectorReplyStage::Dispatched
            | ConnectorReplyStage::Ambiguous => false,
        }
    }
}

impl Vault {
    /// Queues `job`: generated work once per (agent, event), chosen words
    /// once per (agent, event, request) — a live job for the same key answers
    /// with its own id.
    ///
    /// # Errors
    /// The job does not encode, or the queue write fails.
    pub fn enqueue_connector_reply_job(
        &self,
        job: &ConnectorReplyJob,
        now: u64,
    ) -> Result<AttemptId> {
        let key = job.queue_key();
        let payload = serde_json::to_vec(job)
            .map_err(|_| Error::InvariantViolation("connector reply job did not encode"))?;
        let outcome = AttemptQueue::new(self).enqueue(EnqueueAttempt {
            kind: CONNECTOR_REPLY_JOB_KIND.to_owned(),
            payload,
            dedupe_key: Some(key.clone()),
            run_id: Some(key),
            now,
        })?;
        Ok(match outcome {
            EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record.id,
        })
    }

    /// Keeps one exact-words reply for `agent`'s `event` under the caller's
    /// `request_ref`, reads it back byte-exact, then queues the job naming the
    /// kept body. The body is persisted FIRST (positive resume, never atomic
    /// body+queue): a crash between save and queue retries the same body and
    /// enqueues again. The slot is `inbox:<blake3>` over length-prefixed
    /// `request_ref` + exact `text`, so a distinct `request_ref` permits
    /// identical-word followups while retries share one slot: the save returns
    /// the body already kept, the read-back must equal the input, and the job
    /// is ALWAYS enqueued (coalescing while pending, replaying once terminal).
    /// The payload names only slot, body pointer, time and input blake3 —
    /// never raw words. No wake is faked; no one-per-event hold or cap.
    /// Queueing is not delivery; read the job's result for what happened.
    ///
    /// # Errors
    /// The body does not save or read back, the read-back differs, the job
    /// does not encode, or the queue write fails.
    pub fn enqueue_connector_reply_text(
        &self,
        agent: EntityId,
        event: &ConnectorEvent,
        request_ref: &str,
        text: &str,
        now: u64,
    ) -> Result<AttemptId> {
        let reply_ref = chosen_reply_ref(request_ref, text);
        let kept = self.save_connector_reply_body(&event.event_id, agent, &reply_ref, text, now)?;
        let kept_text = self
            .connector_reply_body_text(&kept.content_ref)?
            .ok_or_else(|| Error::InvariantViolation("chosen reply body did not read back"))?;
        if kept_text != text {
            return Err(Error::InvariantViolation(
                "chosen reply body does not match its request",
            ));
        }
        let job = ConnectorReplyJob {
            agent,
            event: (*event).clone(),
            source: ConnectorReplyJobSource::Chosen {
                reply_ref,
                body_ref: kept.content_ref,
                written_at: kept.written_at,
                text_hash: blake3::hash(text.as_bytes()).to_hex().to_string(),
            },
        };
        self.enqueue_connector_reply_job(&job, now)
    }

    /// Returns to the queue every job left leased, by a stopped process or
    /// by a pass whose settle failed, so the next claim picks it up. The
    /// reply worker runs it at the start of every pass, when it holds no
    /// lease of its own.
    ///
    /// # Errors
    /// The queue write fails.
    pub fn reclaim_connector_reply_jobs(&self, now: u64) -> Result<()> {
        AttemptQueue::new(self).cleanup_kind_leases(
            CONNECTOR_REPLY_JOB_KIND,
            CleanupAttemptLeases {
                now,
                lease_timeout_secs: CONNECTOR_REPLY_LEASE_RECLAIM_SECS,
            },
        )?;
        Ok(())
    }

    /// Claims the next ready reply job. A row that does not decode is failed
    /// with its reason and the claim moves on.
    ///
    /// # Errors
    /// The queue read or write fails.
    pub fn claim_connector_reply_job(
        &self,
        now: u64,
    ) -> Result<Option<(AttemptRecord, ConnectorReplyJob)>> {
        let queue = AttemptQueue::new(self);
        loop {
            let claimed = match queue.claim_kind(
                CONNECTOR_REPLY_JOB_KIND,
                ClaimAttempt {
                    lease_owner: CONNECTOR_REPLY_JOB_LEASE_OWNER.to_owned(),
                    now,
                },
            )? {
                ClaimOutcome::Empty => return Ok(None),
                ClaimOutcome::Claimed(claimed) => claimed,
            };
            match serde_json::from_slice::<ConnectorReplyJob>(&claimed.payload) {
                Ok(job) => return Ok(Some((claimed, job))),
                Err(_) => {
                    queue.fail(FailAttempt {
                        id: claimed.id,
                        lease_owner: CONNECTOR_REPLY_JOB_LEASE_OWNER.to_owned(),
                        attempt_count: claimed.attempt_count,
                        reason: "connector reply job did not decode".to_owned(),
                        now,
                    })?;
                }
            }
        }
    }

    /// Settles the claimed job with `result`. A held or failed send, or a
    /// fault the job may get past on its own, returns the job to the queue
    /// as the same row, due after a backoff that doubles with each run: the
    /// rerun reuses the kept body and replays the logical send, which sends
    /// once the hold or the provider clears. Otherwise `result` is kept as
    /// the job's result and the job ends: completed when it answered or had
    /// nothing to answer, failed with its stage as the reason when the send
    /// is ambiguous or the fault waits on the owner. Each run's result is
    /// kept as a version of the same artifact, so a rerun after a restart
    /// appends its own and the head is the latest run's. Returns that ref,
    /// or `None` for a requeued job.
    ///
    /// # Errors
    /// The result does not encode, or a vault or queue write fails.
    pub fn settle_connector_reply_job(
        &self,
        claimed: &AttemptRecord,
        job: &ConnectorReplyJob,
        result: &ConnectorReplyJobResult,
        now: u64,
    ) -> Result<Option<String>> {
        let queue = AttemptQueue::new(self);
        let reason = || {
            let mut reason = result
                .reason
                .clone()
                .filter(|reason| !reason.is_empty())
                .unwrap_or_else(|| format!("connector reply {:?}", result.stage));
            reason.truncate(reason.floor_char_boundary(CONNECTOR_REPLY_QUEUE_REASON_BYTES));
            reason
        };
        if result.runs_again() {
            let shift = claimed.attempt_count.saturating_sub(1).min(6);
            let wait =
                (CONNECTOR_REPLY_RETRY_FIRST_SECS << shift).min(CONNECTOR_REPLY_RETRY_MAX_SECS);
            self.keep_connector_reply_result(claimed, job, result, now)?;
            queue.requeue(RequeueAttempt {
                id: claimed.id,
                lease_owner: CONNECTOR_REPLY_JOB_LEASE_OWNER.to_owned(),
                attempt_count: claimed.attempt_count,
                reason: reason(),
                due_at: now.saturating_add(wait),
            })?;
            return Ok(None);
        }
        let result_ref = self.keep_connector_reply_result(claimed, job, result, now)?;
        queue.set_result(SetAttemptResult {
            id: claimed.id,
            lease_owner: CONNECTOR_REPLY_JOB_LEASE_OWNER.to_owned(),
            attempt_count: claimed.attempt_count,
            result_ref: AttemptResultRef::new(result_ref.clone())?,
            now,
        })?;
        match result.stage {
            ConnectorReplyStage::NoReply | ConnectorReplyStage::Dispatched => {
                queue.complete(CompleteAttempt {
                    id: claimed.id,
                    lease_owner: CONNECTOR_REPLY_JOB_LEASE_OWNER.to_owned(),
                    attempt_count: claimed.attempt_count,
                    now,
                })?;
            }
            ConnectorReplyStage::Held
            | ConnectorReplyStage::Failed
            | ConnectorReplyStage::Ambiguous
            | ConnectorReplyStage::Fault => {
                queue.fail(FailAttempt {
                    id: claimed.id,
                    lease_owner: CONNECTOR_REPLY_JOB_LEASE_OWNER.to_owned(),
                    attempt_count: claimed.attempt_count,
                    reason: reason(),
                    now,
                })?;
            }
        }
        Ok(Some(result_ref))
    }

    /// Runs a `Failed` reply job again now, as its successor: the row is
    /// read and must be a failed connector reply job, the successor is
    /// minted in a write transaction, and its observers are notified, so the
    /// next pass claims it (FIX 10899). Returns the successor's id.
    ///
    /// # Errors
    /// No attempt has `attempt`, the row is no failed connector reply job,
    /// the successor cannot be minted, or a vault write fails.
    pub fn retry_failed_connector_reply_job(
        &self,
        attempt: AttemptId,
        now: u64,
    ) -> Result<AttemptId> {
        let queue = AttemptQueue::new(self);
        let record = queue.get(attempt)?.ok_or(Error::EntityNotFound)?;
        if record.kind != CONNECTOR_REPLY_JOB_KIND {
            return Err(Error::InvalidConfig(
                "the attempt is not a connector reply job".to_owned(),
            ));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let successor = queue.successor_of_failed_in_txn(&mut wtxn, attempt, now)?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        Ok(successor.id)
    }

    /// Keeps `result` as the job's result: the artifact is ensured, then the
    /// run's result is appended as a new version unless it is byte-equal to
    /// the head, so every run's result stays and the head is the latest
    /// run's (FIX 10900). Returns the ref the head names.
    ///
    /// # Errors
    /// The result does not encode, or a vault write fails.
    fn keep_connector_reply_result(
        &self,
        claimed: &AttemptRecord,
        job: &ConnectorReplyJob,
        result: &ConnectorReplyJobResult,
        now: u64,
    ) -> Result<String> {
        let artifact_id = connector_reply_result_id(claimed.id)?;
        if self.get_blob_artifact(&artifact_id)?.is_none() {
            let at = TimeRange {
                start: now,
                end: now,
            };
            self.put_blob_artifact(
                &artifact_id,
                &BlobArtifactBody::new(job.queue_key(), CONNECTOR_REPLY_RESULT_MEDIA_TYPE),
                at,
                now,
            )?;
        }
        let bytes = serde_json::to_vec(result)
            .map_err(|_| Error::InvariantViolation("connector reply result did not encode"))?;
        let head_bytes = self
            .blob_artifact_versions(&artifact_id)?
            .last()
            .map(|head| self.read_blob_artifact_version(&artifact_id, head.version))
            .transpose()?
            .flatten();
        if head_bytes.as_deref() != Some(bytes.as_slice()) {
            let run_ref = job.queue_key();
            let at = TimeRange {
                start: now,
                end: now,
            };
            self.append_blob_artifact_version(
                &artifact_id,
                &bytes,
                &BlobVersionProvenance::AgentRun { run_ref },
                WriteActor::new(job.agent, EdgeActorClass::Agent),
                at,
                now,
            )?;
        }
        Ok(format!(
            "{CONNECTOR_REPLY_RESULT_PREFIX}{}",
            artifact_id.to_hex()
        ))
    }

    /// Every result the job's runs kept, oldest first; the head is the
    /// latest run's. A version that does not decode is passed over, so one
    /// bad write never hides the rest (FIX 10900).
    ///
    /// # Errors
    /// The version chain does not read.
    pub fn connector_reply_job_results(
        &self,
        attempt: AttemptId,
    ) -> Result<Vec<ConnectorReplyJobResult>> {
        let artifact_id = connector_reply_result_id(attempt)?;
        let mut results = Vec::new();
        for version in self.blob_artifact_versions(&artifact_id)? {
            let Some(bytes) = self.read_blob_artifact_version(&artifact_id, version.version)?
            else {
                continue;
            };
            if let Ok(result) = serde_json::from_slice::<ConnectorReplyJobResult>(&bytes) {
                results.push(result);
            }
        }
        Ok(results)
    }
}

/// The artifact a job attempt's result is kept as.
fn connector_reply_result_id(attempt: AttemptId) -> Result<EntityId> {
    EntityId::derive(
        CONNECTOR_REPLY_RESULT_DOMAIN,
        &[attempt.as_bytes().as_slice()],
    )
}

/// Leaves a reply job row's payload without its event's payload when the
/// job names anyone among `erased`: its agent, or the event's actor,
/// receiving identity or known counterparty. A chosen job's body pointer goes
/// with it; slot ref and input hash stay as mechanical ids. The event's id,
/// connector, kind and predicate stay, so the row still decodes; a claim of it
/// answers nothing. Returns whether the row changed: a row that does not
/// decode, or one already erased, names nobody.
///
/// # Errors
/// The erased job does not encode.
pub(crate) fn erase_connector_reply_job_payload(
    record: &mut AttemptRecord,
    erased: &BTreeSet<EntityId>,
) -> Result<bool> {
    let Ok(mut job) = serde_json::from_slice::<ConnectorReplyJob>(&record.payload) else {
        return Ok(false);
    };
    if job.event.payload.is_null() {
        return Ok(false);
    }
    let names_erased = job.named_ids().iter().any(|id| erased.contains(id));
    if !names_erased {
        return Ok(false);
    }
    job.event.payload = serde_json::Value::Null;
    if let ConnectorReplyJobSource::Chosen { body_ref, .. } = &mut job.source {
        body_ref.clear();
    }
    record.payload = serde_json::to_vec(&job)
        .map_err(|_| Error::InvariantViolation("erased connector reply job did not encode"))?;
    Ok(true)
}

/// Erases the result each of `attempts`, reply job rows the payload pass
/// erased, kept: its artifact is removed whole in the erase's transaction,
/// as a staged job's artifact is, with its version chain, head and indexes.
/// An attempt that kept no result is left alone; a legal hold on the
/// artifact keeps it, logged, and the rest of the erase goes on.
///
/// # Errors
/// Storage errors.
pub(crate) fn erase_connector_reply_results_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    attempts: &[AttemptId],
) -> Result<()> {
    for attempt in attempts {
        let artifact = connector_reply_result_id(*attempt)?;
        erase_connector_reply_result_artifact_in_txn(store, txn, &artifact, true)?;
    }
    Ok(())
}

/// Erases one kept reply result, whole: its artifact with its version chain,
/// head and indexes, and the kept reply body its head version names, when
/// the head still decodes to a result naming one (FIX 10902) and
/// follow_body_ref holds (true only for an actual job result; the body's own
/// erase passes false, REVIEW-4385 P1). The body goes
/// through this same erasure, so its own hold keeps it, logged, like the
/// result's. A version the body read cannot parse names no body. A hold on
/// any version's ASSET keeps the whole artifact instead (FIX 12532), and a
/// torn body stages its hard-delete marker and propagation tombstone in the
/// same transaction (REVIEW-4385 P1), so replicas cannot restore it. Returns
/// whether the tear ran; a hold-kept body stages nothing (REVIEW-4385 P1).
fn erase_connector_reply_result_artifact_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    artifact: &EntityId,
    follow_body_ref: bool,
) -> Result<bool> {
    let raw = EntityStoreRead::port_entity_raw(store, txn, artifact)?;
    if raw
        .as_deref()
        .and_then(crate::batch::EntityMetadataHeader::parse)
        .map(|header| header.entity_type)
        != Some(crate::registry::ENTITY_TYPE_BLOB_ARTIFACT)
    {
        return Ok(false);
    }
    // A hold on any version's ASSET keeps the whole artifact (FIX 12532):
    // the tear below would otherwise refuse on the held ASSET and fail the
    // erase, rolling back the source hard erase with it (REVIEW-4385 P1).
    // Every hash the chain and the replicated claims hold is checked before
    // anything mutates.
    let raw = raw.unwrap_or_default();
    for content_hash in
        crate::blob_artifact::held_content_hashes_in_txn(store, txn, artifact, &raw)?
    {
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&content_hash)?;
        if crate::store::legal_hold::held_in_txn(store, txn, asset.as_bytes())? {
            tracing::warn!(
                artifact = %artifact.to_hex(),
                "connector reply erase: a legal hold keeps the job's result bytes"
            );
            return Ok(false);
        }
    }
    let mut body_artifact = None;
    // REVIEW-4385 P1: the body_ref is followed only on the actual job
    // result. The body's own bytes are erased whole, never parsed for a
    // further body_ref, so a crafted body cannot tombstone an unrelated
    // artifact transitively.
    if follow_body_ref
        && let Some(head) =
            crate::blob_artifact::read_blob_artifact_head_in_txn(store, txn, artifact)?
    {
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&head.content_hash)?;
        if let Some(row) = EntityStoreRead::port_entity_record(store, txn, &asset)? {
            if row.entity_type != crate::registry::ENTITY_TYPE_ASSET
                || blake3::hash(&row.body).as_bytes() != &head.content_hash
            {
                return Err(Error::CorruptedIndex("blob content hash"));
            }
            if let Ok(result) = serde_json::from_slice::<ConnectorReplyJobResult>(&row.body)
                && let Some(body_ref) = result.body_ref.as_deref()
                && let Some(rest) =
                    body_ref.strip_prefix(crate::outbound::CONNECTOR_REPLY_BODY_PREFIX)
                && let Some(hex) = rest.split('@').next()
                && let Ok(body) = EntityId::from_hex(hex)
                && body != *artifact
            {
                body_artifact = Some(body);
            }
        }
    }
    if let Err(error) = store.reject_legal_hold_in_txn(txn, artifact.as_bytes()) {
        if !crate::store::legal_hold::held_in_txn(store, txn, artifact.as_bytes())? {
            return Err(error);
        }
        tracing::warn!(
            artifact = %artifact.to_hex(),
            "connector reply erase: a legal hold keeps the job's result"
        );
        return Ok(false);
    }
    crate::provenance::erase_row_provenance_without_attempt_payloads_in_txn(
        store, txn, artifact, true,
    )?;
    let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, artifact)?;
    crate::ppr::invalidate_ppr_for_delete(store, txn, artifact, &neighbors)?;
    if graph {
        crate::store::graph_version::increment_graph_version(store, txn)?;
    }
    if vector {
        crate::store::vector_index::increment_vector_version(store, txn)?;
    }
    if let Some(body) = body_artifact {
        // The tear destroys the row its window rides: capture the body's
        // learned_at first, so its hard erasure publishes in its own window.
        // The body is the newly reached row (REVIEW-4385 P1): its permanent
        // marker refuses a peer's copy sent again, and its tombstone takes
        // the copies peers hold.
        let body_learned_at = EntityStoreRead::port_entity_raw(store, txn, &body)?
            .as_deref()
            .and_then(crate::batch::EntityMetadataHeader::parse)
            .map(|header| header.learned_at);
        // A hold keeps the body: its marker and tombstone stage only on
        // the outcome that actually tore it (REVIEW-4385 P1), never on the
        // hold that promised the bytes stay.
        let erased = erase_connector_reply_result_artifact_in_txn(store, txn, &body, false)?;
        if erased && let Some(learned_at) = body_learned_at {
            let value = crate::deletion::TombstoneValueV2 {
                reason: crate::deletion::TombstoneReason::UserHardDelete,
                deleted_at: crate::ports::recorded_at_in_txn(store, txn)?,
                request_id: *body.as_bytes(),
            };
            crate::deletion::stage_engine_row_hard_erasure_in_txn(
                store, txn, &body, learned_at, &value,
            )?;
        }
    }
    Ok(true)
}

/// The dedupe and run key of one agent's reply job for one event.
fn connector_reply_job_key(agent: EntityId, event_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONNECTOR_REPLY_JOB_KEY_DOMAIN);
    for value in [agent.as_bytes().as_slice(), event_id.as_bytes()] {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("connector-reply-job:{}", hasher.finalize().to_hex())
}

// No helper nesting: request slot derivation stays a top-level private fn
// beside the queue key it namespaces.
/// The request-namespaced reply slot for one exact-words request: `inbox:`
/// over the blake3 of the length-prefixed request identity + exact text.
fn chosen_reply_ref(request_ref: &str, text: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONNECTOR_REPLY_CHOSEN_REF_DOMAIN);
    for value in [request_ref.as_bytes(), text.as_bytes()] {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("inbox:{}", hasher.finalize().to_hex())
}
