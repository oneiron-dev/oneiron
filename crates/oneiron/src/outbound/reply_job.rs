//! The durable connector reply job (FIX 2405). A Dreamer pass that wakes an
//! agent on a message it should answer only hands the reply off: it queues
//! one job per (agent, event) and settles at once, spending nothing. The
//! host's reply worker claims the job off the pass, generates (or reuses the
//! kept body), dispatches through the ordinary recorded pipeline and keeps a
//! result naming what happened and what the model calls actually spent.
//!
//! The queue is the source of truth: a job survives a restart, and a rerun
//! after one reuses the kept body and replays the logical send, so it never
//! asks the model twice or sends twice.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, CompleteAttempt, EnqueueAttempt, EnqueueOutcome, FailAttempt,
    SetAttemptResult,
};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::connector_key::events::ConnectorEvent;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault, WriteActor};

/// The attempt kind a connector reply job is queued under.
pub const CONNECTOR_REPLY_JOB_KIND: &str = "connector.reply";
/// Every job result ref starts with this: `connector-reply-result:<artifact hex>`.
pub const CONNECTOR_REPLY_RESULT_PREFIX: &str = "connector-reply-result:";
/// Domain of a job's dedupe and run key: one job per (agent, event).
const CONNECTOR_REPLY_JOB_KEY_DOMAIN: &[u8] = b"oneiron.connector-reply-job.v1\0";
/// Domain of a job result's artifact id: one per job attempt.
const CONNECTOR_REPLY_RESULT_DOMAIN: &[u8] = b"oneiron:connector-reply-job-result:v1";
const CONNECTOR_REPLY_RESULT_MEDIA_TYPE: &str = "application/json";
/// The lease owner the host's reply worker claims jobs as.
const CONNECTOR_REPLY_JOB_LEASE_OWNER: &str = "connector-reply-worker";

/// One agent's reply to one connector event, handed off by the Dreamer
/// pass that woke the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorReplyJob {
    pub agent: EntityId,
    pub event: ConnectorEvent,
    /// The wake attempt that handed the reply off.
    pub parent_attempt: AttemptId,
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
    /// The Gate held the reply.
    Held,
    /// The send failed.
    Failed,
    /// The send may have landed; it waits for a look, never a resend.
    Ambiguous,
    /// The job could not run: the agent, the model or the vault failed.
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
        }
    }
}

impl Vault {
    /// Queues `job`, once per (agent, event): a live job for the same pair
    /// answers with its own id.
    ///
    /// # Errors
    /// The job does not encode, or the queue write fails.
    pub fn enqueue_connector_reply_job(
        &self,
        job: &ConnectorReplyJob,
        now: u64,
    ) -> Result<AttemptId> {
        let key = connector_reply_job_key(job.agent, &job.event.event_id);
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

    /// Returns to the queue every job a stopped process left leased, so a
    /// restart picks them up. The reply worker runs it once as it starts,
    /// before it claims anything.
    ///
    /// # Errors
    /// The queue write fails.
    pub fn reclaim_connector_reply_jobs(&self, now: u64) -> Result<()> {
        AttemptQueue::new(self).cleanup_kind_leases(
            CONNECTOR_REPLY_JOB_KIND,
            CleanupAttemptLeases {
                now,
                lease_timeout_secs: 0,
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

    /// Keeps `result` as the claimed job's result and settles it: a job that
    /// answered or had nothing to answer completes; a held, failed,
    /// ambiguous or faulted one fails with its stage as the reason, so it
    /// waits for a look and its requeue reuses the kept body. The first
    /// result a job keeps stands; a rerun after a restart names the same
    /// ref. Returns that ref.
    ///
    /// # Errors
    /// The result does not encode, or a vault or queue write fails.
    pub fn settle_connector_reply_job(
        &self,
        claimed: &AttemptRecord,
        job: &ConnectorReplyJob,
        result: &ConnectorReplyJobResult,
        now: u64,
    ) -> Result<String> {
        let artifact_id = EntityId::derive(
            CONNECTOR_REPLY_RESULT_DOMAIN,
            &[claimed.id.as_bytes().as_slice()],
        )?;
        let result_ref = format!("{CONNECTOR_REPLY_RESULT_PREFIX}{}", artifact_id.to_hex());
        if self.get_blob_artifact(&artifact_id)?.is_none() {
            let bytes = serde_json::to_vec(result)
                .map_err(|_| Error::InvariantViolation("connector reply result did not encode"))?;
            let run_ref = connector_reply_job_key(job.agent, &job.event.event_id);
            let at = TimeRange {
                start: now,
                end: now,
            };
            self.put_blob_artifact(
                &artifact_id,
                &BlobArtifactBody::new(run_ref.clone(), CONNECTOR_REPLY_RESULT_MEDIA_TYPE),
                at,
                now,
            )?;
            self.append_blob_artifact_version(
                &artifact_id,
                &bytes,
                &BlobVersionProvenance::AgentRun { run_ref },
                WriteActor::new(job.agent, EdgeActorClass::Agent),
                at,
                now,
            )?;
        }
        let queue = AttemptQueue::new(self);
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
                    reason: result
                        .reason
                        .clone()
                        .unwrap_or_else(|| format!("connector reply {:?}", result.stage)),
                    now,
                })?;
            }
        }
        Ok(result_ref)
    }
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
