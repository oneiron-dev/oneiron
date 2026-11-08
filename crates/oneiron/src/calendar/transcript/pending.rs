//! Retained transcript ingestion through the caller's original hook boundary.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
    EnqueueOutcome, FailAttempt, RequeueAttempt,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
    TranscriptRetainedCaller,
};
use crate::runtime_hooks::verb::VerbHookWaitStatus;
use crate::session_lifecycle::SessionImportHint;

use super::{TranscriptFileDropInput, TranscriptIngestOutcome};

pub const TRANSCRIPT_PENDING_ATTEMPT_KIND: &str = "calendar.transcript.pending";
/// The existing busy-session wait; hook waits follow their actual ask instead.
pub const TRANSCRIPT_OPEN_SESSION_WAIT_SECS: u64 = 24 * 60 * 60;
const TRANSCRIPT_RETRY_SECS: u64 = 60;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct TranscriptRetry {
    pub version: u64,
    pub session: Option<SessionImportHint>,
    pub ask: Option<EntityId>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PendingTranscript {
    actor: String,
    actor_class: u8,
    caller: TranscriptRetainedCaller,
    source_blob_ref: String,
    arrived_at_ms: u64,
    event_ref: Option<String>,
    retry: TranscriptRetry,
    deadline: Option<u64>,
}

impl PendingTranscript {
    fn encode(&self) -> crate::Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|_| crate::Error::InvariantViolation("transcript upload did not encode"))
    }
}

/// What one drain pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingTranscriptPass {
    pub landed: usize,
    pub waiting: usize,
    pub failed: usize,
}

impl Memory<'_> {
    pub(super) fn ingest_transcript_with_retention(
        &self,
        input: &TranscriptFileDropInput,
    ) -> MemoryResult<TranscriptIngestOutcome> {
        let vault = self.vault();
        let queue = AttemptQueue::new(vault);
        let now = vault.now_recorded_at();
        let lease_owner = format!("calendar.transcript.ingest:{}", self.actor().to_hex());
        let mut active: Option<(AttemptRecord, PendingTranscript)> = None;
        let mut retry = None;
        let result = self.calendar_transcript_ingest_once(input, &mut retry, &mut |prepared| {
            let pending = self.pending_transcript(input, prepared.clone(), now)?;
            let caller = pending.caller.clone();
            let payload = pending.encode()?;
            let dedupe_key = self.transcript_dedupe_key(input);
            let (record, claimed, saved) = vault.try_with_write_txn_grouped(|txn| {
                let record = match queue.enqueue_with_task_ref_and_dedupe_actor_in_txn(
                    txn,
                    EnqueueAttempt {
                        kind: TRANSCRIPT_PENDING_ATTEMPT_KIND.to_owned(),
                        payload,
                        dedupe_key: Some(dedupe_key),
                        run_id: None,
                        now,
                    },
                    None,
                    Some(&self.actor().to_hex()),
                )? {
                    EnqueueOutcome::Enqueued(row) | EnqueueOutcome::Existing(row) => row,
                };
                let mut saved: PendingTranscript = serde_json::from_slice(&record.payload)
                    .map_err(|_| MemoryError::bad_request("transcript upload did not decode"))?;
                if saved.actor != self.actor().to_hex()
                    || saved.actor_class != self.actor_class() as u8
                    || saved.retry.version != prepared.version
                {
                    return Err(MemoryError::bad_request(
                        "transcript retained caller or version changed",
                    ));
                }
                // A different worker keeps its lease; a scheduled row keeps its
                // existing due instant. This call never starts another hook chain.
                if !record.state.is_ready_indexed() {
                    return Ok((record, None, saved));
                }
                let claimed = queue.claim_id_in_txn(
                    txn,
                    record.id,
                    ClaimAttempt {
                        lease_owner: lease_owner.clone(),
                        now,
                    },
                )?;
                let ClaimOutcome::Claimed(claimed) = claimed else {
                    return Ok((record, None, saved));
                };
                saved.caller = caller;
                if saved.retry.session.is_none() {
                    saved.retry.session = prepared.session.clone();
                }
                let claimed = queue.replace_leased_payload_in_txn(
                    txn,
                    &claimed,
                    &lease_owner,
                    claimed.attempt_count,
                    saved.encode()?,
                )?;
                Ok::<_, MemoryError>((record, Some(claimed), saved))
            })?;
            let Some(claimed) = claimed else {
                return Ok(Some(TranscriptIngestOutcome::Queued {
                    attempt_ref: uuid::Uuid::from_bytes(*record.id.as_bytes())
                        .simple()
                        .to_string(),
                }));
            };
            *prepared = saved.retry.clone();
            active = Some((claimed, saved));
            Ok(None)
        });
        if let Some((attempt, mut pending)) = active {
            pending.caller = self.retain_transcript_caller()?;
            pending.retry = retry.ok_or(crate::Error::InvariantViolation(
                "transcript retry was not prepared",
            ))?;
            finish(
                vault,
                &queue,
                &attempt,
                &mut pending,
                &lease_owner,
                now,
                &result,
            )?;
        } else if matches!(
            &result,
            Ok(TranscriptIngestOutcome::RetryOpenSession { .. })
        ) {
            let retry = retry.ok_or(crate::Error::InvariantViolation(
                "transcript retry was not prepared",
            ))?;
            let pending = self.pending_transcript(input, retry, now)?;
            let payload = pending.encode()?;
            let dedupe_key = self.transcript_dedupe_key(input);
            vault.try_with_write_txn_grouped(|txn| {
                queue.enqueue_with_task_ref_and_dedupe_actor_in_txn(
                    txn,
                    EnqueueAttempt {
                        kind: TRANSCRIPT_PENDING_ATTEMPT_KIND.to_owned(),
                        payload,
                        dedupe_key: Some(dedupe_key),
                        run_id: None,
                        now,
                    },
                    None,
                    Some(&self.actor().to_hex()),
                )?;
                Ok::<_, MemoryError>(())
            })?;
        }
        result
    }

    fn transcript_dedupe_key(&self, input: &TranscriptFileDropInput) -> String {
        format!(
            "{TRANSCRIPT_PENDING_ATTEMPT_KIND}:{}:{}:{}:{}",
            input.source_blob_ref,
            input.arrived_at_ms,
            self.actor_class() as u8,
            input.event_ref.as_deref().unwrap_or("")
        )
    }

    fn pending_transcript(
        &self,
        input: &TranscriptFileDropInput,
        retry: TranscriptRetry,
        now: u64,
    ) -> MemoryResult<PendingTranscript> {
        Ok(PendingTranscript {
            actor: self.actor().to_hex(),
            actor_class: self.actor_class() as u8,
            caller: self.retain_transcript_caller()?,
            source_blob_ref: input.source_blob_ref.clone(),
            arrived_at_ms: input.arrived_at_ms,
            event_ref: input.event_ref.clone(),
            retry,
            deadline: Some(now.saturating_add(TRANSCRIPT_OPEN_SESSION_WAIT_SECS)),
        })
    }
}

/// Drains due retained uploads through their own caller and saved identity.
pub fn run_pending_transcript_ingests(
    vault: &Vault,
    lease_owner: &str,
    limit: usize,
) -> crate::Result<PendingTranscriptPass> {
    let queue = AttemptQueue::new(vault);
    let mut pass = PendingTranscriptPass::default();
    for _ in 0..limit {
        let now = vault.now_recorded_at();
        let ClaimOutcome::Claimed(mut attempt) = queue.claim_kind(
            TRANSCRIPT_PENDING_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now,
            },
        )?
        else {
            break;
        };
        let Ok(mut pending) = serde_json::from_slice::<PendingTranscript>(&attempt.payload) else {
            fail(
                &queue,
                &attempt,
                lease_owner,
                now,
                "transcript upload did not decode",
            )?;
            pass.failed += 1;
            continue;
        };
        let result = land(vault, &queue, &mut attempt, &mut pending, lease_owner);
        match finish(
            vault,
            &queue,
            &attempt,
            &mut pending,
            lease_owner,
            now,
            &result,
        )? {
            Settlement::Landed => pass.landed += 1,
            Settlement::Waiting => pass.waiting += 1,
            Settlement::Failed => pass.failed += 1,
        }
    }
    Ok(pass)
}

fn land(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    attempt: &mut AttemptRecord,
    pending: &mut PendingTranscript,
    lease_owner: &str,
) -> MemoryResult<TranscriptIngestOutcome> {
    let actor = EntityId::from_hex(&pending.actor)
        .map_err(|_| MemoryError::bad_request("transcript caller is not an entity id"))?;
    let class = EdgeActorClass::try_from_u8(pending.actor_class)
        .ok_or_else(|| MemoryError::bad_request("transcript caller class is unknown"))?;
    let memory = pending.caller.memory(vault, actor, class)?;
    let result = (|| {
        if let (Some(hint), Some(ask)) = (&pending.retry.session, pending.retry.ask) {
            match vault.session_import_hook_wait(hint, ask, &memory)? {
                VerbHookWaitStatus::Waiting => {
                    return Ok(TranscriptIngestOutcome::HookPending {
                        session_ref: hint.id(),
                        ask,
                    });
                }
                VerbHookWaitStatus::Unavailable => {
                    return Err(MemoryError::bad_request(
                        "transcript saved hook invocation is unavailable",
                    ));
                }
                VerbHookWaitStatus::Ready => {}
            }
        }
        let bytes = memory
            .read_blob_version(&pending.source_blob_ref, pending.retry.version)?
            .ok_or_else(|| MemoryError::bad_request("transcript source bytes are unavailable"))?;
        let input = TranscriptFileDropInput {
            source_blob_ref: pending.source_blob_ref.clone(),
            decoded_text: String::from_utf8(bytes)
                .map_err(|_| MemoryError::bad_request("transcript source is not UTF-8"))?,
            arrived_at_ms: pending.arrived_at_ms,
            event_ref: pending.event_ref.clone(),
        };
        let mut retry = Some(pending.retry.clone());
        let mut saved = pending.clone();
        let result = memory.calendar_transcript_ingest_once(&input, &mut retry, &mut |prepared| {
            saved.retry = prepared.clone();
            let payload = saved.encode()?;
            *attempt = vault.try_with_write_txn_grouped(|txn| {
                queue.replace_leased_payload_in_txn(
                    txn,
                    attempt,
                    lease_owner,
                    attempt.attempt_count,
                    payload,
                )
            })?;
            Ok(None)
        });
        if let Some(retry) = retry {
            pending.retry = retry;
        }
        result
    })();
    pending.caller = memory.retain_transcript_caller()?;
    result
}

enum Settlement {
    Landed,
    Waiting,
    Failed,
}

fn finish(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    attempt: &AttemptRecord,
    pending: &mut PendingTranscript,
    lease_owner: &str,
    now: u64,
    result: &MemoryResult<TranscriptIngestOutcome>,
) -> crate::Result<Settlement> {
    let reason = match result {
        Ok(
            TranscriptIngestOutcome::Session { .. } | TranscriptIngestOutcome::NoteFallback { .. },
        ) => {
            queue.complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: attempt.attempt_count,
                now,
            })?;
            return Ok(Settlement::Landed);
        }
        Ok(TranscriptIngestOutcome::HookPending { .. }) => {
            "the transcript's session hook awaits its native ask".to_owned()
        }
        Ok(TranscriptIngestOutcome::RetryOpenSession { .. }) => {
            "the caller's local session is still open".to_owned()
        }
        Ok(TranscriptIngestOutcome::Queued { .. }) => {
            return Err(
                crate::Error::InvariantViolation("a leased transcript was queued twice").into(),
            );
        }
        Err(error)
            if error.code != MEMORY_CODE_BAD_REQUEST
                && error.code != MEMORY_CODE_NOT_FOUND
                && error.hook.is_none() =>
        {
            error.to_string()
        }
        Err(error) => {
            fail(queue, attempt, lease_owner, now, &error.to_string())?;
            return Ok(Settlement::Failed);
        }
    };
    if !matches!(result, Ok(TranscriptIngestOutcome::HookPending { .. }))
        && pending.deadline.is_some_and(|deadline| now >= deadline)
    {
        fail(
            queue,
            attempt,
            lease_owner,
            now,
            "the caller's local session stayed open past the deadline",
        )?;
        return Ok(Settlement::Failed);
    }
    let payload = pending.encode()?;
    vault.try_with_write_txn_grouped(|txn| {
        queue.replace_leased_payload_in_txn(
            txn,
            attempt,
            lease_owner,
            attempt.attempt_count,
            payload,
        )?;
        queue.requeue_in_txn(
            txn,
            RequeueAttempt {
                id: attempt.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: attempt.attempt_count,
                reason,
                due_at: now.saturating_add(TRANSCRIPT_RETRY_SECS),
            },
        )?;
        Ok::<_, crate::Error>(())
    })?;
    vault.store.notify_attempt_observers();
    Ok(Settlement::Waiting)
}

fn fail(
    queue: &AttemptQueue<'_>,
    attempt: &AttemptRecord,
    lease_owner: &str,
    now: u64,
    reason: &str,
) -> crate::Result<()> {
    queue.fail(FailAttempt {
        id: attempt.id,
        lease_owner: lease_owner.to_owned(),
        attempt_count: attempt.attempt_count,
        reason: reason.to_owned(),
        now,
    })?;
    Ok(())
}
