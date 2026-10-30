//! A transcript upload that met its caller's open local session (FIX 9654).
//!
//! The verified upload is retained as one queued attempt, keyed by the upload,
//! and lands once the session has closed: the host drains due rows in queue
//! order ([`run_pending_transcript_ingests`]), each ingested once as its own
//! caller through the same verified landing. A row still meeting an open
//! session waits one retry step; past its deadline it fails with the reason.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
    FailAttempt, RequeueAttempt,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};

use super::{TranscriptFileDropInput, TranscriptIngestOutcome};

/// Attempt kind of one retained upload waiting on its caller's open session.
pub const TRANSCRIPT_PENDING_ATTEMPT_KIND: &str = "calendar.transcript.pending";

/// How long a retained upload waits for its caller's open session to close.
pub const TRANSCRIPT_OPEN_SESSION_WAIT_SECS: u64 = 24 * 60 * 60;

/// How long a retained upload waits between tries.
const TRANSCRIPT_RETRY_SECS: u64 = 60;

/// One retained upload: the caller it lands as, the uploaded version it
/// names (its bytes stay in the blob, read again when it lands), and the
/// instant past which it stops waiting.
#[derive(Serialize, Deserialize)]
struct PendingTranscript {
    actor: String,
    actor_class: u8,
    source_blob_ref: String,
    version: u64,
    arrived_at_ms: u64,
    event_ref: Option<String>,
    deadline: u64,
}

/// What one drain pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingTranscriptPass {
    /// Uploads that landed as a closed session or a note.
    pub landed: usize,
    /// Uploads whose caller's session is still open, waiting one more step.
    pub waiting: usize,
    /// Uploads that failed for good: past the deadline, or no longer valid.
    pub failed: usize,
}

impl Memory<'_> {
    /// Retains the verified `input` for the bound caller as one queued
    /// attempt; a second upload of the same bytes at the same arrival joins
    /// the row already pending.
    pub(super) fn queue_pending_transcript(
        &self,
        input: &TranscriptFileDropInput,
        now: u64,
    ) -> MemoryResult<()> {
        let source = EntityId::from_hex(&input.source_blob_ref)
            .map_err(|_| MemoryError::bad_request("source_blob_ref is not an entity id"))?;
        let head = self.vault().blob_artifact_head(&source)?.ok_or_else(|| {
            MemoryError::bad_request("transcript source has no uploaded blob version")
        })?;
        let payload = serde_json::to_vec(&PendingTranscript {
            actor: self.actor().to_hex(),
            actor_class: self.actor_class() as u8,
            source_blob_ref: input.source_blob_ref.clone(),
            version: head.version,
            arrived_at_ms: input.arrived_at_ms,
            event_ref: input.event_ref.clone(),
            deadline: now.saturating_add(TRANSCRIPT_OPEN_SESSION_WAIT_SECS),
        })
        .map_err(|_| MemoryError::bad_request("transcript upload did not encode"))?;
        AttemptQueue::new(self.vault()).enqueue(EnqueueAttempt {
            kind: TRANSCRIPT_PENDING_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key: Some(format!(
                "{TRANSCRIPT_PENDING_ATTEMPT_KIND}:{}:{}",
                input.source_blob_ref, input.arrived_at_ms
            )),
            run_id: None,
            now,
        })?;
        Ok(())
    }
}

/// Claims up to `limit` due retained uploads, oldest first, and lands each
/// once as its caller. A caller whose session is still open, or a landing
/// that failed for a passing reason, waits one retry step until the
/// deadline; an upload that no longer verifies fails.
///
/// # Errors
///
/// Queue failures; a failed landing settles its own row.
pub fn run_pending_transcript_ingests(
    vault: &Vault,
    lease_owner: &str,
    limit: usize,
) -> crate::Result<PendingTranscriptPass> {
    let queue = AttemptQueue::new(vault);
    let mut pass = PendingTranscriptPass::default();
    for _ in 0..limit {
        let now = vault.now_recorded_at();
        let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
            TRANSCRIPT_PENDING_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now,
            },
        )?
        else {
            break;
        };
        let Ok(pending) = serde_json::from_slice::<PendingTranscript>(&attempt.payload) else {
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
        match land(vault, &pending) {
            Ok(TranscriptIngestOutcome::RetryOpenSession { .. }) if now < pending.deadline => {
                queue.requeue(RequeueAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    reason: "the caller's local session is still open".to_owned(),
                    due_at: now.saturating_add(TRANSCRIPT_RETRY_SECS),
                })?;
                pass.waiting += 1;
            }
            Ok(TranscriptIngestOutcome::RetryOpenSession { .. }) => {
                fail(
                    &queue,
                    &attempt,
                    lease_owner,
                    now,
                    "the caller's local session stayed open past the deadline",
                )?;
                pass.failed += 1;
            }
            Ok(_) => {
                queue.complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    now,
                })?;
                pass.landed += 1;
            }
            // An upload that no longer verifies, or a caller who can no
            // longer read it, fails for good; any other failure tries again
            // until the deadline.
            Err(error)
                if now < pending.deadline
                    && error.code != MEMORY_CODE_BAD_REQUEST
                    && error.code != MEMORY_CODE_NOT_FOUND =>
            {
                queue.requeue(RequeueAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    reason: error.to_string(),
                    due_at: now.saturating_add(TRANSCRIPT_RETRY_SECS),
                })?;
                pass.waiting += 1;
            }
            Err(error) => {
                fail(&queue, &attempt, lease_owner, now, &error.to_string())?;
                pass.failed += 1;
            }
        }
    }
    Ok(pass)
}

/// One landing of `pending` as its own caller, from the uploaded version it
/// names; the landing itself checks that version is still the head.
fn land(vault: &Vault, pending: &PendingTranscript) -> MemoryResult<TranscriptIngestOutcome> {
    let actor = EntityId::from_hex(&pending.actor)
        .map_err(|_| MemoryError::bad_request("transcript caller is not an entity id"))?;
    let class = EdgeActorClass::try_from_u8(pending.actor_class)
        .ok_or_else(|| MemoryError::bad_request("transcript caller class is unknown"))?;
    let memory = vault.memory(actor, class);
    let bytes = memory
        .read_blob_version(&pending.source_blob_ref, pending.version)?
        .ok_or_else(|| MemoryError::bad_request("transcript source bytes are unavailable"))?;
    let decoded_text = String::from_utf8(bytes)
        .map_err(|_| MemoryError::bad_request("transcript source is not UTF-8"))?;
    memory.calendar_transcript_ingest_once(&TranscriptFileDropInput {
        source_blob_ref: pending.source_blob_ref.clone(),
        decoded_text,
        arrived_at_ms: pending.arrived_at_ms,
        event_ref: pending.event_ref.clone(),
    })
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
