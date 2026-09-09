//! Durable admission txn, attempt payload codec, dispatch handoff, and status reads.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, CompleteOutcome, EnqueueAttempt, EnqueueOutcome, FailAttempt, FailOutcome,
    RetryAttempt, RetryOutcome,
};
use crate::error::{Error, Result};

use super::inbound::route_inbound_surface_event;
use super::validate_non_blank;
use super::{
    InboundSurfaceEventInput, InboundSurfaceRouteReceipt, SurfaceEvent, SurfaceEventDispatchRoute,
};

/// Attempt-queue kind owning inbound surface-event dispatch.
pub const SURFACE_EVENT_ATTEMPT_KIND: &str = "surface_event.dispatch.v1";

/// Route prefix the ack's status path is built on.
const SURFACE_EVENT_STATUS_PATH_PREFIX: &str = "/v1/core/surface-events/";

/// Durable payload a queued surface-event attempt carries to its worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceEventAttemptPayload {
    pub event: SurfaceEvent,
    pub route: SurfaceEventDispatchRoute,
    /// Downstream idempotency key. Exactly the public correlation id.
    pub dispatch_idempotency_key: String,
}

/// Public reference to the durable attempt backing one admitted event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SurfaceEventAttemptRef(String);

impl SurfaceEventAttemptRef {
    pub(super) fn from_attempt_id(id: AttemptId) -> Self {
        let bytes = id.as_bytes();
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
            hex.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
        }
        Self(hex)
    }

    /// Lowercase 32-hex attempt id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Durable lifecycle of an admitted surface event, in public spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceEventHandoffState {
    Queued,
    Leased,
    Paused,
    Completed,
    Failed,
    Cancelled,
    /// The executor stopped carrying the handoff without delivering and
    /// without anyone stopping it. Its own token rather than a fold onto
    /// `Failed` (nothing reported a fault) or `Cancelled` (nobody asked): a
    /// caller polling this surface is owed the true reason its event never
    /// landed.
    Abandoned,
}

impl SurfaceEventHandoffState {
    pub(super) const fn from_attempt_state(state: AttemptState) -> Self {
        match state {
            AttemptState::Queued => Self::Queued,
            // A landing attempt still holds its lease and its runtime, so the
            // handoff surface reads it as leased: live work, not a handoff that
            // completed or was cancelled.
            AttemptState::Leased | AttemptState::Landing => Self::Leased,
            // A deferred retry is not runnable-now, same as a pause.
            AttemptState::Scheduled | AttemptState::Paused => Self::Paused,
            AttemptState::Completed => Self::Completed,
            AttemptState::Failed => Self::Failed,
            AttemptState::Cancelled => Self::Cancelled,
            AttemptState::Abandoned => Self::Abandoned,
        }
    }

    /// Stable wire spelling, matching the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Abandoned => "abandoned",
        }
    }
}

/// Ack returned the moment an inbound event is durably committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceEventAck {
    pub correlation_id: String,
    pub attempt_ref: SurfaceEventAttemptRef,
    pub state: SurfaceEventHandoffState,
    /// `true` when this correlation id already had an attempt row.
    pub replayed: bool,
    /// When the attempt backing this correlation id was admitted. A replay
    /// carries the original admission, matching the status snapshot's
    /// `created_at`, never the replay's own clock.
    pub accepted_at: u64,
    pub status_path: String,
}

/// Durable snapshot of an admitted event's handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceEventHandoffStatus {
    pub correlation_id: String,
    pub attempt_ref: SurfaceEventAttemptRef,
    pub state: SurfaceEventHandoffState,
    pub attempt_count: u32,
    pub last_error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Admission outcome: a durable ack, or the typed route rejection that
/// stopped the event before it reached the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SurfaceEventAdmission {
    Accepted(SurfaceEventAck),
    Rejected(InboundSurfaceRouteReceipt),
}

/// Downstream handler a worker invokes for a leased surface event.
pub trait SurfaceEventDispatcher {
    fn dispatch(&self, request: SurfaceEventDispatchRequest<'_>)
    -> SurfaceEventDispatchDisposition;
}

/// Everything a dispatcher needs, already stamped at admission time.
#[derive(Debug)]
pub struct SurfaceEventDispatchRequest<'a> {
    pub event: &'a SurfaceEvent,
    pub route: SurfaceEventDispatchRoute,
    pub agent_ref: &'a str,
    pub correlation_id: &'a str,
    pub idempotency_key: &'a str,
}

/// What a dispatcher decided about one leased attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceEventDispatchDisposition {
    Complete,
    Retry { backoff_until: u64, reason: String },
    Fail { reason: String },
}

/// Result of one worker turn over the surface-event queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceEventWorkerOutcome {
    Empty,
    Completed(SurfaceEventHandoffStatus),
    Retried(SurfaceEventHandoffStatus),
    Failed(SurfaceEventHandoffStatus),
}

impl Vault {
    /// Resolves an inbound adapter payload into an identity-stamped
    /// SurfaceEvent or a typed route rejection receipt.
    pub fn route_inbound_surface_event(
        &self,
        input: InboundSurfaceEventInput,
    ) -> Result<InboundSurfaceRouteReceipt> {
        route_inbound_surface_event(self, input)
    }

    /// Routes an inbound event and, when it routes, commits it to the durable
    /// attempt queue before acking. No dispatcher runs inline: the ack means
    /// "durably ours", and a worker claims the row later.
    pub fn enqueue_inbound_surface_event(
        &self,
        input: InboundSurfaceEventInput,
        now: u64,
    ) -> Result<SurfaceEventAdmission> {
        let receipt = route_inbound_surface_event(self, input)?;
        let Some(event) = receipt.surface_event.clone() else {
            return Ok(SurfaceEventAdmission::Rejected(receipt));
        };
        let record = admit_surface_event_once(self, &event, now)?;
        Ok(SurfaceEventAdmission::Accepted(SurfaceEventAck {
            status_path: surface_event_status_path(&event.correlation_id),
            correlation_id: event.correlation_id,
            attempt_ref: SurfaceEventAttemptRef::from_attempt_id(record.attempt.id),
            state: SurfaceEventHandoffState::from_attempt_state(record.attempt.state),
            replayed: record.replayed,
            // The row's own stamp, not this call's clock: a replay admitted
            // nothing, and dating the ack `now` would contradict the
            // `created_at` the status snapshot reads off the same attempt.
            accepted_at: record.attempt.created_at,
        }))
    }

    /// Reads the durable handoff snapshot for one public correlation id.
    pub fn surface_event_handoff_status(
        &self,
        correlation_id: &str,
    ) -> Result<Option<SurfaceEventHandoffStatus>> {
        validate_non_blank(
            correlation_id,
            "surface event correlation id must be non-empty",
        )?;
        let run_id = surface_event_run_id(correlation_id);
        let queue = AttemptQueue::new(self);
        let Some(attempt) = sole_surface_event_attempt(queue.list_run(&run_id)?, correlation_id)?
        else {
            return Ok(None);
        };
        Ok(Some(handoff_status(correlation_id, &attempt)))
    }

    /// Claims and dispatches the next queued surface event.
    ///
    /// The worker leg is exercised by tests until the surface-serving ticket
    /// owns production wiring; the transitions it drives are the queue's own.
    pub fn dispatch_next_surface_event(
        &self,
        lease_owner: &str,
        now: u64,
        dispatcher: &dyn SurfaceEventDispatcher,
    ) -> Result<SurfaceEventWorkerOutcome> {
        let queue = AttemptQueue::new(self);
        let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
            SURFACE_EVENT_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now,
            },
        )?
        else {
            return Ok(SurfaceEventWorkerOutcome::Empty);
        };

        let payload = decode_surface_event_attempt_payload(&attempt.payload)?;
        let disposition = dispatcher.dispatch(SurfaceEventDispatchRequest {
            event: &payload.event,
            route: payload.route,
            agent_ref: &payload.event.actor_ref,
            correlation_id: &payload.event.correlation_id,
            idempotency_key: &payload.dispatch_idempotency_key,
        });

        let correlation_id = payload.event.correlation_id.as_str();
        match disposition {
            SurfaceEventDispatchDisposition::Complete => {
                let outcome = queue.complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    now,
                })?;
                let (CompleteOutcome::Completed(record)
                | CompleteOutcome::AlreadyCompleted(record)) = outcome;
                Ok(SurfaceEventWorkerOutcome::Completed(handoff_status(
                    correlation_id,
                    &record,
                )))
            }
            SurfaceEventDispatchDisposition::Retry {
                backoff_until,
                reason,
            } => {
                let RetryOutcome::Retried(record) = queue.retry(RetryAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    backoff_until,
                    last_error: Some(reason),
                    now,
                })?;
                Ok(SurfaceEventWorkerOutcome::Retried(handoff_status(
                    correlation_id,
                    &record,
                )))
            }
            SurfaceEventDispatchDisposition::Fail { reason } => {
                let outcome = queue.fail(FailAttempt {
                    id: attempt.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: attempt.attempt_count,
                    reason,
                    now,
                })?;
                let (FailOutcome::Failed(record) | FailOutcome::AlreadyFailed(record)) = outcome;
                Ok(SurfaceEventWorkerOutcome::Failed(handoff_status(
                    correlation_id,
                    &record,
                )))
            }
        }
    }
}

/// The one durable row an admitted correlation id resolves to.
struct AdmittedSurfaceEvent {
    attempt: AttemptRecord,
    replayed: bool,
}

/// Commits at most one attempt per public correlation id.
///
/// The run-index lookup and the enqueue share one write transaction, so two
/// concurrent submissions of the same correlation id cannot both insert: LMDB
/// serializes the writers and the loser observes the winner's row.
fn admit_surface_event_once(
    vault: &Vault,
    event: &SurfaceEvent,
    now: u64,
) -> Result<AdmittedSurfaceEvent> {
    let run_id = surface_event_run_id(&event.correlation_id);
    let payload = encode_surface_event_attempt_payload(&SurfaceEventAttemptPayload {
        event: event.clone(),
        route: event.dispatch_route(),
        dispatch_idempotency_key: event.correlation_id.clone(),
    })?;

    let queue = AttemptQueue::new(vault);
    let mut wtxn = vault.store.env.write_txn()?;
    if let Some(existing) = sole_surface_event_attempt(
        attempts_for_run_in_write_txn(vault, &queue, &wtxn, &run_id)?,
        &event.correlation_id,
    )? {
        // A row already owns this correlation id — including after it reached a
        // terminal state. Replay derives that attempt instead of dispatching a
        // second one; the write txn is dropped without a commit.
        return Ok(AdmittedSurfaceEvent {
            attempt: existing,
            replayed: true,
        });
    }

    let outcome = queue.enqueue_in_txn(
        &mut wtxn,
        EnqueueAttempt {
            kind: SURFACE_EVENT_ATTEMPT_KIND.to_owned(),
            payload,
            // One derivation keys both queue indexes. A raw provider id is
            // unbounded, the queue's dedupe cap is 512 bytes, and a length
            // rejection here would contradict the ruling that admission never
            // refuses an event merely for a long provider id. The bounded run
            // id is deterministic and equals the correlation id for every id
            // the raw key could have carried, so replay still lands on this
            // row; the public id stays verbatim on the envelope, the ack, and
            // the status snapshot.
            dedupe_key: Some(run_id.clone()),
            run_id: Some(run_id),
            now,
        },
    )?;
    wtxn.commit()?;
    Ok(match outcome {
        EnqueueOutcome::Enqueued(attempt) => AdmittedSurfaceEvent {
            attempt,
            replayed: false,
        },
        EnqueueOutcome::Existing(attempt) => AdmittedSurfaceEvent {
            attempt,
            replayed: true,
        },
    })
}

/// Reads a run's attempt rows inside the caller's write transaction.
///
/// The read must share the admission transaction: a read-transaction lookup
/// followed by a separate write would let a concurrent submitter slip a second
/// row in between.
fn attempts_for_run_in_write_txn(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    wtxn: &heed::RwTxn<'_>,
    run_id: &str,
) -> Result<Vec<AttemptRecord>> {
    let mut records = Vec::new();
    for id_bytes in vault.store.attempt_ids_for_run_in_txn(wtxn, run_id)? {
        let id = AttemptId::from_bytes(&id_bytes)?;
        let record = queue
            .get_in_write_txn(wtxn, id)?
            .ok_or(Error::CorruptedIndex("attempt run index"))?;
        if record.run_id.as_deref() != Some(run_id) {
            return Err(Error::CorruptedIndex("attempt run index"));
        }
        records.push(record);
    }
    Ok(records)
}

/// Resolves a run's attempt rows to the single surface-event row it may hold.
///
/// A row of another kind under the same public correlation id is a typed
/// collision, and more than one row for a once-only run is corruption — never
/// "pick the latest".
fn sole_surface_event_attempt(
    mut records: Vec<AttemptRecord>,
    correlation_id: &str,
) -> Result<Option<AttemptRecord>> {
    if records.len() > 1 {
        return Err(Error::CorruptedIndex("surface event correlation run"));
    }
    let Some(record) = records.pop() else {
        return Ok(None);
    };
    if record.kind != SURFACE_EVENT_ATTEMPT_KIND {
        return Err(Error::SurfaceEventCorrelationKindCollision {
            correlation_id: correlation_id.to_owned(),
            holding_kind: record.kind,
        });
    }
    Ok(Some(record))
}

fn handoff_status(correlation_id: &str, record: &AttemptRecord) -> SurfaceEventHandoffStatus {
    SurfaceEventHandoffStatus {
        correlation_id: correlation_id.to_owned(),
        attempt_ref: SurfaceEventAttemptRef::from_attempt_id(record.id),
        state: SurfaceEventHandoffState::from_attempt_state(record.state),
        attempt_count: record.attempt_count,
        last_error: record.last_error.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

/// Status URL an ack points at, with the correlation id percent-encoded so a
/// provider id carrying `/` or `?` still addresses its own resource.
fn surface_event_status_path(correlation_id: &str) -> String {
    let mut path = String::from(SURFACE_EVENT_STATUS_PATH_PREFIX);
    for byte in correlation_id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            path.push(byte as char);
        } else {
            path.push('%');
            path.push(HEX_DIGITS[usize::from(byte >> 4)].to_ascii_uppercase() as char);
            path.push(HEX_DIGITS[usize::from(byte & 0x0f)].to_ascii_uppercase() as char);
        }
    }
    path
}

/// Encodes an attempt payload for durable storage.
pub fn encode_surface_event_attempt_payload(
    payload: &SurfaceEventAttemptPayload,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(payload).map_err(|error| {
        Error::InvalidConfig(format!(
            "surface event attempt payload did not encode: {error}"
        ))
    })
}

/// Decodes a durable attempt payload.
pub fn decode_surface_event_attempt_payload(bytes: &[u8]) -> Result<SurfaceEventAttemptPayload> {
    rmp_serde::from_slice(bytes)
        .map_err(|_| Error::InvalidAttemptQueueRecord("surface event attempt payload"))
}

/// Longest provider correlation id carried into the queue verbatim.
///
/// The attempt queue caps `run_id` at 128 bytes (and `dedupe_key` at 512). A
/// provider id at or under this cap is its own key; anything longer folds to a
/// `sha256:` digest so admission never rejects an event merely for a long
/// provider id.
const MAX_VERBATIM_CORRELATION_RUN_ID_BYTES: usize = 128;

/// Derives the bounded queue key for a public correlation id.
///
/// Keys both the durable run index and the queue's dedupe index, so a replay
/// resolves to one row through either. Deterministic in both directions of a
/// replay: the same provider id always yields the same key, and the public
/// correlation id is never rewritten.
#[must_use]
pub fn surface_event_run_id(correlation_id: &str) -> String {
    if correlation_id.len() <= MAX_VERBATIM_CORRELATION_RUN_ID_BYTES {
        return correlation_id.to_owned();
    }
    let digest = Sha256::digest(correlation_id.as_bytes());
    let mut run_id = String::with_capacity("sha256:".len() + digest.len() * 2);
    run_id.push_str("sha256:");
    for byte in digest {
        run_id.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        run_id.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
    }
    run_id
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
