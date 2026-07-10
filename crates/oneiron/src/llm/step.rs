//! LLM-5 durable-step layer: `call_as_step` BLAKE3 memoization plus the
//! unified Budget/Consent trap record (ONE-1343).
//!
//! Step identity is the request content hash ([`LlmRequest::canonical_hash`])
//! — never a call-site ordinal. Memo scope is `(job_id, step_hash)` and is
//! per-device: live progression and the memo index live in private
//! `vault_meta` rows that never sync, while ONE terminal `dreamer.step`
//! vault claim per finished step is the durable, auditable record
//! (checkpoint-in-append). Control flow re-runs on resume; side effects are
//! memoized — never bit-replayed.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use rmpv::Value;

use crate::Vault;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
use crate::dreamer_runner::DREAMER_RUNNER_JOB_KIND;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::job_queue::JobId;
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::{
    ClaimCandidate, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
    WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY, WriteActor, WriteEnvelope, WriteProvenance,
};

use super::{
    BudgetDenied, BudgetGuard, CallClass, CallPurpose, LlmBackend, LlmError, LlmRequest,
    LlmResponse, LlmResult, canonical_json_bytes,
};

/// Claim predicate for terminal durable-step records (design D13).
pub const DREAMER_STEP_PREDICATE: &str = "dreamer.step";
/// Claim predicate for the unified Budget/Consent trap record (design D4).
pub const DREAMER_TRAP_PREDICATE: &str = "dreamer.trap";
/// Current pinned `dreamer.step` claim value schema version.
pub const DREAMER_STEP_VALUE_SCHEMA_VERSION: u64 = 1;
/// Pinned MessagePack key set for `dreamer.step` claim values.
pub const DREAMER_STEP_VALUE_KEYS: [&str; 12] = [
    "schema_version",
    "job_id",
    "step_hash",
    "progression",
    "model_id",
    "purpose",
    "params_hash",
    "usage_in",
    "usage_out",
    "response",
    "response_ref",
    "at",
];
/// Current pinned `dreamer.trap` claim value schema version.
pub const DREAMER_TRAP_VALUE_SCHEMA_VERSION: u64 = 1;
/// Pinned MessagePack key set for `dreamer.trap` claim values.
pub const DREAMER_TRAP_VALUE_KEYS: [&str; 7] = [
    "schema_version",
    "trap_kind",
    "job_id",
    "step_hash",
    "state",
    "at",
    "note",
];
/// Terminal responses at or under this encoded size inline into the step
/// claim; larger responses live in a type-85 `BlobArtifact` behind
/// `response_ref` (C9 claim-check/pointer rule).
pub const DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES: usize = 16_384;
/// Retry backoff schedule for [`LlmError::Retryable`] failures — the ONE
/// retry authority (ruling L6). One retry per entry, all under the SAME
/// lease; absolute settlement makes retries free of double-count.
pub const DREAMER_STEP_RETRY_BACKOFF_MS: [u64; 3] = [250, 1_000, 4_000];

const DREAMER_PRIVATE_STEP_STATE_PREFIX: &[u8] = b"dreamer:step_state:v1:"; // + job_id(16) + step_hash(32)
const DREAMER_PRIVATE_STEP_INDEX_PREFIX: &[u8] = b"dreamer:step_index:v1:"; // + job_id(16) + step_hash(32) -> claim id (16)
const DREAMER_PRIVATE_STEP_INDEX_CLAIM_PREFIX: &[u8] = b"dreamer:step_index:v1:i:"; // + claim id (16) -> forward key
const DREAMER_PRIVATE_TRAP_BINDING_PREFIX: &[u8] = b"dreamer:trap_binding:v1:"; // + trap anchor claim id (16)

const DREAMER_STEP_STATE_SCHEMA_VERSION: u64 = 1;
const DREAMER_STEP_STATE_KEYS: [&str; 5] = [
    "schema_version",
    "progression",
    "started_at",
    "updated_at",
    "response",
];

const DREAMER_TRAP_BINDING_SCHEMA_VERSION: u64 = 1;
const DREAMER_TRAP_BINDING_KEYS: [&str; 4] =
    ["schema_version", "job_id", "step_hash", "park_owner"];

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_JOB_ID: &str = "job_id";
const KEY_STEP_HASH: &str = "step_hash";
const KEY_PROGRESSION: &str = "progression";
const KEY_MODEL_ID: &str = "model_id";
const KEY_PURPOSE: &str = "purpose";
const KEY_PARAMS_HASH: &str = "params_hash";
const KEY_USAGE_IN: &str = "usage_in";
const KEY_USAGE_OUT: &str = "usage_out";
const KEY_RESPONSE: &str = "response";
const KEY_RESPONSE_REF: &str = "response_ref";
const KEY_AT: &str = "at";
const KEY_TRAP_KIND: &str = "trap_kind";
const KEY_STATE: &str = "state";
const KEY_NOTE: &str = "note";
const KEY_PARK_OWNER: &str = "park_owner";
const KEY_STARTED_AT: &str = "started_at";
const KEY_UPDATED_AT: &str = "updated_at";

const TRAP_CHAIN_WALK_CAP: usize = 64;

pub type DurableStepResult<T> = std::result::Result<T, DurableStepError>;

/// Typed failure surface of the durable-step layer.
#[derive(Debug, thiserror::Error)]
pub enum DurableStepError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Llm(#[from] LlmError),
    #[error("durable step canonicalization failed: {0}")]
    Canonical(#[from] serde_json::Error),
    /// Fatal terminal failure on a `CallClass::Durable` request: the caller
    /// must execute its declared deterministic fallback — silent-empty
    /// results are FORBIDDEN (ruling L6).
    #[error(
        "durable step fatal LLM error; execute declared deterministic fallback {fallback:?}: {source}"
    )]
    FallbackDemanded { fallback: String, source: LlmError },
}

/// Live progression of one durable step, stored as `u8` in the private
/// device-local state row (ruling L6): `Started → ResponseReceived →
/// Logged → Finished`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepProgression {
    Started,
    ResponseReceived,
    Logged,
    Finished,
}

impl StepProgression {
    /// Stable progression string used in `dreamer.step` claim values.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::ResponseReceived => "response_received",
            Self::Logged => "logged",
            Self::Finished => "finished",
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::Started => 0,
            Self::ResponseReceived => 1,
            Self::Logged => 2,
            Self::Finished => 3,
        }
    }

    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Started),
            1 => Some(Self::ResponseReceived),
            2 => Some(Self::Logged),
            3 => Some(Self::Finished),
            _ => None,
        }
    }
}

/// Trap flavor carried by one `dreamer.trap` record kind (design D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DreamerTrapKind {
    Budget,
    Consent,
}

impl DreamerTrapKind {
    /// Stable trap-kind string used in `dreamer.trap` claim values.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Budget => "budget",
            Self::Consent => "consent",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "budget" => Some(Self::Budget),
            "consent" => Some(Self::Consent),
            _ => None,
        }
    }
}

/// Trap state machine (design D4). Legal chains are
/// `created→waiting→sent→consumed` and `created→sent→consumed`
/// (signal-before-wait); every other transition is rejected fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DreamerTrapState {
    Created,
    Waiting,
    Sent,
    Consumed,
}

impl DreamerTrapState {
    /// Stable state string used in `dreamer.trap` claim values.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Waiting => "waiting",
            Self::Sent => "sent",
            Self::Consumed => "consumed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(Self::Created),
            "waiting" => Some(Self::Waiting),
            "sent" => Some(Self::Sent),
            "consumed" => Some(Self::Consumed),
            _ => None,
        }
    }

    const fn may_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Waiting)
                | (Self::Created, Self::Sent)
                | (Self::Waiting, Self::Sent)
                | (Self::Sent, Self::Consumed)
        )
    }
}

/// Caller-owned context for one durable step. The dispatcher owns
/// `envelope_actor`; guests never supply it.
#[derive(Clone)]
pub struct DurableStepContext<'a> {
    pub vault: &'a Vault,
    pub job_id: JobId,
    pub run_id: Option<String>,
    pub envelope_actor: WriteActor,
    pub subject: EntityId,
    pub now_ms: u64,
}

/// Handle to a suspended step's trap record chain. `trap_claim_id` is the
/// `created` anchor claim; state transitions supersede forward from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapRef {
    pub trap_claim_id: EntityId,
    pub kind: DreamerTrapKind,
    pub step_hash: [u8; 32],
}

/// Terminal outcome of [`call_as_step`].
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    Finished {
        response: LlmResponse,
        memoized: bool,
    },
    Trapped(TrapRef),
}

/// Durable LLM call: memoize on `(job_id, step_hash)`, spend under a
/// [`BudgetGuard`] lease, retry retryable failures (the ONE retry
/// authority), and persist ONE terminal `dreamer.step` claim.
///
/// Recovery rule (pinned): memo-index hit → memoized terminal response with
/// ZERO admission; private row at ResponseReceived/Logged with payload →
/// finish the write path from the stored payload, ZERO new spend; row at
/// Started or absent → execute normally under a FRESH lease (one bounded
/// re-spend; the prior lease settled/aborted on its own path).
pub async fn call_as_step(
    ctx: &DurableStepContext<'_>,
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
) -> DurableStepResult<StepOutcome> {
    let step_hash = request.canonical_hash()?;

    if let Some(claim_id) = step_index_lookup(ctx.vault, ctx.job_id, &step_hash)? {
        let body = ctx
            .vault
            .get_claim(&claim_id)?
            .ok_or(Error::InvalidClaimBody("dreamer step index claim missing"))?;
        let decoded = decode_step_claim_value(&body.value)?;
        let response = load_step_response(ctx.vault, &decoded)?;
        return Ok(StepOutcome::Finished {
            response,
            memoized: true,
        });
    }

    if let Some(row) = step_state_read(ctx.vault, ctx.job_id, &step_hash)?
        && matches!(
            row.progression,
            StepProgression::ResponseReceived | StepProgression::Logged
        )
        && let Some(payload) = row.response_payload.as_deref()
    {
        let response: LlmResponse = serde_json::from_slice(payload)?;
        log_terminal_step(ctx, &step_hash, &request, &response)?;
        step_state_delete(ctx.vault, ctx.job_id, &step_hash)?;
        return Ok(StepOutcome::Finished {
            response,
            memoized: true,
        });
    }

    step_state_write(
        ctx.vault,
        ctx.job_id,
        &step_hash,
        StepProgression::Started,
        None,
        ctx.now_ms,
    )?;

    let admission = match guard.admit_for_request(&request) {
        Ok(admission) => admission,
        Err(BudgetDenied::Exhausted) => {
            let trap = open_trap(
                ctx.vault,
                ctx,
                DreamerTrapKind::Budget,
                step_hash,
                "durable step budget exhausted",
            )?;
            let store = crate::dreamer_runner::DreamerRunnerStore::new(ctx.vault);
            store.park_job(crate::dreamer_runner::ParkDreamerJob {
                job_id: ctx.job_id,
                reason: "durable step budget exhausted".to_owned(),
                park_owner: trap_park_owner(&trap.trap_claim_id),
                now: ctx.now_ms,
            })?;
            step_state_delete(ctx.vault, ctx.job_id, &step_hash)?;
            return Ok(StepOutcome::Trapped(trap));
        }
        Err(denied) => return Err(LlmError::from(denied).into()),
    };

    let response = match generate_with_retry(backend, &request, &admission.lease).await {
        Ok(response) => response,
        Err(error) => {
            let _ = guard.abort(&admission.lease);
            return Err(step_call_failure(&request, error));
        }
    };

    // The provider answered, so the tokens were really spent: the reserved
    // lease MUST settle on EVERY exit from the post-response persistence block.
    // A `?` out of `serde_json::to_vec` / `step_state_write` /
    // `log_terminal_step` returns BEFORE the explicit settle below, which would
    // leak the reserved units for the guard's lifetime and throttle later
    // admissions (#478-1). This RAII guard settles on drop; `settle_absolute`
    // is idempotent on an already-settled lease, so the happy-path settle stays
    // a no-op once the guard is disarmed.
    let lease_settle = LeaseSettleOnDrop::new(guard, &admission.lease, &response.usage);

    let payload = serde_json::to_vec(&response)?;
    step_state_write(
        ctx.vault,
        ctx.job_id,
        &step_hash,
        StepProgression::ResponseReceived,
        Some(&payload),
        ctx.now_ms,
    )?;

    log_terminal_step(ctx, &step_hash, &request, &response)?;

    lease_settle.settle().map_err(LlmError::from)?;
    step_state_delete(ctx.vault, ctx.job_id, &step_hash)?;

    Ok(StepOutcome::Finished {
        response,
        memoized: false,
    })
}

fn step_call_failure(request: &LlmRequest, error: LlmError) -> DurableStepError {
    if matches!(error, LlmError::Fatal(_))
        && let CallClass::Durable { fallback } = &request.envelope.class
    {
        return DurableStepError::FallbackDemanded {
            fallback: fallback.name.clone(),
            source: error,
        };
    }
    DurableStepError::Llm(error)
}

/// RAII settlement for a durable step's reserved lease once the provider has
/// answered. The spend is real from that point, so the lease must settle on
/// every exit from the post-response persistence block — otherwise a
/// persistence error leaks the reservation for the guard's lifetime (#478-1).
/// The happy path calls [`LeaseSettleOnDrop::settle`], which disarms the guard
/// and surfaces the settlement result; any early return drops the guard, which
/// settles best-effort. `used_units` mirrors `settle_terminal` (absolute
/// input+output totals), so both paths count the SAME spend — no undercount.
struct LeaseSettleOnDrop<'a> {
    guard: &'a BudgetGuard,
    lease: &'a super::BudgetLease,
    used_units: u64,
    armed: bool,
}

impl<'a> LeaseSettleOnDrop<'a> {
    fn new(guard: &'a BudgetGuard, lease: &'a super::BudgetLease, usage: &super::LlmUsage) -> Self {
        Self {
            guard,
            lease,
            used_units: usage.input.total.saturating_add(usage.output.total),
            armed: true,
        }
    }

    fn settle(mut self) -> std::result::Result<super::BudgetSettlement, BudgetDenied> {
        self.armed = false;
        self.guard.settle_absolute(self.lease, self.used_units)
    }
}

impl Drop for LeaseSettleOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.guard.settle_absolute(self.lease, self.used_units);
        }
    }
}

async fn generate_with_retry(
    backend: &dyn LlmBackend,
    request: &LlmRequest,
    lease: &super::BudgetLease,
) -> LlmResult<LlmResponse> {
    let mut retries = 0_usize;
    loop {
        match backend.generate(request.clone(), lease).await {
            Ok(response) => return Ok(response),
            Err(LlmError::Retryable(error)) => {
                if retries >= DREAMER_STEP_RETRY_BACKOFF_MS.len() {
                    return Err(LlmError::Retryable(error));
                }
                sleep_ms(DREAMER_STEP_RETRY_BACKOFF_MS[retries]).await;
                retries += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// std-only timer future (zero-new-deps pin, design D1): a helper thread
/// wakes the most recent waker once the deadline passes.
fn sleep_ms(ms: u64) -> SleepFuture {
    SleepFuture {
        deadline: Instant::now() + Duration::from_millis(ms),
        shared_waker: None,
    }
}

struct SleepFuture {
    deadline: Instant,
    shared_waker: Option<Arc<Mutex<Waker>>>,
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(());
        }
        if let Some(shared) = &self.shared_waker {
            *shared.lock().expect("sleep waker mutex poisoned") = cx.waker().clone();
            return Poll::Pending;
        }
        let shared = Arc::new(Mutex::new(cx.waker().clone()));
        self.shared_waker = Some(Arc::clone(&shared));
        let deadline = self.deadline;
        std::thread::spawn(move || {
            let now = Instant::now();
            if deadline > now {
                std::thread::sleep(deadline - now);
            }
            shared
                .lock()
                .expect("sleep waker mutex poisoned")
                .wake_by_ref();
        });
        Poll::Pending
    }
}

// ---------------------------------------------------------------------------
// Terminal step claim (checkpoint-in-append) + memo index
// ---------------------------------------------------------------------------

fn log_terminal_step(
    ctx: &DurableStepContext<'_>,
    step_hash: &[u8; 32],
    request: &LlmRequest,
    response: &LlmResponse,
) -> DurableStepResult<EntityId> {
    let payload = serde_json::to_vec(response)?;
    let params_hash =
        bytes_to_hex_lower(blake3::hash(&canonical_json_bytes(&request.params)?).as_bytes());
    let claim_id = EntityId::now();
    let occurred = TimeRange {
        start: ctx.now_ms,
        end: ctx.now_ms,
    };
    let envelope = dreamer_runtime_envelope(ctx)?;
    let inline = payload.len() <= DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES;
    let inline_response = if inline {
        Some(String::from_utf8(payload.clone()).map_err(|_| {
            Error::InvalidClaimBody("dreamer step response encoding must be UTF-8 JSON")
        })?)
    } else {
        None
    };
    let existing_started_at =
        step_state_read(ctx.vault, ctx.job_id, step_hash)?.map_or(ctx.now_ms, |row| row.started_at);

    ctx.vault
        .with_write_txn(|wtxn| {
            let response_ref = if inline {
                None
            } else {
                let artifact_id = EntityId::now();
                let body = BlobArtifactBody::new("dreamer.step.response", "application/json");
                let encoded = encode_blob_artifact_body(&body)?;
                ctx.vault
                    .batch_in()
                    .put(
                        &artifact_id,
                        ENTITY_TYPE_BLOB_ARTIFACT,
                        occurred,
                        ctx.now_ms,
                        &encoded,
                    )
                    .apply(wtxn)?;
                let run_ref = format!("dreamer-step:{}", bytes_to_hex_lower(ctx.job_id.as_bytes()));
                ctx.vault.append_blob_artifact_version_in_txn(
                    wtxn,
                    &artifact_id,
                    &payload,
                    &BlobVersionProvenance::AgentRun { run_ref },
                    ctx.envelope_actor,
                    occurred,
                    ctx.now_ms,
                )?;
                Some(artifact_id)
            };

            let value = encode_step_claim_value(&EncodedStepClaim {
                job_id: ctx.job_id,
                step_hash: *step_hash,
                progression: StepProgression::Finished,
                model_id: request.model.as_str().to_owned(),
                purpose: call_purpose_str(&request.envelope.purpose),
                params_hash: params_hash.clone(),
                usage_in: response.usage.input.total,
                usage_out: response.usage.output.total,
                response: inline_response.clone(),
                response_ref,
                at: ctx.now_ms,
            });
            let candidate = ClaimCandidate::new(
                DREAMER_STEP_PREDICATE,
                ClaimSubject::Entity(ctx.subject),
                value,
                1.0,
            );
            ctx.vault
                .batch_in()
                .claim_candidate(&claim_id, candidate, &envelope, occurred, ctx.now_ms)
                .apply(wtxn)?;

            // The batch put hook indexes the claim; the Logged private row lands
            // in the SAME wtxn so a death here recovers from either side.
            step_state_put_in_txn(
                ctx.vault,
                wtxn,
                ctx.job_id,
                step_hash,
                &StepStateRow {
                    progression: StepProgression::Logged,
                    started_at: existing_started_at,
                    updated_at: ctx.now_ms,
                    response_payload: Some(payload.clone()),
                },
            )?;
            Ok(claim_id)
        })
        .map_err(DurableStepError::from)
}

fn load_step_response(vault: &Vault, decoded: &DecodedStepClaim) -> DurableStepResult<LlmResponse> {
    let bytes = match (&decoded.response, &decoded.response_ref) {
        (Some(inline), None) => inline.clone().into_bytes(),
        (None, Some(artifact_id)) => {
            let head = vault
                .blob_artifact_head(artifact_id)?
                .ok_or(Error::InvalidClaimBody(
                    "dreamer step response_ref artifact missing",
                ))?;
            vault
                .read_blob_artifact_version(artifact_id, head.version)?
                .ok_or(Error::InvalidClaimBody(
                    "dreamer step response_ref version missing",
                ))?
        }
        // decode_step_claim_value already fail-closes; defensive here.
        _ => {
            return Err(
                Error::InvalidClaimBody("dreamer step claim response shape invalid").into(),
            );
        }
    };
    Ok(serde_json::from_slice(&bytes)?)
}

fn call_purpose_str(purpose: &CallPurpose) -> String {
    match purpose {
        CallPurpose::Extraction => "extraction".to_owned(),
        CallPurpose::Consolidation => "consolidation".to_owned(),
        CallPurpose::AnswerGen => "answer_gen".to_owned(),
        CallPurpose::AutoCheck => "auto_check".to_owned(),
        CallPurpose::ToolRouting => "tool_routing".to_owned(),
        CallPurpose::Voice => "voice".to_owned(),
        CallPurpose::Eval => "eval".to_owned(),
        CallPurpose::Other { name } => format!("other:{name}"),
    }
}

fn dreamer_runtime_envelope(ctx: &DurableStepContext<'_>) -> Result<WriteEnvelope> {
    let mut entries = vec![(Value::from("surface"), Value::from(DREAMER_RUNNER_JOB_KIND))];
    if let Some(run_id) = &ctx.run_id {
        entries.push((Value::from("run"), Value::from(run_id.as_str())));
    }
    entries.push((
        Value::from("job_id"),
        Value::from(bytes_to_hex_lower(ctx.job_id.as_bytes())),
    ));
    Ok(WriteEnvelope::new(
        ctx.envelope_actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(entries))?,
        ClaimApprovalStatus::Proposed,
    ))
}

struct EncodedStepClaim {
    job_id: JobId,
    step_hash: [u8; 32],
    progression: StepProgression,
    model_id: String,
    purpose: String,
    params_hash: String,
    usage_in: u64,
    usage_out: u64,
    response: Option<String>,
    response_ref: Option<EntityId>,
    at: u64,
}

fn encode_step_claim_value(claim: &EncodedStepClaim) -> Value {
    let mut entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_STEP_VALUE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_JOB_ID),
            Value::Binary(claim.job_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::from(bytes_to_hex_lower(&claim.step_hash)),
        ),
        (
            Value::from(KEY_PROGRESSION),
            Value::from(claim.progression.as_str()),
        ),
        (
            Value::from(KEY_MODEL_ID),
            Value::from(claim.model_id.as_str()),
        ),
        (
            Value::from(KEY_PURPOSE),
            Value::from(claim.purpose.as_str()),
        ),
        (
            Value::from(KEY_PARAMS_HASH),
            Value::from(claim.params_hash.as_str()),
        ),
        (Value::from(KEY_USAGE_IN), Value::from(claim.usage_in)),
        (Value::from(KEY_USAGE_OUT), Value::from(claim.usage_out)),
    ];
    if let Some(response) = &claim.response {
        entries.push((Value::from(KEY_RESPONSE), Value::from(response.as_str())));
    }
    if let Some(response_ref) = &claim.response_ref {
        entries.push((
            Value::from(KEY_RESPONSE_REF),
            Value::Binary(response_ref.as_bytes().to_vec()),
        ));
    }
    entries.push((Value::from(KEY_AT), Value::from(claim.at)));
    Value::Map(entries)
}

pub(crate) struct DecodedStepClaim {
    pub(crate) job_id: JobId,
    pub(crate) step_hash: [u8; 32],
    #[allow(dead_code)] // audit field; consumed by ONE-1344's provenance asserts
    pub(crate) progression: StepProgression,
    #[allow(dead_code)]
    pub(crate) model_id: String,
    #[allow(dead_code)]
    pub(crate) purpose: String,
    #[allow(dead_code)]
    pub(crate) params_hash: String,
    #[allow(dead_code)]
    pub(crate) usage_in: u64,
    #[allow(dead_code)]
    pub(crate) usage_out: u64,
    pub(crate) response: Option<String>,
    pub(crate) response_ref: Option<EntityId>,
    #[allow(dead_code)]
    pub(crate) at: u64,
}

/// Fail-closed `dreamer.step` claim value decode: pinned keys only, no
/// duplicates, schema-version checked, and EXACTLY ONE of
/// `response`/`response_ref` present (both or neither is a typed error).
pub(crate) fn decode_step_claim_value(value: &Value) -> Result<DecodedStepClaim> {
    let entries = expect_map(value, "dreamer step value must be a MessagePack map")?;
    let mut schema_version = None;
    let mut job_id = None;
    let mut step_hash = None;
    let mut progression = None;
    let mut model_id = None;
    let mut purpose = None;
    let mut params_hash = None;
    let mut usage_in = None;
    let mut usage_out = None;
    let mut response = None;
    let mut response_ref = None;
    let mut at = None;
    let mut seen = [false; DREAMER_STEP_VALUE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer step value keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_STEP_VALUE_KEYS)
            .ok_or(invalid_step("dreamer step value key is not pinned"))?;
        if seen[index] {
            return Err(invalid_step("duplicate dreamer step value key"));
        }
        seen[index] = true;

        match DREAMER_STEP_VALUE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer step value schema_version must be an integer",
                )?);
            }
            KEY_JOB_ID => job_id = Some(decode_job_id_value(value)?),
            KEY_STEP_HASH => {
                let hex = expect_string(value, "dreamer step value step_hash must be a string")?;
                step_hash = Some(decode_hash_hex(&hex)?);
            }
            KEY_PROGRESSION => {
                let parsed =
                    expect_string(value, "dreamer step value progression must be a string")?;
                progression = Some(parse_progression_str(&parsed)?);
            }
            KEY_MODEL_ID => {
                model_id = Some(expect_string(
                    value,
                    "dreamer step value model_id must be a string",
                )?);
            }
            KEY_PURPOSE => {
                purpose = Some(expect_string(
                    value,
                    "dreamer step value purpose must be a string",
                )?);
            }
            KEY_PARAMS_HASH => {
                params_hash = Some(expect_string(
                    value,
                    "dreamer step value params_hash must be a string",
                )?);
            }
            KEY_USAGE_IN => {
                usage_in = Some(expect_u64(
                    value,
                    "dreamer step value usage_in must be an integer",
                )?);
            }
            KEY_USAGE_OUT => {
                usage_out = Some(expect_u64(
                    value,
                    "dreamer step value usage_out must be an integer",
                )?);
            }
            KEY_RESPONSE => {
                response = Some(expect_string(
                    value,
                    "dreamer step value response must be a string",
                )?);
            }
            KEY_RESPONSE_REF => response_ref = Some(decode_entity_id_value(value)?),
            KEY_AT => {
                at = Some(expect_u64(
                    value,
                    "dreamer step value at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_STEP_VALUE_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_step("missing dreamer step value schema_version"))?;
    if schema_version != DREAMER_STEP_VALUE_SCHEMA_VERSION {
        return Err(invalid_step(
            "unsupported dreamer step value schema_version",
        ));
    }
    if response.is_some() == response_ref.is_some() {
        return Err(invalid_step(
            "dreamer step value must carry exactly one of response/response_ref",
        ));
    }

    Ok(DecodedStepClaim {
        job_id: job_id.ok_or(invalid_step("missing dreamer step value job_id"))?,
        step_hash: step_hash.ok_or(invalid_step("missing dreamer step value step_hash"))?,
        progression: progression.ok_or(invalid_step("missing dreamer step value progression"))?,
        model_id: model_id.ok_or(invalid_step("missing dreamer step value model_id"))?,
        purpose: purpose.ok_or(invalid_step("missing dreamer step value purpose"))?,
        params_hash: params_hash.ok_or(invalid_step("missing dreamer step value params_hash"))?,
        usage_in: usage_in.ok_or(invalid_step("missing dreamer step value usage_in"))?,
        usage_out: usage_out.ok_or(invalid_step("missing dreamer step value usage_out"))?,
        response,
        response_ref,
        at: at.ok_or(invalid_step("missing dreamer step value at"))?,
    })
}

fn parse_progression_str(value: &str) -> Result<StepProgression> {
    match value {
        "started" => Ok(StepProgression::Started),
        "response_received" => Ok(StepProgression::ResponseReceived),
        "logged" => Ok(StepProgression::Logged),
        "finished" => Ok(StepProgression::Finished),
        _ => Err(invalid_step("unknown dreamer step value progression")),
    }
}

// ---------------------------------------------------------------------------
// Memo index maintenance (device-local; wired at the milestone hook points)
// ---------------------------------------------------------------------------

/// Indexes a `dreamer.step` claim into the private memo index inside the
/// caller's write txn. Twin of `index_dreamer_milestone_claim_for_put`;
/// non-Active/stale bodies deindex.
pub(crate) fn index_dreamer_step_claim_for_put(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
    _learned_at: u64,
) -> Result<()> {
    deindex_dreamer_step_claim(store, wtxn, claim_id)?;

    if body.predicate != DREAMER_STEP_PREDICATE
        || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        || body.stale
    {
        return Ok(());
    }
    let Ok(decoded) = decode_step_claim_value(&body.value) else {
        return Ok(());
    };

    let forward_key = step_index_key(decoded.job_id, &decoded.step_hash);
    store
        .vault_meta
        .put(wtxn, &forward_key, claim_id.as_bytes())?;
    store
        .vault_meta
        .put(wtxn, &step_index_claim_key(claim_id), &forward_key)?;
    Ok(())
}

/// Removes a claim's memo-index rows inside the caller's write txn.
pub(crate) fn deindex_dreamer_step_claim(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
) -> Result<()> {
    let claim_key = step_index_claim_key(claim_id);
    let Some(forward_key) = store.vault_meta.get(wtxn, &claim_key)?.map(<[u8]>::to_vec) else {
        return Ok(());
    };
    // Only delete the forward row if it still points at THIS claim.
    if let Some(current) = store.vault_meta.get(wtxn, &forward_key)?
        && current == claim_id.as_bytes()
    {
        store.vault_meta.delete(wtxn, &forward_key)?;
    }
    store.vault_meta.delete(wtxn, &claim_key)?;
    Ok(())
}

fn step_index_lookup(
    vault: &Vault,
    job_id: JobId,
    step_hash: &[u8; 32],
) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = step_index_key(job_id, step_hash);
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    let bytes: [u8; 16] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("dreamer step index row"))?;
    EntityId::from_bytes(bytes).map(Some)
}

fn step_index_key(job_id: JobId, step_hash: &[u8; 32]) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(DREAMER_PRIVATE_STEP_INDEX_PREFIX.len() + 16 + step_hash.len());
    key.extend_from_slice(DREAMER_PRIVATE_STEP_INDEX_PREFIX);
    key.extend_from_slice(job_id.as_bytes());
    key.extend_from_slice(step_hash);
    key
}

fn step_index_claim_key(claim_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_PRIVATE_STEP_INDEX_CLAIM_PREFIX.len() + 16);
    key.extend_from_slice(DREAMER_PRIVATE_STEP_INDEX_CLAIM_PREFIX);
    key.extend_from_slice(claim_id.as_bytes());
    key
}

// ---------------------------------------------------------------------------
// Private step-state rows (device-local live progression)
// ---------------------------------------------------------------------------

struct StepStateRow {
    progression: StepProgression,
    started_at: u64,
    updated_at: u64,
    response_payload: Option<Vec<u8>>,
}

fn step_state_key(job_id: JobId, step_hash: &[u8; 32]) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(DREAMER_PRIVATE_STEP_STATE_PREFIX.len() + 16 + step_hash.len());
    key.extend_from_slice(DREAMER_PRIVATE_STEP_STATE_PREFIX);
    key.extend_from_slice(job_id.as_bytes());
    key.extend_from_slice(step_hash);
    key
}

fn step_state_write(
    vault: &Vault,
    job_id: JobId,
    step_hash: &[u8; 32],
    progression: StepProgression,
    response_payload: Option<&[u8]>,
    now_ms: u64,
) -> Result<()> {
    let started_at =
        step_state_read(vault, job_id, step_hash)?.map_or(now_ms, |row| row.started_at);
    let mut wtxn = vault.store.env.write_txn()?;
    step_state_put_in_txn(
        vault,
        &mut wtxn,
        job_id,
        step_hash,
        &StepStateRow {
            progression,
            started_at,
            updated_at: now_ms,
            response_payload: response_payload.map(<[u8]>::to_vec),
        },
    )?;
    wtxn.commit()?;
    Ok(())
}

fn step_state_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    job_id: JobId,
    step_hash: &[u8; 32],
    row: &StepStateRow,
) -> Result<()> {
    let mut entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_STEP_STATE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PROGRESSION),
            Value::from(u64::from(row.progression.as_u8())),
        ),
        (Value::from(KEY_STARTED_AT), Value::from(row.started_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(row.updated_at)),
    ];
    if let Some(payload) = &row.response_payload {
        entries.push((Value::from(KEY_RESPONSE), Value::Binary(payload.clone())));
    }
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
        .map_err(|_| invalid_step("dreamer step state row MessagePack encode failed"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &step_state_key(job_id, step_hash), &encoded)?;
    Ok(())
}

fn step_state_read(
    vault: &Vault,
    job_id: JobId,
    step_hash: &[u8; 32],
) -> Result<Option<StepStateRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &step_state_key(job_id, step_hash))?
    else {
        return Ok(None);
    };
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| invalid_step("dreamer step state row MessagePack decode failed"))?;
    let entries = expect_map(&value, "dreamer step state row must be a MessagePack map")?;

    let mut schema_version = None;
    let mut progression = None;
    let mut started_at = None;
    let mut updated_at = None;
    let mut response_payload = None;
    let mut seen = [false; DREAMER_STEP_STATE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer step state row keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_STEP_STATE_KEYS)
            .ok_or(invalid_step("dreamer step state row key is not pinned"))?;
        if seen[index] {
            return Err(invalid_step("duplicate dreamer step state row key"));
        }
        seen[index] = true;

        match DREAMER_STEP_STATE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer step state schema_version must be an integer",
                )?);
            }
            KEY_PROGRESSION => {
                let raw = expect_u64(value, "dreamer step state progression must be an integer")?;
                let raw = u8::try_from(raw)
                    .map_err(|_| invalid_step("dreamer step state progression out of range"))?;
                progression = Some(
                    StepProgression::from_u8(raw)
                        .ok_or(invalid_step("unknown dreamer step state progression"))?,
                );
            }
            KEY_STARTED_AT => {
                started_at = Some(expect_u64(
                    value,
                    "dreamer step state started_at must be an integer",
                )?);
            }
            KEY_UPDATED_AT => {
                updated_at = Some(expect_u64(
                    value,
                    "dreamer step state updated_at must be an integer",
                )?);
            }
            KEY_RESPONSE => {
                let Value::Binary(bytes) = value else {
                    return Err(invalid_step("dreamer step state response must be binary"));
                };
                response_payload = Some(bytes.clone());
            }
            _ => unreachable!("index resolved from DREAMER_STEP_STATE_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_step("missing dreamer step state schema_version"))?;
    if schema_version != DREAMER_STEP_STATE_SCHEMA_VERSION {
        return Err(invalid_step(
            "unsupported dreamer step state schema_version",
        ));
    }

    Ok(Some(StepStateRow {
        progression: progression.ok_or(invalid_step("missing dreamer step state progression"))?,
        started_at: started_at.ok_or(invalid_step("missing dreamer step state started_at"))?,
        updated_at: updated_at.ok_or(invalid_step("missing dreamer step state updated_at"))?,
        response_payload,
    }))
}

fn step_state_delete(vault: &Vault, job_id: JobId, step_hash: &[u8; 32]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, &step_state_key(job_id, step_hash))?;
    wtxn.commit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Trap record: ONE claim kind, supersession-based state machine (design D4)
// ---------------------------------------------------------------------------

/// Park-owner token derived from a trap's `created` anchor claim id. The
/// step layer parks trapped jobs under THIS token, records it in the trap's
/// private binding row, and the consume path resumes with it — a parked row
/// held by any other owner is refused fail-closed.
#[must_use]
pub fn trap_park_owner(trap_claim_id: &EntityId) -> String {
    format!(
        "dreamer.trap:{}",
        bytes_to_hex_lower(trap_claim_id.as_bytes())
    )
}

/// Opens a trap for a suspended step: writes the `created` anchor claim AND
/// the private trap-binding row (job id + step hash + park owner) in ONE
/// wtxn. The binding row is the device-local ground truth the consume path
/// validates against — it never syncs and cannot be forged through claims.
/// The budget path in [`call_as_step`] parks the job right after; consent
/// waits arrive via [`trap_for_durable_wait`].
pub fn open_trap(
    vault: &Vault,
    ctx: &DurableStepContext<'_>,
    kind: DreamerTrapKind,
    step_hash: [u8; 32],
    note: &str,
) -> Result<TrapRef> {
    let claim_id = EntityId::now();
    let value = encode_trap_claim_value(&EncodedTrapClaim {
        kind,
        job_id: ctx.job_id,
        step_hash,
        state: DreamerTrapState::Created,
        at: ctx.now_ms,
        note: note.to_owned(),
    });
    let candidate = ClaimCandidate::new(
        DREAMER_TRAP_PREDICATE,
        ClaimSubject::Entity(ctx.subject),
        value,
        1.0,
    );
    let envelope = dreamer_runtime_envelope(ctx)?;
    let occurred = TimeRange {
        start: ctx.now_ms,
        end: ctx.now_ms,
    };
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(&claim_id, candidate, &envelope, occurred, ctx.now_ms)
            .apply(wtxn)?;
        trap_binding_put_in_txn(
            vault,
            wtxn,
            &claim_id,
            &TrapBindingRow {
                job_id: ctx.job_id,
                step_hash,
                park_owner: trap_park_owner(&claim_id),
            },
        )
    })?;
    Ok(TrapRef {
        trap_claim_id: claim_id,
        kind,
        step_hash,
    })
}

/// Maps a guest-facing durable wait raised inside a Dreamer job onto the
/// unified trap record kind: every wait flavor parks as a Consent trap.
#[must_use]
pub fn trap_for_durable_wait(
    wait: &crate::code_run::SelfDurableWait,
    _step_hash: [u8; 32],
) -> DreamerTrapKind {
    match wait.reason {
        crate::code_run::SelfDurableWaitReason::HumanInput
        | crate::code_run::SelfDurableWaitReason::DestructiveEffect
        | crate::code_run::SelfDurableWaitReason::OutboundEffect => DreamerTrapKind::Consent,
    }
}

/// Registers the runner's wait on an open trap (`created→waiting`).
/// Signal-before-wait: if the signal already landed, returns `Sent` without
/// writing; the caller proceeds straight to consume.
pub fn register_wait(vault: &Vault, trap: &TrapRef, now: u64) -> Result<DreamerTrapState> {
    let (head_id, head) = trap_head(vault, &trap.trap_claim_id)?;
    match head.state {
        DreamerTrapState::Created => {
            append_trap_transition(vault, &head_id, &head, DreamerTrapState::Waiting, now, None)?;
            Ok(DreamerTrapState::Waiting)
        }
        DreamerTrapState::Waiting => Ok(DreamerTrapState::Waiting),
        DreamerTrapState::Sent => Ok(DreamerTrapState::Sent),
        DreamerTrapState::Consumed => Err(invalid_trap("dreamer trap already consumed")),
    }
}

/// Writes the resume SIGNAL (`→sent`). The body MUST carry the suspended
/// step's hash; a mismatched hash is rejected here (defense in depth) and
/// again independently at consume (the security boundary, ruling L8).
pub fn send_trap_signal(
    vault: &Vault,
    trap_claim_id: &EntityId,
    step_hash: [u8; 32],
    now: u64,
) -> Result<EntityId> {
    let (head_id, head) = trap_head(vault, trap_claim_id)?;
    if head.step_hash != step_hash {
        return Err(invalid_trap("dreamer trap signal hash mismatch"));
    }
    if !head.state.may_transition_to(DreamerTrapState::Sent) {
        return Err(invalid_trap("dreamer trap signal on non-waiting trap"));
    }
    append_trap_transition(vault, &head_id, &head, DreamerTrapState::Sent, now, None)
}

/// Validates and absorbs the resume signal (`→consumed`).
///
/// Fail-closed validation (ruling L8, uniform including the durable path):
/// the head must be `sent`; the anchor must be THIS trap's `created` record
/// (a record in any other state cannot anchor a consume); the binding —
/// job id, step hash, and park owner — is re-derived from the PRIVATE row
/// written when the trap opened on this device, never from caller-supplied
/// fields or synced claims (forged → typed reject); the head's supersession
/// lineage must chain back to the anchor through legal transitions (stale →
/// typed reject). On success the `consumed` transition and the
/// `resume_parked` un-park (owner-checked) commit in ONE wtxn (atomic
/// consume+resume, design D4); the resumed job id is returned.
pub fn consume_trap_signal(
    vault: &Vault,
    store: &crate::dreamer_runner::DreamerRunnerStore<'_>,
    trap: &TrapRef,
    now: u64,
) -> Result<JobId> {
    let (head_id, head) = trap_head(vault, &trap.trap_claim_id)?;
    if head.state != DreamerTrapState::Sent {
        return Err(invalid_trap("dreamer trap consume requires a sent signal"));
    }
    let anchor = vault
        .get_claim(&trap.trap_claim_id)?
        .ok_or(invalid_trap("dreamer trap created record missing"))?;
    let anchor_decoded = decode_trap_claim_value(&anchor.value)?;
    if anchor_decoded.state != DreamerTrapState::Created {
        return Err(invalid_trap("dreamer trap anchor must be a created record"));
    }
    let binding = trap_binding_read(vault, &trap.trap_claim_id)?
        .ok_or(invalid_trap("dreamer trap binding missing"))?;
    if head.step_hash != binding.step_hash
        || anchor_decoded.step_hash != binding.step_hash
        || trap.step_hash != binding.step_hash
    {
        return Err(invalid_trap("dreamer trap signal hash mismatch"));
    }
    if head.job_id != binding.job_id || anchor_decoded.job_id != binding.job_id {
        return Err(invalid_trap("dreamer trap signal names a different job"));
    }
    require_lineage_chains_to_anchor(vault, &head_id, &trap.trap_claim_id)?;

    vault.with_write_txn(|wtxn| {
        append_trap_transition_in_txn(
            vault,
            wtxn,
            &head_id,
            &head,
            DreamerTrapState::Consumed,
            now,
            None,
        )?;
        // Idempotent when no parked row exists (a consent trap raised before
        // any park, or a resume raced by the runner); a row parked by any
        // OTHER owner is refused inside resume_parked_in_txn.
        store.resume_parked_in_txn(wtxn, binding.job_id, &binding.park_owner, now)?;
        // Consumed is terminal — retire the private binding with the trap.
        trap_binding_delete_in_txn(vault, wtxn, &trap.trap_claim_id)?;
        Ok(())
    })?;
    Ok(binding.job_id)
}

#[derive(Debug, Clone)]
struct EncodedTrapClaim {
    kind: DreamerTrapKind,
    job_id: JobId,
    step_hash: [u8; 32],
    state: DreamerTrapState,
    at: u64,
    note: String,
}

fn encode_trap_claim_value(claim: &EncodedTrapClaim) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_TRAP_VALUE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_TRAP_KIND), Value::from(claim.kind.as_str())),
        (
            Value::from(KEY_JOB_ID),
            Value::Binary(claim.job_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::from(bytes_to_hex_lower(&claim.step_hash)),
        ),
        (Value::from(KEY_STATE), Value::from(claim.state.as_str())),
        (Value::from(KEY_AT), Value::from(claim.at)),
        (Value::from(KEY_NOTE), Value::from(claim.note.as_str())),
    ])
}

pub(crate) struct DecodedTrapClaim {
    pub(crate) kind: DreamerTrapKind,
    pub(crate) job_id: JobId,
    pub(crate) step_hash: [u8; 32],
    pub(crate) state: DreamerTrapState,
    #[allow(dead_code)]
    pub(crate) at: u64,
    pub(crate) note: String,
}

/// Fail-closed `dreamer.trap` claim value decode: pinned keys only, no
/// duplicates, schema-version checked, every field mandatory.
pub(crate) fn decode_trap_claim_value(value: &Value) -> Result<DecodedTrapClaim> {
    let entries = expect_map(value, "dreamer trap value must be a MessagePack map")?;
    let mut schema_version = None;
    let mut trap_kind = None;
    let mut job_id = None;
    let mut step_hash = None;
    let mut state = None;
    let mut at = None;
    let mut note = None;
    let mut seen = [false; DREAMER_TRAP_VALUE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer trap value keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_TRAP_VALUE_KEYS)
            .ok_or(invalid_trap("dreamer trap value key is not pinned"))?;
        if seen[index] {
            return Err(invalid_trap("duplicate dreamer trap value key"));
        }
        seen[index] = true;

        match DREAMER_TRAP_VALUE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer trap value schema_version must be an integer",
                )?);
            }
            KEY_TRAP_KIND => {
                let parsed = expect_string(value, "dreamer trap value trap_kind must be a string")?;
                trap_kind = Some(
                    DreamerTrapKind::parse(&parsed)
                        .ok_or(invalid_trap("unknown dreamer trap value trap_kind"))?,
                );
            }
            KEY_JOB_ID => job_id = Some(decode_job_id_value(value)?),
            KEY_STEP_HASH => {
                let hex = expect_string(value, "dreamer trap value step_hash must be a string")?;
                step_hash = Some(decode_hash_hex(&hex)?);
            }
            KEY_STATE => {
                let parsed = expect_string(value, "dreamer trap value state must be a string")?;
                state = Some(
                    DreamerTrapState::parse(&parsed)
                        .ok_or(invalid_trap("unknown dreamer trap value state"))?,
                );
            }
            KEY_AT => {
                at = Some(expect_u64(
                    value,
                    "dreamer trap value at must be an integer",
                )?);
            }
            KEY_NOTE => {
                note = Some(expect_string(
                    value,
                    "dreamer trap value note must be a string",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_TRAP_VALUE_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_trap("missing dreamer trap value schema_version"))?;
    if schema_version != DREAMER_TRAP_VALUE_SCHEMA_VERSION {
        return Err(invalid_trap(
            "unsupported dreamer trap value schema_version",
        ));
    }

    Ok(DecodedTrapClaim {
        kind: trap_kind.ok_or(invalid_trap("missing dreamer trap value trap_kind"))?,
        job_id: job_id.ok_or(invalid_trap("missing dreamer trap value job_id"))?,
        step_hash: step_hash.ok_or(invalid_trap("missing dreamer trap value step_hash"))?,
        state: state.ok_or(invalid_trap("missing dreamer trap value state"))?,
        at: at.ok_or(invalid_trap("missing dreamer trap value at"))?,
        note: note.ok_or(invalid_trap("missing dreamer trap value note"))?,
    })
}

/// Walks forward from any claim in a trap chain to the current head by
/// following inbound `Supersedes` edges (superseder → superseded).
fn trap_head(vault: &Vault, anchor: &EntityId) -> Result<(EntityId, DecodedTrapClaim)> {
    let mut current = *anchor;
    for _ in 0..TRAP_CHAIN_WALK_CAP {
        let superseder = vault
            .edges_in(&current)?
            .into_iter()
            .find(|edge| edge.kind == EdgeKind::Supersedes)
            .map(|edge| edge.target);
        match superseder {
            Some(next) => current = next,
            None => {
                let body = vault
                    .get_claim(&current)?
                    .ok_or(invalid_trap("dreamer trap record missing"))?;
                if body.predicate != DREAMER_TRAP_PREDICATE {
                    return Err(invalid_trap("dreamer trap head is not a trap record"));
                }
                return Ok((current, decode_trap_claim_value(&body.value)?));
            }
        }
    }
    Err(invalid_trap("dreamer trap supersession chain too deep"))
}

/// Walks backward from `head` via outbound `Supersedes` edges and requires
/// reaching `anchor` (the run's `created` record). A sent record that does
/// not chain to this run's anchor is stale.
fn require_lineage_chains_to_anchor(
    vault: &Vault,
    head: &EntityId,
    anchor: &EntityId,
) -> Result<()> {
    let mut current = *head;
    for _ in 0..TRAP_CHAIN_WALK_CAP {
        if current == *anchor {
            return Ok(());
        }
        let superseded = vault
            .edges_out(&current)?
            .into_iter()
            .find(|edge| edge.kind == EdgeKind::Supersedes)
            .map(|edge| edge.target);
        match superseded {
            Some(next) => current = next,
            None => return Err(invalid_trap("dreamer trap signal not chained to this trap")),
        }
    }
    Err(invalid_trap("dreamer trap supersession chain too deep"))
}

/// Appends one trap state transition: writes the next-state claim and
/// supersedes the current head in ONE wtxn. Illegal transitions are typed
/// rejects and write nothing.
fn append_trap_transition(
    vault: &Vault,
    head_id: &EntityId,
    head: &DecodedTrapClaim,
    next: DreamerTrapState,
    now: u64,
    note_override: Option<&str>,
) -> Result<EntityId> {
    vault.with_write_txn(|wtxn| {
        append_trap_transition_in_txn(vault, wtxn, head_id, head, next, now, note_override)
    })
}

/// Transaction-composable body of [`append_trap_transition`], so the consume
/// path can co-commit the transition with the `resume_parked` un-park.
fn append_trap_transition_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    head_id: &EntityId,
    head: &DecodedTrapClaim,
    next: DreamerTrapState,
    now: u64,
    note_override: Option<&str>,
) -> Result<EntityId> {
    if !head.state.may_transition_to(next) {
        return Err(invalid_trap("illegal dreamer trap state transition"));
    }
    let head_body = vault
        .get_claim(head_id)?
        .ok_or(invalid_trap("dreamer trap record missing"))?;
    let envelope = envelope_from_claim_body(&head_body)?;
    let subject = match head_body.subject {
        ClaimSubject::Entity(entity) => entity,
        ClaimSubject::Edge { .. } => {
            return Err(invalid_trap("dreamer trap subject must be an entity"));
        }
    };

    let claim_id = EntityId::now();
    let value = encode_trap_claim_value(&EncodedTrapClaim {
        kind: head.kind,
        job_id: head.job_id,
        step_hash: head.step_hash,
        state: next,
        at: now,
        note: note_override.map_or_else(|| head.note.clone(), str::to_owned),
    });
    let candidate = ClaimCandidate::new(
        DREAMER_TRAP_PREDICATE,
        ClaimSubject::Entity(subject),
        value,
        1.0,
    );
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    vault
        .batch_in()
        .claim_candidate(&claim_id, candidate, &envelope, occurred, now)
        .apply(wtxn)?;
    vault.supersede_claim_in_txn(wtxn, &claim_id, head_id, now)?;
    Ok(claim_id)
}

/// Rebuilds the runtime write envelope from a trap claim's envelope-stamped
/// evidence map (actor ref + class + provenance), so transitions carry the
/// same actor identity as the record they supersede.
fn envelope_from_claim_body(body: &ClaimBody) -> Result<WriteEnvelope> {
    let Some(Value::Map(entries)) = &body.evidence else {
        return Err(invalid_trap(
            "dreamer trap record missing envelope evidence",
        ));
    };
    let mut actor_ref = None;
    let mut actor_class = None;
    let mut provenance = None;
    for (key, value) in entries {
        match key.as_str() {
            Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY) => {
                if let Value::Binary(bytes) = value
                    && let Ok(raw) = <[u8; 16]>::try_from(bytes.as_slice())
                {
                    actor_ref = EntityId::from_bytes(raw).ok();
                }
            }
            Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY) => {
                actor_class = value
                    .as_u64()
                    .and_then(|raw| u8::try_from(raw).ok())
                    .and_then(EdgeActorClass::try_from_u8);
            }
            Some(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY) => provenance = Some(value.clone()),
            _ => {}
        }
    }
    let actor_ref = actor_ref.ok_or(invalid_trap("dreamer trap evidence missing actor"))?;
    let actor_class =
        actor_class.ok_or(invalid_trap("dreamer trap evidence missing actor class"))?;
    let provenance = provenance.ok_or(invalid_trap("dreamer trap evidence missing provenance"))?;
    Ok(WriteEnvelope::new(
        WriteActor::new(actor_ref, actor_class),
        ClaimSource::Generated,
        WriteProvenance::new(provenance)?,
        ClaimApprovalStatus::Proposed,
    ))
}

// ---------------------------------------------------------------------------
// Private trap-binding rows (device-local consume ground truth, ruling L8)
// ---------------------------------------------------------------------------

/// Device-local binding of one trap anchor to the suspended step: written by
/// [`open_trap`] in the anchor's wtxn, read back at consume as the ONLY
/// authority for the job id, step hash, and park owner.
struct TrapBindingRow {
    job_id: JobId,
    step_hash: [u8; 32],
    park_owner: String,
}

fn trap_binding_key(anchor: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_PRIVATE_TRAP_BINDING_PREFIX.len() + 16);
    key.extend_from_slice(DREAMER_PRIVATE_TRAP_BINDING_PREFIX);
    key.extend_from_slice(anchor.as_bytes());
    key
}

fn trap_binding_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    anchor: &EntityId,
    row: &TrapBindingRow,
) -> Result<()> {
    let entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_TRAP_BINDING_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_JOB_ID),
            Value::Binary(row.job_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::Binary(row.step_hash.to_vec()),
        ),
        (
            Value::from(KEY_PARK_OWNER),
            Value::from(row.park_owner.as_str()),
        ),
    ];
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
        .map_err(|_| invalid_trap("dreamer trap binding row MessagePack encode failed"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &trap_binding_key(anchor), &encoded)?;
    Ok(())
}

fn trap_binding_read(vault: &Vault, anchor: &EntityId) -> Result<Option<TrapBindingRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &trap_binding_key(anchor))?
    else {
        return Ok(None);
    };
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| invalid_trap("dreamer trap binding row MessagePack decode failed"))?;
    let entries = expect_map(&value, "dreamer trap binding row must be a MessagePack map")?;

    let mut schema_version = None;
    let mut job_id = None;
    let mut step_hash = None;
    let mut park_owner = None;
    let mut seen = [false; DREAMER_TRAP_BINDING_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer trap binding row keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_TRAP_BINDING_KEYS)
            .ok_or(invalid_trap("dreamer trap binding row key is not pinned"))?;
        if seen[index] {
            return Err(invalid_trap("duplicate dreamer trap binding row key"));
        }
        seen[index] = true;

        match DREAMER_TRAP_BINDING_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer trap binding schema_version must be an integer",
                )?);
            }
            KEY_JOB_ID => job_id = Some(decode_job_id_value(value)?),
            KEY_STEP_HASH => {
                let Value::Binary(bytes) = value else {
                    return Err(invalid_trap(
                        "dreamer trap binding step_hash must be binary",
                    ));
                };
                let raw: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid_trap("dreamer trap binding step_hash must be 32 bytes"))?;
                step_hash = Some(raw);
            }
            KEY_PARK_OWNER => {
                park_owner = Some(expect_string(
                    value,
                    "dreamer trap binding park_owner must be a string",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_TRAP_BINDING_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_trap("missing dreamer trap binding schema_version"))?;
    if schema_version != DREAMER_TRAP_BINDING_SCHEMA_VERSION {
        return Err(invalid_trap(
            "unsupported dreamer trap binding schema_version",
        ));
    }

    Ok(Some(TrapBindingRow {
        job_id: job_id.ok_or(invalid_trap("missing dreamer trap binding job_id"))?,
        step_hash: step_hash.ok_or(invalid_trap("missing dreamer trap binding step_hash"))?,
        park_owner: park_owner.ok_or(invalid_trap("missing dreamer trap binding park_owner"))?,
    }))
}

fn trap_binding_delete_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    anchor: &EntityId,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .delete(wtxn, &trap_binding_key(anchor))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Codec helpers (the pinned_key_index idiom, local to the step layer)
// ---------------------------------------------------------------------------

const fn invalid_step(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

const fn invalid_trap(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

fn pinned_key_index(key: &str, keys: &[&str]) -> Option<usize> {
    keys.iter().position(|pinned| *pinned == key)
}

fn expect_map<'v>(value: &'v Value, context: &'static str) -> Result<&'v Vec<(Value, Value)>> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_step(context)),
    }
}

fn expect_key<'v>(key: &'v Value, context: &'static str) -> Result<&'v str> {
    key.as_str().ok_or(invalid_step(context))
}

fn expect_u64(value: &Value, context: &'static str) -> Result<u64> {
    value.as_u64().ok_or(invalid_step(context))
}

fn expect_string(value: &Value, context: &'static str) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(invalid_step(context))
}

fn decode_job_id_value(value: &Value) -> Result<JobId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_step("dreamer step job_id must be binary"));
    };
    JobId::from_bytes(bytes)
}

fn decode_entity_id_value(value: &Value) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_step("dreamer step response_ref must be binary"));
    };
    let raw: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_step("dreamer step response_ref must be 16 bytes"))?;
    EntityId::from_bytes(raw)
}

fn decode_hash_hex(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_step("dreamer step step_hash must be 64 hex chars"));
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

const fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid_step("dreamer step step_hash must be hex")),
    }
}

#[cfg(test)]
mod tests;
