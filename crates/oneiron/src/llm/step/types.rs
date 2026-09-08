//! Shared durable-step type layer: schema consts, error, progression/trap enums, step context, and outcome.

use super::super::{LlmError, LlmResponse, PinnedConfigViolation, PinnedModelConfig};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_wake::{BudgetLegibilityEnvelope, WakePassDeadline};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::write_envelope::WriteActor;

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

pub(super) const DREAMER_PRIVATE_STEP_STATE_PREFIX: &[u8] = b"dreamer:step_state:v1:"; // + job_id(16) + step_hash(32)

pub(super) const DREAMER_PRIVATE_STEP_INDEX_PREFIX: &[u8] = b"dreamer:step_index:v1:"; // + job_id(16) + step_hash(32) -> claim id (16)

pub(super) const DREAMER_PRIVATE_STEP_INDEX_CLAIM_PREFIX: &[u8] = b"dreamer:step_index:v1:i:"; // + claim id (16) -> forward key

pub(super) const DREAMER_PRIVATE_TRAP_BINDING_PREFIX: &[u8] = b"dreamer:trap_binding:v1:"; // + trap anchor claim id (16)

pub(super) const DREAMER_PRIVATE_PEER_WAIT_PREFIX: &[u8] = b"dreamer:peer_wait:v1:"; // + task ref (16)

pub(super) const DREAMER_PRIVATE_PEER_WAIT_TRAP_PREFIX: &[u8] = b"dreamer:peer_wait_trap:v1:"; // + trap anchor claim id (16) -> task ref (16)

pub(super) const DREAMER_STEP_STATE_SCHEMA_VERSION: u64 = 1;

pub(super) const DREAMER_STEP_STATE_KEYS: [&str; 5] = [
    "schema_version",
    "progression",
    "started_at",
    "updated_at",
    "response",
];

pub(super) const DREAMER_TRAP_BINDING_SCHEMA_VERSION: u64 = 1;

pub(super) const DREAMER_TRAP_BINDING_KEYS: [&str; 4] =
    ["schema_version", "job_id", "step_hash", "park_owner"];

pub(super) const DREAMER_PEER_WAIT_SCHEMA_VERSION: u64 = 1;

pub(super) const DREAMER_PEER_WAIT_KEYS: [&str; 4] =
    ["schema_version", "trap_claim_id", "step_hash", "at"];

// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";

pub(super) const KEY_ATTEMPT_ID: &str = "job_id";

pub(super) const KEY_STEP_HASH: &str = "step_hash";

pub(super) const KEY_PROGRESSION: &str = "progression";

pub(super) const KEY_MODEL_ID: &str = "model_id";

pub(super) const KEY_PURPOSE: &str = "purpose";

pub(super) const KEY_PARAMS_HASH: &str = "params_hash";

pub(super) const KEY_USAGE_IN: &str = "usage_in";

pub(super) const KEY_USAGE_OUT: &str = "usage_out";

pub(super) const KEY_RESPONSE: &str = "response";

pub(super) const KEY_RESPONSE_REF: &str = "response_ref";

pub(super) const KEY_AT: &str = "at";

pub(super) const KEY_TRAP_KIND: &str = "trap_kind";

pub(super) const KEY_STATE: &str = "state";

pub(super) const KEY_NOTE: &str = "note";

pub(super) const KEY_PARK_OWNER: &str = "park_owner";

pub(super) const KEY_TRAP_CLAIM_ID: &str = "trap_claim_id";

pub(super) const KEY_STARTED_AT: &str = "started_at";

pub(super) const KEY_UPDATED_AT: &str = "updated_at";

// Runtime write-envelope provenance keys stamped by `dreamer_runtime_envelope`
// onto every step/trap record. The memo-index admission gate (ONE-1344) reads
// them back off the stored claim, so writer and reader share these constants.
pub(super) const ENVELOPE_PROVENANCE_SURFACE_KEY: &str = "surface";

pub(super) const ENVELOPE_PROVENANCE_RUN_KEY: &str = "run";

pub(super) const ENVELOPE_PROVENANCE_ATTEMPT_KEY: &str = "job_id";

/// A `params_hash` / `step_hash` is a BLAKE3 digest rendered as lowercase hex.
pub(super) const STEP_HEX_DIGEST_LEN: usize = 64;

pub(super) const TRAP_CHAIN_WALK_CAP: usize = 64;

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
    /// NEW steps are refused once the wake pass enters its graceful-wrap
    /// finalize window (ONE-1305); memoized hits still return.
    #[error("durable step refused: wake pass is in its finalize window")]
    FinalizeRefused,
    /// The in-flight call lost the race against the wake-pass deadline: the
    /// lease was aborted and the attempt parked at the hard cut (ONE-1305).
    #[error("durable step hard cut at the wake-pass deadline")]
    DeadlineHardCut,
    /// The request was refused by the caller's opt-in pinned-model config
    /// (ONE-1344) before any hashing, memo lookup, state write, spend, or
    /// claim — the refusal leaves zero durable and zero private residue.
    #[error(transparent)]
    PinnedConfig(#[from] PinnedConfigViolation),
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

    pub(super) const fn as_u8(self) -> u8 {
        match self {
            Self::Started => 0,
            Self::ResponseReceived => 1,
            Self::Logged => 2,
            Self::Finished => 3,
        }
    }

    pub(super) const fn from_u8(value: u8) -> Option<Self> {
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
    /// A step delegated to a peer executor and is waiting for that executor's
    /// result to land on the synced TASK (ONE-1700).
    PeerResult,
    /// A step asked a PERSON and is waiting for that person's answer
    /// (ONE-1708). Distinct from `Consent`: waiting for someone to DO the work
    /// is not waiting for permission to do it.
    HumanResponse,
}

impl DreamerTrapKind {
    /// Stable trap-kind string used in `dreamer.trap` claim values.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Budget => "budget",
            Self::Consent => "consent",
            Self::PeerResult => "peer_result",
            Self::HumanResponse => "human_response",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "budget" => Some(Self::Budget),
            "consent" => Some(Self::Consent),
            "peer_result" => Some(Self::PeerResult),
            "human_response" => Some(Self::HumanResponse),
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

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(Self::Created),
            "waiting" => Some(Self::Waiting),
            "sent" => Some(Self::Sent),
            "consumed" => Some(Self::Consumed),
            _ => None,
        }
    }

    pub(super) const fn may_transition_to(self, next: Self) -> bool {
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
    pub attempt_id: AttemptId,
    pub run_id: Option<String>,
    pub envelope_actor: WriteActor,
    pub subject: EntityId,
    /// Opt-in pinned-model admission policy (ONE-1344): checked before
    /// hashing, memo, state, budget, backend, and claims. None = no policy.
    pub pinned_config: Option<&'a PinnedModelConfig>,
    /// The wake-pass deadline (ONE-1305): Some inside wake passes. Enables
    /// the finalize-window refusal for NEW steps, the mid-call deadline
    /// race, and the budget legibility envelope on finished outcomes.
    pub deadline: Option<&'a WakePassDeadline>,
    pub now_ms: u64,
}

impl DurableStepContext<'_> {
    /// The step clock in Unix SECONDS. Park rows store `parked_at` in seconds
    /// (`park_attempt_with_progress` multiplies it by 1_000 for `updated_at_ms`),
    /// so the millisecond `now_ms` must be divided down before it reaches
    /// `park_attempt` — otherwise `parked_at` lands ~1000x too large (#480-1).
    pub(super) const fn now_s(&self) -> u64 {
        self.now_ms / 1_000
    }
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
        /// Budget legibility (ONE-1305): Some inside wake passes (when
        /// [`DurableStepContext::deadline`] is set), None outside.
        legibility: Option<BudgetLegibilityEnvelope>,
    },
    Trapped(TrapRef),
}
