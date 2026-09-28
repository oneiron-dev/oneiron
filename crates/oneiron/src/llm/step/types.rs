//! Shared durable-step type layer: schema consts, error, progression/trap enums, step context, and outcome.

use super::super::{LlmError, LlmRequest, LlmResponse};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_wake::{BudgetLegibilityEnvelope, WakePassDeadline};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::side_table::{FixedSideKey, SideKey};
use crate::write_envelope::WriteActor;

/// `AttemptId` is a foreign (same-crate) type; every step-family side table keys on it, so the
/// `SideKey` binding lives once here rather than once per table module.
impl SideKey for AttemptId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes).ok()
    }
}

impl FixedSideKey for AttemptId {
    const WIDTH: usize = 16;
}

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

/// Exact durable-step identity frozen beside an outbound payload. This is a
/// correlation key, never a caller-authored permission bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StepEffectBinding {
    pub(crate) attempt_id: AttemptId,
    pub(crate) step_hash: [u8; 32],
}

impl StepEffectBinding {
    pub(crate) fn for_request(
        attempt_id: AttemptId,
        request: &LlmRequest,
    ) -> DurableStepResult<Self> {
        Ok(Self {
            attempt_id,
            step_hash: request.canonical_hash()?,
        })
    }

    pub(crate) fn frozen_value(self) -> serde_json::Value {
        serde_json::json!({
            "attempt_id": crate::entity_id::bytes_to_hex_lower(self.attempt_id.as_bytes()),
            "step_hash": crate::entity_id::bytes_to_hex_lower(&self.step_hash),
        })
    }

    /// No key means an ordinary non-step effect. A present but malformed key
    /// refuses rather than dropping the step restriction.
    pub(crate) fn from_frozen_payload(payload: &[u8]) -> Result<Option<Self>, Error> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
            return Ok(None);
        };
        let Some(value) = value.get("dreamer_step") else {
            return Ok(None);
        };
        let invalid = || Error::InvalidClaimBody("invalid frozen dreamer step binding");
        let object = value.as_object().ok_or_else(invalid)?;
        if object.len() != 2 {
            return Err(invalid());
        }
        let attempt_hex = object
            .get("attempt_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        let hash_hex = object
            .get("step_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        if attempt_hex.len() != 32 || hash_hex.len() != 64 {
            return Err(invalid());
        }
        let attempt_ref = EntityId::from_hex(attempt_hex).map_err(|_| invalid())?;
        let attempt_id = AttemptId::from_bytes(attempt_ref.as_bytes()).map_err(|_| invalid())?;
        let hash = blake3::Hash::from_hex(hash_hex).map_err(|_| invalid())?;
        if crate::entity_id::bytes_to_hex_lower(attempt_id.as_bytes()) != attempt_hex
            || crate::entity_id::bytes_to_hex_lower(hash.as_bytes()) != hash_hex
        {
            return Err(invalid());
        }
        Ok(Some(Self {
            attempt_id,
            step_hash: *hash.as_bytes(),
        }))
    }
}

pub type DurableStepResult<T> = std::result::Result<T, DurableStepError>;

/// Typed failure surface of the durable-step layer.
#[derive(Debug, thiserror::Error)]
pub enum DurableStepError {
    #[error("LLM failure after spent corrective attempts: {source}")]
    SpentLlm {
        source: LlmError,
        usage: Box<super::super::LlmUsage>,
    },
    #[error("JSON schema validation failed after {attempts} attempts: {errors:?}")]
    SchemaValidation { attempts: u8, errors: Vec<String> },
    /// Terminal provider response(s) failed schema validation after real spend.
    #[error("JSON schema validation failed after {attempts} spent attempts: {errors:?}")]
    SpentSchemaValidation {
        attempts: u8,
        errors: Vec<String>,
        usage: Box<super::super::LlmUsage>,
    },
    /// A fresh correction was refused after prior provider responses spent units.
    #[error("durable step correction refused at wake-pass deadline after spent usage")]
    SpentFinalizeRefused { usage: Box<super::super::LlmUsage> },
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Llm(#[from] LlmError),
    /// The step's sole retry authority has exhausted or refused this call.
    /// The decision records the resident rule without granting a new route.
    #[error("classified LLM failure: {source}")]
    ClassifiedLlm {
        #[source]
        source: LlmError,
        failure_policy: super::super::DreamerFailureDecision,
    },
    #[error("durable step canonicalization failed: {0}")]
    Canonical(#[from] serde_json::Error),
    #[error(transparent)]
    Fallback(#[from] super::super::FallbackError),
    /// NEW steps are refused once the wake pass enters its graceful-wrap
    /// finalize window (ONE-1305); memoized hits still return.
    #[error("durable step refused: wake pass is in its finalize window")]
    FinalizeRefused,
    /// Hard-cut signal still handled by attempt executors. An admitted LLM
    /// call no longer emits it when the wake-pass deadline expires.
    #[error("durable step hard cut at the wake-pass deadline")]
    DeadlineHardCut,
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
    /// The wake-pass deadline (ONE-1305): Some inside wake passes. Enables
    /// the finalize-window refusal for NEW steps and the budget legibility
    /// envelope on finished outcomes. Admitted calls may finish after expiry.
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

/// Terminal outcome of [`call_as_step`](crate::llm::call_as_step).
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    Finished {
        response: LlmResponse,
        memoized: bool,
        /// Budget legibility (ONE-1305): Some inside wake passes (when
        /// [`DurableStepContext::deadline`] is set), None outside.
        legibility: Option<BudgetLegibilityEnvelope>,
        /// Restrictive policy for a deterministic failure result; never an authority grant.
        failure_policy: Option<super::super::DreamerFailureDecision>,
    },
    Trapped {
        trap: TrapRef,
        /// Budget-denial policy, resolved before parking this attempt.
        failure_policy: super::super::DreamerFailureDecision,
    },
}
