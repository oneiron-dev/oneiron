//! Durable model-step claim vocabulary and progression values.

use crate::side_table::codec::{CodecError, RawValue};
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::{LlmResponse, ModelId};
use serde::{Deserialize, Serialize};

/// Claim predicate for terminal durable-step records (design D13).
pub const DREAMER_STEP_PREDICATE: &str = "dreamer.step";

/// Claim predicate for the unified Budget/Consent trap record (design D4).
pub const DREAMER_TRAP_PREDICATE: &str = "dreamer.trap";

/// Current pinned `dreamer.step` claim value schema version.
pub const DREAMER_STEP_VALUE_SCHEMA_VERSION: u64 = 1;

/// Pinned MessagePack key set for `dreamer.step` claim values.
pub const DREAMER_STEP_VALUE_KEYS: [&str; 14] = [
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
    "response_version",
    "response_hash",
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

/// Retry backoff schedule for [`oneiron_model::llm::LlmError::Retryable`] failures — the ONE
/// retry authority (ruling L6). One retry per entry, all under the SAME
/// lease; absolute settlement makes retries free of double-count.
pub const DREAMER_STEP_RETRY_BACKOFF_MS: [u64; 3] = [250, 1_000, 4_000];

/// Live progression of one durable step, stored as `u8` in the private
/// device-local state row (ruling L6): `Started → ResponseReceived →
/// Logged → Finished`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
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

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Started => 0,
            Self::ResponseReceived => 1,
            Self::Logged => 2,
            Self::Finished => 3,
        }
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
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

    pub fn parse(value: &str) -> Option<Self> {
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

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(Self::Created),
            "waiting" => Some(Self::Waiting),
            "sent" => Some(Self::Sent),
            "consumed" => Some(Self::Consumed),
            _ => None,
        }
    }

    pub const fn may_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Waiting)
                | (Self::Created, Self::Sent)
                | (Self::Waiting, Self::Sent)
                | (Self::Sent, Self::Consumed)
        )
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

pub const MODEL_STEP_ATTEMPT_KIND: &str = "model-step";

/// Payload-free projection of the existing live checkpoint or terminal step claim.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStepCheckpoint {
    pub progression: StepProgression,
    /// The live row is retired at completion; its timestamp is then absent.
    pub updated_ms: Option<u64>,
    pub claim_ref: Option<String>,
}

/// One step of one attempt, by the attempt's job ref and the step's
/// canonical request hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettledStepRequest {
    /// 32-hex attempt id (`job:` prefix allowed), as the consolidation
    /// status read names it.
    pub job_ref: String,
    /// 64-hex canonical request hash of the step.
    pub step_hash: String,
}

/// A committed model step: the completion claim, the identity it was
/// recorded for, and the stored response it settled with.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettledStepView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// The run correlation id the completion claim's write envelope
    /// recorded at the step's commit; absent when the attempt had none.
    pub run_id: Option<String>,
    /// 32-hex id of the terminal `dreamer.step` claim.
    pub claim_ref: String,
    /// 64-hex canonical request hash.
    pub step_hash: String,
    /// The fully revisioned model the step was recorded for.
    pub model: ModelId,
    /// The call purpose the step was recorded for.
    pub purpose: String,
    /// BLAKE3 of the request's canonical params JSON, lowercase hex.
    pub params_hash: String,
    /// The stored response: inline, or the exact artifact version the
    /// step appended, checked against its pin.
    pub response: LlmResponse,
}

/// One settled step as a caller's own lane reads it (DOOR-141 PR3a).
pub enum CallerSettledStep {
    /// The terminal claim, and the response artifact it pins, read on the
    /// caller's lane: the step as stored.
    Readable(Box<SettledStepView>),
    /// The terminal claim stands; it, or the artifact it pins, does not read
    /// on the caller's lane.
    Withheld { claim: EntityId },
}

/// A bound trap as its row spells it: anchor id, step hash, then the kind's
/// stable name.
impl RawValue for TrapRef {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(16 + 32 + 16);
        out.extend_from_slice(self.trap_claim_id.as_bytes());
        out.extend_from_slice(&self.step_hash);
        out.extend_from_slice(self.kind.as_str().as_bytes());
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let undecodable = || CodecError::from(Error::CorruptedIndex("code-run wait trap"));
        let (id, rest) = bytes.split_at_checked(16).ok_or_else(undecodable)?;
        let (hash, kind) = rest.split_at_checked(32).ok_or_else(undecodable)?;
        Ok(Self {
            trap_claim_id: id
                .try_into()
                .ok()
                .and_then(|raw| EntityId::from_bytes(raw).ok())
                .ok_or_else(undecodable)?,
            kind: std::str::from_utf8(kind)
                .ok()
                .and_then(DreamerTrapKind::parse)
                .ok_or_else(undecodable)?,
            step_hash: hash.try_into().map_err(|_| undecodable())?,
        })
    }
}
