//! Moved from `crates/oneiron/src/code_run/model_call.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::compaction::output::OutputRef;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

pub const MODEL_CALL_SCHEMA: u8 = 2;

/// Where a model output part is owned. A code-run output and a witnessed
/// MESSAGE are distinct stores; neither reference is synthesized from the other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelCallPartRef {
    Output { occurrence: OutputRef },
    Message { message: EntityId, part_index: u64 },
    Custody { handle: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelCallInputPart {
    Reference {
        row: EntityId,
        occurrence: OutputRef,
    },
    NewBytes {
        body: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
    },
    Unknown {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallDigests {
    pub request_hash: [u8; 32],
    pub messages_digest: [u8; 32],
    pub system_digest: [u8; 32],
    pub tools_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReadDigests {
    pub request_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReadFailure {
    InvalidRequest,
    Auth,
    RateLimited,
    Timeout,
    ServerError,
    LabelRead(oneiron_model::llm::LabelReadFailure),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeReadOutcome {
    Completed {
        usage: oneiron_model::llm::LlmUsage,
    },
    Failed {
        failure: NativeReadFailure,
        usage: Option<oneiron_model::llm::LlmUsage>,
    },
}

/// The actual admission source of a native read, not a caller or payer guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReadRunSource {
    Probe,
    Caller,
    HouseGate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelCallKind {
    Generate {
        digests: ModelCallDigests,
        usage: oneiron_model::llm::LlmUsage,
        finish_reason: oneiron_model::llm::FinishReason,
    },
    LabelRead {
        run_source: NativeReadRunSource,
        digests: NativeReadDigests,
        revision: String,
        outcome: NativeReadOutcome,
    },
    SeatDecision {
        run_source: NativeReadRunSource,
        digests: NativeReadDigests,
        revision: String,
        outcome: NativeReadOutcome,
    },
}

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
