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

/// What a chat call's request was assembled from, taken where the request is
/// assembled (FIX HANDOFF-CONTEXT): ids and counts only, never words. A call
/// whose capture names none reads as unknown, as every non-chat capture and
/// every call recorded before the form existed does. A request digest never
/// picks a form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "form", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelCallContext {
    /// A chat turn: its earlier lines and its context board.
    Turn {
        history: ModelCallHistory,
        board: ModelCallBoard,
    },
    /// A turn action answering a saved turn again, its history rebuilt
    /// from the conversation's ledger.
    TurnAction { action: ModelCallTurnAction },
}

/// The earlier lines a chat turn's request carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelCallHistory {
    /// No earlier line: the thread's first turn.
    Cold,
    /// The answering agent's own retained log: the compaction summaries
    /// standing in it, then the raw turns after them, oldest first.
    RetainedLog {
        summaries: Vec<EntityId>,
        raw_turns: Vec<EntityId>,
    },
    /// The caller's own lines: the latest `kept` rode; the `dropped` lines
    /// before them were past the turn's history bound.
    CallerLines { kept: u64, dropped: u64 },
}

/// Whether a chat turn's context board rode its call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCallBoard {
    Rode,
    /// Read, then left out: refused, held by its route, or not admitted.
    Omitted,
    /// No board for the turn.
    Absent,
}

/// The turn action a call answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCallTurnAction {
    Continue,
    Retry,
}

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
