//! The frames an arm and its host speak (PR-S1 defines them; the candidate
//! process runner speaks them, PR-S2). Each frame carries the protocol
//! version and the arm it is of; a model call and its answer share a call
//! id. A body crosses as ordered chunks of its bytes, each at its offset,
//! closed by its end, and is checked against its whole digest and length.
//! A model call is the host's to admit, meter and send: the arm names the
//! whole request and the pins it must go out on, never a credential.

use serde::{Deserialize, Serialize};

use super::types::{
    ShadowMeterContext, ShadowModelPin, ShadowRunRequest, ShadowRunResult, ShadowUnavailable,
    ShadowUsage,
};
use crate::compaction::output::OutputRef;
use crate::{EntityId, LlmRequest, LlmResponse};

/// One frame of an arm's protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowFrame {
    pub protocol_version: u32,
    pub arm: EntityId,
    pub body: ShadowFrameBody,
}

impl ShadowFrame {
    /// `body`, as a frame of `arm` at this protocol's version.
    #[must_use]
    pub const fn new(arm: EntityId, body: ShadowFrameBody) -> Self {
        Self {
            protocol_version: super::SHADOW_PROTOCOL_VERSION,
            arm,
            body,
        }
    }
}

/// What one frame says.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum ShadowFrameBody {
    /// The host starts the arm.
    Start(Box<ShadowRunRequest>),
    /// The arm asks the host for one model call: the whole request, the
    /// pins it must go out on, and what it is metered under.
    ModelCall {
        call_id: u32,
        request: Box<LlmRequest>,
        pin: Box<ShadowModelPin>,
        meter: ShadowMeterContext,
    },
    /// The host's answer to one model call, with its receipts.
    ModelAnswer {
        call_id: u32,
        answer: ShadowModelAnswer,
        receipt: ShadowReceiptFrame,
    },
    /// Bytes of one body from `offset`, in order.
    BodyChunk {
        body: OutputRef,
        offset: u64,
        bytes: Vec<u8>,
    },
    /// The end of one body: its chunks are checked against its digest and
    /// length.
    BodyEnd { body: OutputRef },
    /// The arm's result.
    Result(Box<ShadowRunResult>),
    /// The host cancels the arm.
    Cancel,
}

/// A model call's answer: the model's response, or why there is none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowModelAnswer {
    Answered(Box<LlmResponse>),
    Unavailable(ShadowUnavailable),
}

/// One model call's receipts, as a frame carries them: the run admission's
/// receipt rows as they serialize (they are written, never read back), with
/// the call's typed identity and what it used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowReceiptFrame {
    pub call_id: u32,
    pub receipts: Vec<serde_json::Value>,
    pub usage: ShadowUsage,
}
