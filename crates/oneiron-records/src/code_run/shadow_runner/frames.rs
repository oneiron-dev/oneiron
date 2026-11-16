//! Moved from `crates/oneiron/src/code_run/shadow_runner/frames.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::shadow_values::ShadowUnavailable;
use crate::dreamer_runner::shadow_values::ShadowUsage;
use oneiron_model::llm::LlmResponse;
use serde::Deserialize;
use serde::Serialize;

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
