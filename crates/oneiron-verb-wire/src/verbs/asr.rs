//! Moved from `crates/oneiron/src/verbs/asr.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AsrOpenRequest {
    pub utterance_id: String,
    #[serde(default)]
    pub scope: crate::memory::recall::RecallScope,
    #[serde(default)]
    pub fire_limit: Option<usize>,
    #[serde(default)]
    pub final_limit: Option<usize>,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AsrSession {
    pub handle: String,
    pub utterance_id: String,
    pub scope: crate::memory::recall::RecallScope,
    pub max_fires: u8,
    pub fire_limit: usize,
    pub final_limit: usize,
    pub limit_clamped: bool,
    pub deadline_ms: u64,
    pub narrowing: oneiron_contracts::claim::ScopedReadReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AsrFireDecision {
    Fired,
    MissedDeadline,
    SkippedUnchanged,
    SkippedEmptySignature,
    SkippedCapExhausted,
}

/// A completed observation boundary. Only `fired` exports prepared candidates;
/// missed deadlines count against the real engine budget but keep no new pack.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AsrHypothesisReceipt {
    pub receipt_ref: String,
    pub handle: String,
    pub utterance_id: String,
    pub revision: u64,
    pub text: String,
    pub scope: crate::memory::recall::RecallScope,
    pub decision: AsrFireDecision,
    pub fires_used: u8,
    pub run_id: Option<String>,
    pub partial: bool,
    pub result_refs: Vec<String>,
    pub narrowing: oneiron_contracts::claim::ScopedReadReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AsrFinalDecision {
    Promoted,
    Finalized,
}

/// `promoted` names the exact fire receipt reused, with no new full recall.
/// A finalized pass may warm-fill a shortfall; its scores are not compared
/// across the fresh/warm boundary. Run ids are absent when telemetry is off.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AsrFinalReceipt {
    pub receipt_ref: String,
    pub handle: String,
    pub utterance_id: String,
    pub revision: u64,
    pub text: String,
    pub scope: crate::memory::recall::RecallScope,
    pub decision: AsrFinalDecision,
    pub reused_fire_receipt: Option<String>,
    pub fires_used: u8,
    pub run_id: Option<String>,
    pub warm_appended: usize,
    pub partial: bool,
    pub result_refs: Vec<String>,
    pub narrowing: oneiron_contracts::claim::ScopedReadReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AsrCloseRequest {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AsrClosed {
    pub handle: String,
}
