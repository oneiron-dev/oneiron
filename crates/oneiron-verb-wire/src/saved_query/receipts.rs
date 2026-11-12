//! Moved from `crates/oneiron/src/saved_query/receipts.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_model::llm::LlmUsage;
use oneiron_store::model_decision::ProviderPin;
use oneiron_store::query_memos::VerdictMemoRow;
use serde::Deserialize;
use serde::Serialize;

/// One completed generation, identified by the exact request it measured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryGenerationReceipt {
    /// BLAKE3 of the generation request.
    pub request_hash: String,
    /// Provider-reported usage, including the host's served-provider stamp.
    pub usage: LlmUsage,
}

/// A newly measured membership judgment. A memo hit carries none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryJudgeReceipt {
    /// The providers the decision ladder actually reached, with model revisions.
    pub providers: Vec<ProviderPin>,
    /// Provider-reported cost per thousand at the answered rung, when known.
    /// This is not an estimate of the whole call's cost.
    pub cost_per_thousand: Option<f64>,
    /// Requests generated on the query's backend, including the separate why.
    /// Stronger synchronous ladder rungs are named by `providers`, not invented
    /// as generation usage rows here.
    pub generations: Vec<SavedQueryGenerationReceipt>,
}
