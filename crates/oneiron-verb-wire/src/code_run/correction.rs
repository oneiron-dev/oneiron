//! Moved from `crates/oneiron/src/code_run/correction.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_model::llm::ModelId;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// What ONE-1929 had to remove from one model reply to reach a bare program.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutorWireRepairs {
    /// Outer transport whitespace was trimmed from the program candidate.
    pub trimmed_transport_whitespace: bool,
    /// One whole markdown fence was stripped.
    pub stripped_code_fence: bool,
    /// One whole `<exec>` wrapper was stripped.
    pub stripped_exec_wrapper: bool,
    /// Console blocks the model wrote, deleted and never kept as output.
    pub discarded_console_blocks: u32,
}

impl ExecutorWireRepairs {
    /// Whether this turn needed ANY healing. One healed turn counts once, no
    /// matter how many of these repairs it took.
    #[must_use]
    pub const fn healed(self) -> bool {
        self.trimmed_transport_whitespace
            || self.stripped_code_fence
            || self.stripped_exec_wrapper
            || self.discarded_console_blocks != 0
    }
}

/// How the executor repairs one model response (FIX 4413).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunCorrectionPolicy {
    /// Normalization passes the executor runs over one model response.
    pub normalization_passes: u32,
    /// Times the executor asks the model again on its own after it rejects
    /// a response.
    pub model_repair_retries: u32,
}

impl CodeRunCorrectionPolicy {
    /// Whether an attempt that ended in `outcome` after `retries_used`
    /// automatic model-repair retries has no retry left. Only a rejected
    /// response exhausts its attempt.
    #[must_use]
    pub fn exhausted(self, outcome: &CodeRunCorrectionOutcome, retries_used: u32) -> bool {
        matches!(outcome, CodeRunCorrectionOutcome::Rejected { .. })
            && retries_used >= self.model_repair_retries
    }
}

/// What the normalization did with one model response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeRunCorrectionOutcome {
    /// The response was a bare program already: no repair was made.
    Clean,
    /// The response became a bare program after one or more repairs.
    Normalized,
    /// The normalization refused the response: no program ran and the step
    /// committed nothing.
    Rejected {
        /// The executor's stable text for the refusal, never the response's
        /// own words.
        reason: String,
    },
}
