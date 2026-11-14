//! Moved from `crates/oneiron/src/memory/recall/paid.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What the rerank stage of a recall at high, xhigh or max did. Absent below
/// high.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RerankReport {
    /// The host's reranker scored the top block, or the prefix of it a call
    /// that stopped short scored, and the block is in its order, the
    /// unscored rest below in fusion order (FIX 11772).
    Applied {
        /// The model the host routed the call to.
        model: String,
        /// The model the endpoint said answered, when it said.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        served_model: Option<String>,
        /// Candidates scored.
        candidates: usize,
        /// Scoring calls made: two when the block changed during the first.
        calls: u32,
    },
    /// The block is in the engine's own order.
    Skipped { reason: RerankSkip },
}

/// Why a paid recall did not rerank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RerankSkip {
    /// The server serves no reranker.
    NoReranker,
    /// Retrieval found nothing to rerank.
    NoCandidates,
    /// The deadline came before the rerank stage.
    Deadline,
    /// A row sent with words became one a device-only world keeps while the
    /// reranker was called, so nothing more was sent ([`RerankEgress`]). Only
    /// a caller on this device reads this reason; one off it reads the skip
    /// of a pack with nothing to rerank.
    DeviceOnly,
}
