//! Moved from `crates/oneiron/src/memory/signal_extraction.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Extract from these witnessed TURNs using the host's configured extraction
/// role/model and the existing inference, selection and promotion gates.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignalExtractionRequest {
    pub turn_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignalExtractionTicket {
    /// One durable attempt per admitted conversation/world/facet partition.
    /// Empty when the production prefilter kept no turns.
    pub job_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignalExtractionResultRequest {
    pub job_ref: String,
}

/// A parent-verified citation, not a model-declared source or content hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignalExtractionSource {
    pub source_ref: String,
    pub claim_ref: Option<String>,
    pub byte_range: Option<(usize, usize)>,
    pub content_hash: String,
    pub messages: Vec<SignalExtractionMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SignalExtractionMessage {
    pub message_ref: String,
    pub byte_range: (usize, usize),
    /// Exact source MESSAGE revision checked by the parent.
    pub revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProspectiveQueryHint {
    pub hint_ref: String,
    pub target_ref: String,
    pub query: String,
    pub source: String,
}
