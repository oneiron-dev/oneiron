//! Query-free retrieval context, preserved verbatim for offline replay.

use oneiron_contracts::retrieval_telemetry::RetrievalSignal;
use serde::{Deserialize, Serialize};

/// A caller's turn identity. Each run remains independent; grouping is a read
/// projection, never a collapsing write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalTurn {
    pub turn_id: [u8; 16],
    pub episode_id: [u8; 16],
    pub turn_idx: u64,
}

/// Query-free opt-in replay context. A host can point at its authorized, immutable
/// query packet (or session message) and corpus snapshot. Neither raw query
/// content nor a query hash is written to telemetry. An absent reference means
/// this row alone cannot reconstruct that part of the request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalReplayInputs {
    pub query_ref: Option<String>,
    pub config: serde_json::Value,
    pub corpus_snapshot_ref: Option<String>,
}
