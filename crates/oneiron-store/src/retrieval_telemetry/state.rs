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

impl RetrievalReplayInputs {
    /// Known string and array backing of the config, including object keys.
    ///
    /// Excludes object-map storage, number internals and the two reference fields.
    pub fn known_config_backing_bytes(&self) -> u64 {
        replay_config_bytes(&self.config)
    }
}

// Object map storage and number internals are not measured here.
fn replay_config_bytes(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::String(value) => value.capacity() as u64,
        serde_json::Value::Array(values) => values.iter().fold(
            (values.capacity() as u64)
                .saturating_mul(std::mem::size_of::<serde_json::Value>() as u64),
            |bytes, value| bytes.saturating_add(replay_config_bytes(value)),
        ),
        serde_json::Value::Object(values) => values.iter().fold(0_u64, |bytes, (key, value)| {
            bytes
                .saturating_add(key.capacity() as u64)
                .saturating_add(replay_config_bytes(value))
        }),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => 0,
    }
}
