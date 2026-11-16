//! Moved from `crates/oneiron/src/memory/session_reads.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HydrateRequest {
    pub refs: Vec<String>,
    /// The caller's retrieval filter: it only narrows what the refs read.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityRequest {
    pub entity_ref: String,
    /// The caller's retrieval filter: it only narrows what the ref reads.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryBm25Request {
    pub query: String,
    pub limit: usize,
    /// The caller's retrieval filter, applied inside the posting scan,
    /// before the rank and the cut.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateNoteRequest {
    pub kind: String,
    pub markdown: String,
}
