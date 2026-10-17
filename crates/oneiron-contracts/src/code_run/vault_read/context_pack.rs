//! The vault-read context-pack request and its depth / budget controls.
//! `oneiron::code_run::vault_read` re-exports them next to the response records.

use serde::{Deserialize, Serialize};

use super::types::default_limit;

/// Engine-executable context-pack subset of the accepted route.
///
/// The daemon-only session, companion, disclosure, policy, time, and projection
/// controls are outside this engine contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreContextPackRequest {
    /// Executor model@revision for pair-specific skill reliability ranking.
    #[serde(default)]
    pub executor_model: Option<String>,
    /// Optional BM25 text seed.
    #[serde(default)]
    pub query: Option<String>,
    /// Optional vector seed.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    pub query_vector: Option<Vec<f32>>,
    /// Optional media seed (OF-370): bytes the host embeds into one declared
    /// space and searches as one more ranked list beside `query` and
    /// `query_vector`. It seeds a pack on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<ContextPackMediaQuery>,
    /// Maximum primary candidates to retrieve.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Nested depth controls; populated fields win over their top-level twins.
    #[serde(default)]
    pub depth: Option<ContextPackDepthControls>,
    /// Top-level edge expansion depth (compatibility twin).
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    pub edge_hop: Option<u32>,
    /// Top-level neighbor cap (compatibility twin).
    #[serde(default, rename = "max_neighbors", alias = "maxNeighbors")]
    pub max_neighbors: Option<usize>,
    /// Retrieval and serialization budget controls.
    #[serde(default)]
    pub budget: Option<ContextPackBudgetControls>,
}

impl CoreContextPackRequest {
    /// Accepted-route resolution: a populated nested `depth` field wins over
    /// its top-level compatibility twin; an absent nested field falls back.
    #[must_use]
    pub fn resolved_depth(&self) -> ContextPackDepthControls {
        ContextPackDepthControls {
            edge_hop: self
                .depth
                .as_ref()
                .and_then(|d| d.edge_hop)
                .or(self.edge_hop),
            max_neighbors: self
                .depth
                .as_ref()
                .and_then(|d| d.max_neighbors)
                .or(self.max_neighbors),
        }
    }
}

/// A retrieval request's media query (OF-370), the wire shape of the
/// server's `POST /v1/core/context-pack` `media`: bytes its host embeds into
/// one declared space through the `ai.embed` rung that space's id names.
/// The engine never embeds them itself: a host with no media runtime refuses
/// the request rather than read it without them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextPackMediaQuery {
    /// Declared embedding space id: an `ai.embed` rung id from
    /// `GET /v1/ai/options`, then `@where`.
    pub space: String,
    /// Media type of the bytes; it picks the space's query tower: `image/*`,
    /// `audio/*`, or `text/*` (UTF-8).
    pub mime: String,
    /// The bytes, standard base64, at most `[limits].retrieval_query_bytes`
    /// as sent.
    #[serde(alias = "bytesB64")]
    pub bytes_b64: String,
    /// The kinds of item the space's list keeps; every kind the space holds
    /// when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<MediaQueryKind>,
}

/// One kind of item a media query's list keeps: the input kinds a declared
/// space holds, spelled as the engine's `InputKind` spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MediaQueryKind {
    Text,
    Image,
    Audio,
}

/// Nested edge-expansion depth controls.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextPackDepthControls {
    /// Edge expansion depth for neighbor hydration.
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    pub edge_hop: Option<u32>,
    /// Maximum neighbors to hydrate during edge expansion.
    #[serde(default, rename = "max_neighbors", alias = "maxNeighbors")]
    pub max_neighbors: Option<usize>,
}

/// Per-kind retrieval item budgets applied before final truncation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextPackRetrievalBudgetControls {
    /// CLAIM item budget.
    #[serde(default)]
    pub claims: Option<usize>,
    /// TURN item budget.
    #[serde(default)]
    pub turns: Option<usize>,
    /// SUMMARY item budget.
    #[serde(default)]
    pub summaries: Option<usize>,
    /// FACET item budget.
    #[serde(default)]
    pub facets: Option<usize>,
    /// Remaining-kind item budget.
    #[serde(default)]
    pub other: Option<usize>,
    /// Edge-walk neighbor selection cap.
    #[serde(default, rename = "selected_edges", alias = "selectedEdges")]
    pub selected_edges: Option<usize>,
}

/// Token and item budget controls.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextPackBudgetControls {
    /// Serialized token budget.
    #[serde(default, rename = "token_budget", alias = "tokenBudget")]
    pub token_budget: Option<usize>,
    /// Per-item token cap; `0` disables it.
    #[serde(default, rename = "max_item_tokens", alias = "maxItemTokens")]
    pub max_item_tokens: Option<usize>,
    /// Maximum field characters before truncation.
    #[serde(default, rename = "max_field_chars", alias = "maxFieldChars")]
    pub max_field_chars: Option<usize>,
    /// Per-kind retrieval item budgets.
    #[serde(default)]
    pub retrieval: Option<ContextPackRetrievalBudgetControls>,
}
