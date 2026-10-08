//! Vault-read request shapes and the view / count-mode knobs they carry.
//! `oneiron::code_run::vault_read` re-exports them next to the response shapes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Accepted default page limit, copied from the accepted route's
/// `default_limit()`.
///
/// Public because `oneiron`'s vault-read tests build requests with it.
pub const fn default_limit() -> usize {
    10
}

/// Read projection requested by the accepted routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum View {
    /// Compact projection used by list/search results.
    Summary,
    /// Identity-only projection; the v1 rule omits the body.
    Standard,
    /// Full projection including the decoded body.
    Full,
}

/// Count precision requested by callers and reported in response metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CountMode {
    /// Skip count work and report `total = 0`.
    None,
    /// Report a non-exact search estimate.
    Estimate,
    /// Requested exact count; search responses collapse it to `Estimate`.
    Exact,
}

impl CountMode {
    /// The serde default for `count_mode`. Public because `oneiron`'s vault-read tests
    /// build requests with it.
    pub const fn default_estimate() -> Self {
        Self::Estimate
    }

    /// Accepted collapse: search responses never report exact counts.
    #[must_use]
    pub const fn for_search_response(self) -> Self {
        match self {
            Self::None => Self::None,
            Self::Estimate | Self::Exact => Self::Estimate,
        }
    }
}

/// Accepted `POST /v1/core/query` request body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreQueryRequest {
    /// Optional BM25 text query.
    #[serde(default)]
    pub query: Option<String>,
    /// Optional vector query.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    pub query_vector: Option<Vec<f32>>,
    /// Maximum result count.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Projection view. Defaults to `Summary`.
    #[serde(default)]
    pub view: Option<View>,
    /// Count precision. Defaults to `Estimate`.
    #[serde(
        default = "CountMode::default_estimate",
        rename = "countMode",
        alias = "count_mode"
    )]
    pub count_mode: CountMode,
}

/// Accepted `POST /v1/core/hydrate` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreHydrateRequest {
    /// Canonical short reference in `shortId:contentHashHex` form.
    #[serde(default, rename = "ref", alias = "short_ref", alias = "shortRef")]
    pub reference: Option<String>,
    /// Short id without the content hash.
    #[serde(default, rename = "short_id", alias = "shortId")]
    pub short_id: Option<String>,
    /// Two-hex-digit content hash.
    #[serde(default, rename = "content_hash", alias = "contentHash")]
    pub content_hash: Option<String>,
    /// Projection view for live entities. Defaults to `Full`.
    #[serde(default)]
    pub view: Option<View>,
}

/// Accepted `POST /v1/core/batch/shortId/hydrate` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreBatchShortIdHydrateRequest {
    /// Canonical short references in `shortId:contentHashHex` form.
    #[serde(
        default,
        rename = "refs",
        alias = "short_refs",
        alias = "shortRefs",
        alias = "short_ids",
        alias = "shortIds"
    )]
    pub refs: Vec<String>,
    /// Projection view for live entities. Defaults to `Full`.
    #[serde(default)]
    pub view: Option<View>,
}

/// Canonical transport body for the accepted
/// `GET /v1/core/memory/{id}/timeline` route.
///
/// An HTTP `WireTransport` places `id` in the route path and `view` in the
/// query while still carrying this canonical JSON body at the `round_trip`
/// seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreMemoryTimelineRequest {
    /// Hex entity id whose supersession chain is requested.
    pub id: String,
    /// Accepted for wire fidelity. Deliberately ignored in v1: the engine
    /// timeline record carries no `item` projection to view.
    #[serde(default)]
    pub view: Option<View>,
}

/// M8-reserved ask request payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct AskRequest(pub Value);

/// M8-reserved code-search request payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct CodeSearchRequest(pub Value);

/// M8-reserved code-execute request payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct CodeExecuteRequest(pub Value);
