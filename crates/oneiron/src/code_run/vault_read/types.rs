//! Query, hydrate, timeline and runtime-deferred request/response shapes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::deletion::{HydratedShortIdDeletion, MemoryTimelineRecordState};

/// Maximum refs accepted by one batch short-id hydrate call. Copied from the
/// accepted route's `CORE_MAX_BATCH_ENTITIES`.
pub const VAULT_READ_MAX_BATCH_REFS: usize = 256;

/// Accepted default page limit, copied from the accepted route's
/// `default_limit()`.
pub(super) const fn default_limit() -> usize {
    10
}

/// Read projection requested by the accepted routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    pub(super) const fn default_estimate() -> Self {
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

/// Accepted over-fetch recipe. `Exact` is collapsed before this call.
pub(super) const fn search_fetch_limit(count_mode: CountMode, page_limit: usize) -> usize {
    match count_mode {
        CountMode::None => page_limit,
        CountMode::Estimate => page_limit.saturating_add(1),
        CountMode::Exact => {
            panic!("count mode collapses to none/estimate before fetch-limit resolution")
        }
    }
}

/// Accepted `search_meta` total: `None` reports zero, `Estimate` reports the
/// admitted over-fetch count.
pub(super) const fn search_total(count_mode: CountMode, admitted: usize) -> u64 {
    match count_mode {
        CountMode::None => 0,
        CountMode::Estimate => admitted as u64,
        CountMode::Exact => panic!("count mode collapses to none/estimate before meta resolution"),
    }
}

/// Entity record constructible from `ScopedRead::get_entity_parts`.
///
/// `body` is the one view-controlled field in v1: `Standard` omits it, while
/// `Summary` and `Full` carry the public MessagePack → JSON projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreEntityRecord {
    /// Full `EntityId` as lowercase hex.
    pub id: String,
    /// Numeric entity type byte.
    pub entity_type: u8,
    /// Entity learned-at timestamp in Unix seconds.
    pub learned_at: u64,
    /// Retrieval score, when the record came from a ranked read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// Decoded entity body, when the view includes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

/// Accepted `POST /v1/core/query` request body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Count metadata reported by [`CoreQueryResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreQueryMeta {
    /// Reported total under the collapsed count mode.
    pub total: u64,
    /// Collapsed count mode actually applied.
    #[serde(rename = "countMode")]
    pub count_mode: CountMode,
}

/// Query response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreQueryResponse {
    /// Projected page of admitted entities.
    pub items: Vec<CoreEntityRecord>,
    /// Reserved cursor field; this contract version never paginates.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Count metadata.
    pub meta: CoreQueryMeta,
}

/// Accepted `POST /v1/core/hydrate` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Hydrate outcome for a resolved short ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreHydrateStatus {
    /// Resolved to a live entity payload.
    Live,
    /// Resolved to a deleted shell or dangling short-id row.
    Deleted,
}

/// Hydrate response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreHydrateResponse {
    /// Hydrate state for the resolved short ref.
    pub status: CoreHydrateStatus,
    /// Requested short id without content hash.
    #[serde(rename = "short_id")]
    pub short_id: String,
    /// Requested content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    pub content_hash: String,
    /// Hex entity id the short ref resolved to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Numeric entity type byte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<u8>,
    /// Deletion metadata for deleted shells and dangling rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion: Option<HydratedShortIdDeletion>,
    /// Projected entity record for live entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<CoreEntityRecord>,
}

/// Accepted `POST /v1/core/batch/shortId/hydrate` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Per-item batch hydrate outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreShortIdHydrateOutcome {
    /// Resolved to a live entity.
    Live,
    /// Resolved to a deleted shell or dangling row.
    Deleted,
    /// The caller's ref did not parse.
    MalformedShortId,
    /// The accepted route answered absence.
    NotFound,
}

/// One batch hydrate item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreBatchShortIdHydrateItem {
    /// Caller-echoed input ref.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Outcome for this ref.
    pub outcome: CoreShortIdHydrateOutcome,
    /// Hydrate result for `Live`/`Deleted` outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<CoreHydrateResponse>,
}

/// Batch hydrate response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreBatchShortIdHydrateResponse {
    /// Per-input results, in caller order.
    pub results: Vec<CoreBatchShortIdHydrateItem>,
}

/// Canonical transport body for the accepted
/// `GET /v1/core/memory/{id}/timeline` route.
///
/// An HTTP `WireTransport` places `id` in the route path and `view` in the
/// query while still carrying this canonical JSON body at the `round_trip`
/// seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMemoryTimelineRequest {
    /// Hex entity id whose supersession chain is requested.
    pub id: String,
    /// Accepted for wire fidelity. Deliberately ignored in v1: the engine
    /// timeline record carries no `item` projection to view.
    #[serde(default)]
    pub view: Option<View>,
}

/// One projected timeline record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMemoryTimelineRecord {
    /// Hex entity id of this record.
    pub id: String,
    /// Renderer-facing lifecycle state.
    pub state: MemoryTimelineRecordState,
    /// Numeric entity type byte, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<u8>,
    /// Occurrence start timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_start: Option<u64>,
    /// Occurrence end timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_end: Option<u64>,
    /// Learned-at timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub learned_at: Option<u64>,
    /// Stored body size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_bytes: Option<usize>,
    /// Deletion metadata for deletion shells.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion: Option<HydratedShortIdDeletion>,
    /// Hex ids this record supersedes, already clamped.
    pub supersedes: Vec<String>,
    /// Hex ids that supersede this record, already clamped.
    pub superseded_by: Vec<String>,
}

/// Timeline response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMemoryTimelineResponse {
    /// Hex anchor entity id.
    #[serde(rename = "anchor_id")]
    pub anchor_id: String,
    /// Ordered timeline records.
    pub records: Vec<CoreMemoryTimelineRecord>,
}

/// M8-reserved ask request payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AskRequest(pub Value);

/// M8-reserved ask response payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AskResponse(pub Value);

/// M8-reserved code-search request payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeSearchRequest(pub Value);

/// M8-reserved code-search response payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeSearchResponse(pub Value);

/// M8-reserved code-execute request payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeExecuteRequest(pub Value);

/// M8-reserved code-execute response payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeExecuteResponse(pub Value);
