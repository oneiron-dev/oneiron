//! The OpenAPI mirror of the MEMORIES section a context board serves
//! (`oneiron::MemoriesSection`): what a client built from the served document
//! sees. Nothing here is built; each field names a served key.

use crate::api::context_pack::CoreDisclosureAssembly;
use serde::Serialize;
use utoipa::ToSchema;

/// Stable MEMORIES slot name.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextBoardMemorySlot {
    Claims,
    Turns,
    Summaries,
    Facets,
    Other,
}

/// Source of one MEMORIES row.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextBoardMemorySource {
    Result,
    Neighbor,
}

/// Per-slot row caps for a MEMORIES section.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesBudget {
    /// Claim row cap.
    #[schema(example = 2)]
    claims: usize,
    /// Turn/message row cap.
    #[schema(example = 4)]
    turns: usize,
    /// Summary row cap.
    #[schema(example = 1)]
    summaries: usize,
    /// Facet row cap.
    #[schema(example = 1)]
    facets: usize,
    /// Row cap for all other entity types.
    #[schema(example = 2)]
    other: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_total: Option<usize>,
}

/// Companion assembly metadata echoed with a MEMORIES section.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardCompanionAssembly {
    /// Effective caller/session identity used for the MEMORIES section.
    #[schema(example = "session-123")]
    caller: Option<String>,
    /// Effective companion scope: personal when both refs resolve to PERSON
    /// identities, otherwise neutral.
    #[schema(example = "personal")]
    scope: Option<String>,
    /// How the companion scope was resolved: `person_identity` when both refs
    /// are PERSON entities, otherwise `neutral_default`.
    #[serde(rename = "scope_source")]
    #[schema(example = "person_identity")]
    scope_source: Option<String>,
    /// Optional PERSON identity used for companion-aware assembly metadata.
    #[serde(rename = "person_ref")]
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: Option<String>,
    /// Optional PERSON at the relationship's other end, used for companion-aware assembly
    /// metadata.
    #[serde(rename = "counterpart_person_ref")]
    #[schema(example = "22222222222222222222222222222222")]
    counterpart_person_ref: Option<String>,
    /// Effective expression register boundary.
    #[schema(example = "warm")]
    expression: Option<String>,
}

/// One stable row in a MEMORIES section.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemoryRow {
    /// Zero-based index after stable sorting and slot-budget filtering.
    #[serde(rename = "row_index")]
    #[schema(example = 0)]
    row_index: usize,
    /// Budget slot that owns this row.
    slot: ContextBoardMemorySlot,
    /// Whether the row came from primary results or neighbors.
    source: ContextBoardMemorySource,
    /// Hex entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Short id used for compact display.
    #[serde(rename = "short_id")]
    #[schema(example = "tr_a1b2c3d4")]
    short_id: String,
    /// One-byte content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    #[schema(example = "a7")]
    content_hash: String,
    /// Numeric entity type byte.
    #[serde(rename = "entity_type")]
    #[schema(example = 1)]
    entity_type: u8,
    /// Short ref for ASSET and ASSET_TEXT rows. Consumers pass this to the core hydrate resolver.
    #[serde(rename = "asset_ref", skip_serializing_if = "Option::is_none")]
    #[schema(example = "tx123:a7")]
    asset_ref: Option<String>,
    /// Retrieval score.
    #[schema(example = 0.87)]
    score: f32,
    /// Canonical engine-issued source-trust label, never inferred from prose.
    claim_source: Option<String>,
    /// World partition; foreign ids render outside the first-party wrapper.
    world: Option<String>,
    /// True when the row's world cannot be proven; it renders under `MEMORIES world=unknown`.
    #[schema(example = false)]
    world_unproven: bool,
    /// pinned, snippet, or index_only.
    tier: String,
    /// Escaped only at rendering, absent for foreign index-only rows.
    snippet: Option<String>,
    /// `<pack>/<hook>` when a hook block pins this row; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "local/remind")]
    hook: Option<String>,
    /// The board room's pin record when the room pins this row (ROOM-SCOPED-PINS): who
    /// pinned it, the agent that acted for that PERSON and when; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    room_pin: Option<ContextBoardRoomPin>,
}

/// One shared pin of the board's room, on the MEMORIES row of its target.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardRoomPin {
    /// Hex entity id of the pinned record.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    target: String,
    /// Hex id of the PERSON who pinned it.
    pinned_by: String,
    /// Hex id of the agent that pinned it for that PERSON; null when the PERSON did.
    acting_agent: Option<String>,
    /// Engine time of the pin, in Unix seconds.
    #[schema(example = 1_800_000_000)]
    pinned_at: u64,
}

/// MEMORIES section envelope.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemories {
    /// Section format version.
    #[schema(example = "v4")]
    version: String,
    /// Applied per-slot row budget.
    budget: ContextBoardMemoriesBudget,
    /// Stable MEMORIES rows.
    rows: Vec<ContextBoardMemoryRow>,
    /// Companion assembly metadata when companion controls are present.
    companion: Option<ContextBoardCompanionAssembly>,
    /// Disclosure block for the clamp the board's assembly read under (OF-365); absent when no
    /// disclosure context was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure: Option<CoreDisclosureAssembly>,
    /// How many optional rows the projection cut past their slot's cap or the shared cap, per
    /// slot; absent when it cut none.
    #[serde(skip_serializing_if = "Option::is_none")]
    cut: Option<ContextBoardMemoriesCut>,
}

/// How many optional rows a MEMORIES projection cut, per slot: each one past its slot's cap or
/// the shared cap. A pinned row is never cut, and a cut row stays stored.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesCut {
    /// Claim rows cut.
    #[schema(example = 1)]
    claims: usize,
    /// Turn/message rows cut.
    #[schema(example = 0)]
    turns: usize,
    /// Summary rows cut.
    #[schema(example = 0)]
    summaries: usize,
    /// Facet rows cut.
    #[schema(example = 0)]
    facets: usize,
    /// Rows of all other entity types cut.
    #[schema(example = 2)]
    other: usize,
}

/// The caller's MEMORIES cursor.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesCursor {
    /// Effective session id.
    #[serde(rename = "session_id")]
    #[schema(example = "session-123")]
    session_id: String,
    /// Monotonic cursor revision for this session.
    #[schema(example = 2_u64)]
    revision: u64,
    /// Number of context-pack queries observed for this session.
    #[serde(rename = "query_count")]
    #[schema(example = 2_u64)]
    query_count: u64,
    /// Last persisted retrieval telemetry run id, when available.
    #[serde(rename = "last_retrieval_run_id")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    last_retrieval_run_id: Option<String>,
    /// Bounded list of most recent context-pack result ids for this session.
    #[serde(rename = "last_result_ids")]
    last_result_ids: Vec<String>,
}
