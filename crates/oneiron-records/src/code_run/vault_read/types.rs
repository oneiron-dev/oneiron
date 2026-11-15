//! Moved from `crates/oneiron/src/code_run/vault_read/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::deletion::timeline::HydratedShortIdDeletion;
use crate::deletion::timeline::MemoryTimelineRecordState;
pub use oneiron_contracts::code_run::vault_read::AskRequest;
pub use oneiron_contracts::code_run::vault_read::CodeExecuteRequest;
pub use oneiron_contracts::code_run::vault_read::CodeSearchRequest;
pub use oneiron_contracts::code_run::vault_read::CoreBatchShortIdHydrateRequest;
pub use oneiron_contracts::code_run::vault_read::CoreHydrateRequest;
pub use oneiron_contracts::code_run::vault_read::CoreMemoryTimelineRequest;
pub use oneiron_contracts::code_run::vault_read::CoreQueryAffect;
pub use oneiron_contracts::code_run::vault_read::CoreQueryRequest;
pub use oneiron_contracts::code_run::vault_read::CountMode;
pub use oneiron_contracts::code_run::vault_read::View;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// Entity record constructible from a `ScopedRead::read` row.
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

/// Count metadata reported by [`CoreQueryResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreQueryMeta {
    /// Reported total under the collapsed count mode.
    pub total: u64,
    /// Collapsed count mode actually applied.
    #[serde(rename = "countMode")]
    pub count_mode: CountMode,
    /// Whether this door lowered the requested result count; always false.
    #[serde(
        rename = "limitClamped",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub limit_clamped: bool,
}

/// Query response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreQueryResponse {
    /// Authorized references plus a typed withheld-data notice.
    #[serde(flatten)]
    pub access: crate::access_grant::context::GrantedData<String>,
    /// Mandatory read clamp receipt, including un-narrowed reads.
    pub narrowing: oneiron_contracts::claim::ScopedReadReceipt,
    /// Projected page of admitted entities.
    pub items: Vec<CoreEntityRecord>,
    /// Reserved cursor field; this contract version never paginates.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Count metadata.
    pub meta: CoreQueryMeta,
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
    /// Mandatory read clamp receipt, including un-narrowed reads.
    pub narrowing: oneiron_contracts::claim::ScopedReadReceipt,
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
    /// A legal order keeps the named record, which this reader otherwise
    /// reads, from use (FIX 5226): its own slot, never the batch's abort.
    UseRestricted,
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
    /// Mandatory read clamp receipt, including un-narrowed reads.
    pub narrowing: oneiron_contracts::claim::ScopedReadReceipt,
    /// Per-input results, in caller order.
    pub results: Vec<CoreBatchShortIdHydrateItem>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreMemoryTimelineResponse {
    /// Policy intersection and withheld history count for this timeline.
    pub narrowing: oneiron_contracts::claim::ScopedReadReceipt,
    /// Hex anchor entity id.
    #[serde(rename = "anchor_id")]
    pub anchor_id: String,
    /// Ordered timeline records.
    pub records: Vec<CoreMemoryTimelineRecord>,
}

/// M8-reserved ask response payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AskResponse(pub Value);

/// M8-reserved code-search response payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeSearchResponse(pub Value);

/// M8-reserved code-execute response payload. Opaque on purpose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeExecuteResponse(pub Value);
