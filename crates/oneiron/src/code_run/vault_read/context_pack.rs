//! Context-pack request controls, record shapes, stats and projection types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use oneiron_contracts::code_run::vault_read::{
    ContextPackBudgetControls, ContextPackDepthControls, ContextPackRetrievalBudgetControls,
    CoreContextPackRequest,
};

/// Local serialization of every public `ContextEntity` field.
///
/// `fields` is a `BTreeMap` rather than the engine's `HashMap` so the
/// serialized bytes are deterministic: adapter parity is byte-comparable, which
/// a randomly-seeded hash order cannot be.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreContextPackEntityRecord {
    /// Hex entity id.
    pub id: String,
    /// Short id allocated by the vault, or hex fallback.
    pub short_id: String,
    /// One-byte content hash.
    pub content_hash: u8,
    /// Numeric entity type byte.
    pub entity_type: u8,
    /// Retrieval score.
    pub score: f32,
    /// Hydrated fields when the pack hydrated them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<BTreeMap<String, Value>>,
    /// Hydrated edges when the pack included them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<Vec<CoreContextPackEdgeRecord>>,
    /// Stored vector when the pack included it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<Vec<f32>>,
}

/// Local serialization of one hydrated context edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreContextPackEdgeRecord {
    /// `EdgeKind`'s pinned storage discriminant.
    pub kind: u8,
    /// Hex target entity id.
    pub target: String,
    /// Target short id when the target is present in the same pack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_short_id: Option<String>,
    /// Edge weight.
    pub weight: f32,
    /// Edge creation timestamp in Unix seconds.
    pub created_at: u64,
    /// Optional edge VAD payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vad: Option<CoreContextPackVad>,
    /// Optional cached edge provenance flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<CoreContextPackEdgeProvenance>,
}

/// Local VAD triple.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CoreContextPackVad {
    /// Valence component.
    pub valence: f32,
    /// Arousal component.
    pub arousal: f32,
    /// Dominance component.
    pub dominance: f32,
}

/// Local edge provenance flags, using their pinned `repr(u8)` discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackEdgeProvenance {
    /// `EdgeConfirmationStatus` discriminant.
    pub confirmation_status: u8,
    /// `EdgeActorClass` discriminant.
    pub actor_class: u8,
}

/// Closed local mirror of the engine's retrieval `Signal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreContextPackSignal {
    /// Vector similarity channel.
    Vector,
    /// BM25 text channel.
    Text,
    /// Phonetic channel.
    Phonetic,
    /// Temporal channel.
    Temporal,
    /// Personalized PageRank channel.
    Ppr,
    /// Hypothetical-document expansion channel.
    Hyde,
}

/// Local token accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackTokenStats {
    /// Stable tokenizer identifier used for every count here.
    pub tokenizer_id: String,
    /// Exact token count of the serialized pack.
    pub total_tokens: usize,
    /// Per-section row-token accounting.
    pub sections: Vec<CoreContextPackSectionTokenStats>,
    /// Per-item row-token accounting.
    pub items: Vec<CoreContextPackItemTokenStats>,
}

/// Local per-section token accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackSectionTokenStats {
    /// Logical section name.
    pub section: String,
    /// Row-level token count for this section.
    pub tokens: usize,
}

/// Local per-item token accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackItemTokenStats {
    /// Logical section containing this item.
    pub section: String,
    /// Serialized short reference for the item.
    pub id: String,
    /// Entity type byte used for the serialized row group.
    pub entity_type: u8,
    /// Row-level token count for this item.
    pub tokens: usize,
}

/// Why items were truncated or dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreContextPackAccountingReason {
    /// Per-kind item budget.
    ItemBudget,
    /// Token budget.
    TokenBudget,
}

/// Local item accounting record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackAccounting {
    /// Number of items affected.
    pub count: usize,
    /// Accounting reason.
    pub reason: CoreContextPackAccountingReason,
}

/// Local mirror of the public pack stats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackStats {
    /// Candidates considered by retrieval.
    pub candidates_considered: usize,
    /// Retrieval signals used.
    pub signals_used: Vec<CoreContextPackSignal>,
    /// Query time in microseconds.
    pub query_time_us: u64,
    /// Entities hydrated for the results section.
    pub entities_hydrated: usize,
    /// Entities hydrated for the neighbors section.
    pub neighbors_hydrated: usize,
    /// Cosine-ghost candidates dampened.
    pub cosine_ghosts_dampened: usize,
    /// CLAIM records suppressed by the read-path gates.
    pub claims_suppressed: usize,
    /// Token accounting.
    pub tokens: CoreContextPackTokenStats,
    /// Items truncated.
    pub items_truncated: CoreContextPackAccounting,
    /// Items dropped.
    pub items_dropped: CoreContextPackAccounting,
}

/// Why an otherwise successful pack surfaced no entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreContextPackEmptyReason {
    /// Read-path filters matched nothing.
    FilterMatchedNone,
    /// Nothing in scope to retrieve.
    NoData,
    /// Every candidate was already activated.
    AllActivated,
    /// Every candidate scored below threshold.
    BelowThreshold,
}

/// Structured empty-context record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreContextPackEmpty {
    /// Machine-readable reason.
    pub reason: CoreContextPackEmptyReason,
    /// Candidate count in scope.
    pub total_in_scope: usize,
    /// Human-readable hint.
    pub hint: String,
}

/// Field-for-field local projection of the public `ContextPack`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreContextPackProjection {
    /// Turn-local capability discoveries, independent of memory rows.
    #[serde(default)]
    pub capabilities: Vec<crate::context_board::CapabilityHit>,
    /// Authorized references plus a typed withheld-data notice.
    #[serde(flatten)]
    pub access: crate::access_grant::GrantedData<String>,
    /// Mandatory actor-ceiling intersection receipt.
    pub narrowing: crate::claim::ScopedReadReceipt,
    /// Primary results.
    pub results: Vec<CoreContextPackEntityRecord>,
    /// Edge-walk neighbors.
    pub neighbors: Vec<CoreContextPackEntityRecord>,
    /// Pack statistics.
    pub stats: CoreContextPackStats,
    /// Empty-context record when the pack surfaced nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty: Option<CoreContextPackEmpty>,
}

/// Context-pack response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CoreContextPackResponse(pub CoreContextPackProjection);
