//! Moved from `crates/oneiron/src/memory/structural/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::vault::entity_view::EntityView;
use serde::Deserialize;
use serde::Serialize;

/// One BM25 text-index field for a structural put.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TextIndexField {
    /// Analyzer field name (e.g. `content`, `name`).
    pub field: String,
    /// Field text.
    pub value: String,
}

/// One outgoing edge for a structural put.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StructuralEdgeSpec {
    /// snake_case `EdgeKind` name (e.g. `belongs_to`, `attached`).
    pub edge_kind: String,
    /// Target entity ref (short-id ref or hex).
    pub target_ref: String,
    /// Edge weight in `[0, 1]`; `None` ⇒ the kind's default (1.0 fallback).
    pub weight: Option<f32>,
}

/// Structural put carrying text-index fields and edges (B2 migrator group).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StructuralPutInput {
    /// Caller-supplied deterministic 32-hex id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Registry kind string (`MESSAGE`, `PERSON`, `TASK`, `ASSET`, …).
    /// `CLAIM` is rejected — claims go through `Memory::commit`.
    pub kind: String,
    /// Entity body as a JSON object (stored as MessagePack).
    pub body: serde_json::Value,
    /// BM25 fields to index for this entity.
    pub text_fields: Option<Vec<TextIndexField>>,
    /// Outgoing edges from this entity.
    pub edges: Option<Vec<StructuralEdgeSpec>>,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// One habit check-in append (B2 migrator group).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HabitCheckinInput {
    /// Habit-role TASK ref (short-id ref or hex); must exist.
    pub habit_ref: String,
    /// Caller-supplied deterministic 32-hex checkin id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Extra body fields (JSON object). The facade injects the pinned
    /// `role` key (`HabitCheckin`); supplying `role` here is rejected.
    pub data: Option<serde_json::Value>,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// One imported-evidence claim admission (B1a migration-admission verb over
/// `ingest.rs` `admit_imported_evidence_claim`; the gate still decides).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AdmitImportedClaimInput {
    /// Registered ingest source id; unknown sources fail closed.
    pub source_id: String,
    /// Stable source record id (idempotency/provenance anchor).
    pub source_record_id: String,
    /// Caller-supplied deterministic 32-hex claim id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Subject entity ref (must exist).
    pub subject_ref: String,
    /// Predicate.
    pub predicate: String,
    /// Claim value (JSON).
    pub value: serde_json::Value,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}

/// One blob artifact registration (B8 blob door).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlobArtifactInput {
    /// Caller-supplied deterministic 32-hex artifact id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Display name (≤512 bytes).
    pub name: String,
    /// Media type (≤256 bytes).
    pub media_type: String,
    /// Unix seconds.
    pub occurred_at: u64,
    /// Unix seconds; `None` ⇒ `occurred_at`.
    pub learned_at: Option<u64>,
}
