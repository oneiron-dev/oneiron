//! Read-facing views and per-verb inputs for structural puts.

use serde::{Deserialize, Serialize};
/// Typed read-back view of one entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityView {
    /// 32-hex entity id.
    pub id_hex: String,
    /// Short-id ref, when one is assigned.
    pub short_ref: Option<String>,
    /// Registry kind string (e.g. `MESSAGE`); `TYPE_<n>` for unregistered.
    pub kind: String,
    /// Occurred interval start (Unix seconds).
    pub occurred_start: u64,
    /// Occurred interval end (Unix seconds).
    pub occurred_end: u64,
    /// Learned-at (Unix seconds).
    pub learned_at: u64,
    /// Body decoded MessagePack→JSON; `None` when absent or not
    /// JSON-shaped (binary values are redacted per the companion codec).
    pub body: Option<serde_json::Value>,
}
/// One BM25 text-index field for a structural put.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextIndexField {
    /// Analyzer field name (e.g. `content`, `name`).
    pub field: String,
    /// Field text.
    pub value: String,
}
/// One outgoing edge for a structural put.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralEdgeSpec {
    /// snake_case `EdgeKind` name (e.g. `belongs_to`, `attached`).
    pub edge_kind: String,
    /// Target entity ref (short-id ref or hex).
    pub target_ref: String,
    /// Edge weight in `[0, 1]`; `None` ⇒ the kind's default (1.0 fallback).
    pub weight: Option<f32>,
}
/// Structural put carrying text-index fields and edges (B2 migrator group).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralPutInput {
    /// Caller-supplied deterministic 32-hex id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Registry kind string (`MESSAGE`, `PERSON`, `TASK`, `ASSET`, …).
    /// `CLAIM` is rejected — claims go through [`Memory::commit`].
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
/// Receipt for a structural write (put/checkin/companion/blob artifact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRefReceipt {
    /// Short-id ref of the written entity (hex fallback).
    pub entity_ref: String,
    /// 32-hex id of the written entity.
    pub id_hex: String,
    /// Facade write marker (`put:<hex>`); structural puts produce no gate
    /// decision at base.
    pub receipt_ref: String,
}
/// One habit check-in append (B2 migrator group).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
/// One companion persona registration (B2 migrator group, design §2.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompanionRecordInput {
    /// Caller-supplied deterministic 32-hex record id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Owner PERSON ref (personal scope).
    pub owner_ref: String,
    /// Companion persona PERSON ref.
    pub persona_ref: String,
    /// Opaque record value (JSON, stored as MessagePack).
    pub value: serde_json::Value,
    /// Provenance source string; `None` ⇒ `user_stated`.
    pub source: Option<String>,
    /// When set, the record is retired at this time after creation
    /// (migration of `isActive == false` rows).
    pub retired_at: Option<u64>,
    /// Creation time (Unix seconds) — stamps the `created` lifecycle event.
    pub learned_at: u64,
}
/// One imported-evidence claim admission (B1a migration-admission verb over
/// `ingest.rs` `admit_imported_evidence_claim`; the gate still decides).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// View of one appended blob artifact version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobVersionView {
    /// 32-hex artifact id.
    pub artifact_ref: String,
    /// Version number (1-based, append-only).
    pub version: u64,
    /// blake3 content hash, lowercase hex.
    pub content_hash_hex: String,
    /// 32-hex id of the `blob.version` LEDGER claim.
    pub claim_ref: String,
    /// Unix seconds.
    pub created_at: u64,
}
