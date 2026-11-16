//! Moved from `crates/oneiron/src/verbs/persona.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::access_grant::request::AccessRequestStatus;
use crate::share_travel::copy::CopyRefs;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompanionAccessRequestAnswer {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompanionAccessRequestAnswerRequest {
    pub request: EntityId,
    pub answer: CompanionAccessRequestAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompanionProfileRequestedScope {
    CompanionProfile {
        person_ref: EntityId,
        facet_ref: Option<EntityId>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CompanionAccessRequestAnswered {
    pub request: EntityId,
    pub principal_ref: EntityId,
    pub capability: String,
    pub scope: CompanionProfileRequestedScope,
    pub status: AccessRequestStatus,
    /// Approval creates exactly this grant at the request's id; denial creates none.
    pub grant_ref: Option<EntityId>,
    pub decided_by: Option<EntityId>,
    pub decided_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonaSnapshotPreviewRequest {
    pub subject: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotPreviewRow {
    pub row_id: String,
    pub kind: String,
    pub text: String,
    pub provenance_refs: Vec<String>,
    pub attribution: Option<String>,
    pub struck: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotPreview {
    pub subject: EntityId,
    pub stamp: String,
    pub identity_line: String,
    pub rows: Vec<PersonaSnapshotPreviewRow>,
    /// RFC 3339 UTC compile time, as on the owner's persona surface.
    pub compiled_at: String,
    pub stale_after_secs: u64,
}

/// The structured mode-A render, from the same compile as the markdown card.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotMemoryPack {
    pub schema: String,
    pub kind: String,
    /// Absent from a copy made without its vault refs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<EntityId>,
    pub identity_line: Option<String>,
    pub audience_ref: Option<String>,
    pub takes_included: bool,
    pub compiled_at_secs: u64,
    pub stale_after_secs: u64,
    pub persona_compile_stamp: String,
    pub rows: Vec<PersonaSnapshotMemoryPackRow>,
}

/// A memory-pack row. Relationship rows carry only coarse text; the other
/// rows retain their sources — except in an Omit copy (FIX 1199), whose rows
/// carry `row-N` labels with no mapping to the envelope's native
/// `included_row_ids` and `struck_row_ids`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotMemoryPackRow {
    pub row_id: String,
    pub kind: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salience: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotExportedCopy {
    pub export_id: EntityId,
    pub subject: EntityId,
    pub stamp: String,
    /// The copy edited to issue this version; null for the initial export.
    pub previous_export_id: Option<EntityId>,
    pub memory_pack: PersonaSnapshotMemoryPack,
    /// The MemoryPack-lite render's exact bytes, as the export issued them
    /// and its receipt's fingerprint covers them; `memory_pack` is their
    /// typed view.
    pub memory_pack_json: String,
    pub markdown: String,
    pub included_row_ids: Vec<String>,
    pub struck_row_ids: Vec<String>,
    pub compiled_at: String,
    pub stale_after_secs: u64,
    /// What this copy is, by digest, and what it left out (FIX 1199).
    pub receipt: PersonaSnapshotCopyReceipt,
}

/// A persona copy's local receipt (FIX 1199): the export record's digest of
/// both renders and the vault ref slots they left out. It names the copy;
/// it grants nothing.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PersonaSnapshotCopyReceipt {
    /// The ref choice the copy was made under.
    pub refs: CopyRefs,
    /// blake3 hex over both renders as the export issued them:
    /// `memory_pack_json`, a NUL byte, then `markdown`.
    pub artifact_fingerprint: String,
    /// The vault ref slots both renders left out (`subject_ref`,
    /// `audience_ref` and `provenance_refs` dropped; `row_id` and
    /// `attribution` under copy-local labels); empty for `preserve`.
    pub omitted_refs: Vec<String>,
}
