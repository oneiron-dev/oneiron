//! Moved from `crates/oneiron/src/verbs/memory_requests.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::claims::ClaimInput;
use crate::memory::reads::NeighborOpts;
pub use crate::memory::session_reads::CreateNoteRequest;
pub use crate::memory::session_reads::EntityRequest;
pub use crate::memory::session_reads::HydrateRequest;
pub use crate::memory::session_reads::QueryBm25Request;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    pub claims: Vec<ClaimInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimRefRequest {
    pub claim_ref: String,
}

/// `vault.claims.history` input: one claim's supersession timeline, under
/// the caller's retrieval filter (FIX 3977). Writes keep [`ClaimRefRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimHistoryRequest {
    pub claim_ref: String,
    /// The caller's retrieval filter: it narrows the versions the timeline
    /// reads.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

/// Retraction by exact claim or by subject and predicate, never a hard delete.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ForgetRequest {
    Claim(ClaimRefRequest),
    Predicate(ForgetPredicateRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForgetPredicateRequest {
    pub subject_ref: String,
    pub predicate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NeighborsRequest {
    pub entity_ref: String,
    pub opts: NeighborOpts,
    /// The caller's retrieval filter: anchor, exact pair and peer each meet
    /// it before an edge takes one of the limit's slots.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppendBlobVersionRequest {
    pub artifact_ref: String,
    /// RFC 4648 base64. The decoded bytes are measured against
    /// `blob_content_bytes` and stored whole, never refused for their size.
    pub content_base64: String,
    #[serde(default)]
    pub run_ref: Option<String>,
    pub occurred_at: u64,
    #[serde(default)]
    pub learned_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadBlobVersionRequest {
    pub artifact_ref: String,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateNoteFromEntityRequest {
    pub source_ref: String,
    pub kind: String,
    /// The caller's stated reason, for a source its diary gate reads: another
    /// author's diary entry (FIX 9953). Every other source needs none.
    #[serde(default)]
    pub reason: Option<String>,
}

/// An opinion's subject or claim, named by short ref or 32-hex id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthorTakeTarget {
    /// Links the NOTE to a subject with `about`.
    Subject(String),
    /// Links the NOTE to a CLAIM with `claim_of`; the engine checks its type.
    Claim(String),
}

/// `vault.notes.author_take`: attribution comes only from the bound caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorTakeRequest {
    pub target: AuthorTakeTarget,
    pub markdown: String,
    /// The source document revision the take was read from, as
    /// `<document-ref>@<revision>`: each link's `edge.provenance` claim cites
    /// it. Absent when no source document exists.
    #[serde(default)]
    pub source_ref: Option<String>,
}

/// `vault.consolidation.enqueue`'s input (OF-237): one Dreamer consolidation
/// attempt, as `ConsolidationAttemptInput` takes it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationEnqueueRequest {
    /// `micro`, `meso` or `macro`.
    pub scope: String,
    /// The attempt's opaque input.
    pub input: serde_json::Value,
    #[serde(default)]
    pub run_id: Option<String>,
    /// Advisory: coalesces onto an existing attempt, never a lock.
    #[serde(default)]
    pub dedupe_key: Option<String>,
    /// Unix seconds; omitted, now.
    #[serde(default)]
    pub now: Option<u64>,
}

/// `vault.consolidation.status`'s input: the job ref an enqueue returned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationStatusRequest {
    pub job_ref: String,
}
