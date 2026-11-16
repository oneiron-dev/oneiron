//! Moved from `crates/oneiron/src/verbs/memory_requests.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::memory::session_reads::CreateNoteRequest;
pub use oneiron_verb_wire::memory::session_reads::EntityRequest;
pub use oneiron_verb_wire::memory::session_reads::HydrateRequest;
pub use oneiron_verb_wire::memory::session_reads::QueryBm25Request;
pub use oneiron_verb_wire::verbs::memory_requests::AppendBlobVersionRequest;
pub use oneiron_verb_wire::verbs::memory_requests::AuthorTakeRequest;
pub use oneiron_verb_wire::verbs::memory_requests::AuthorTakeTarget;
pub use oneiron_verb_wire::verbs::memory_requests::ClaimHistoryRequest;
pub use oneiron_verb_wire::verbs::memory_requests::ClaimRefRequest;
pub use oneiron_verb_wire::verbs::memory_requests::CommitRequest;
pub use oneiron_verb_wire::verbs::memory_requests::ConsolidationEnqueueRequest;
pub use oneiron_verb_wire::verbs::memory_requests::ConsolidationStatusRequest;
pub use oneiron_verb_wire::verbs::memory_requests::CreateNoteFromEntityRequest;
pub use oneiron_verb_wire::verbs::memory_requests::ForgetPredicateRequest;
pub use oneiron_verb_wire::verbs::memory_requests::ForgetRequest;
pub use oneiron_verb_wire::verbs::memory_requests::NeighborsRequest;
pub use oneiron_verb_wire::verbs::memory_requests::ReadBlobVersionRequest;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobContent {
    pub content_base64: String,
}
