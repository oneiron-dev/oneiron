//! Moved from `crates/oneiron/src/memory/origin_doors/workbench_types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::merge_queue_doors::types::MergeQueuePointersView;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::code_document_values::CodeDocumentFrontier;
use oneiron_store::code_document_values::CodeFileMetadataEdit;
use oneiron_store::code_import_manifest::CodeImportAnchor;
use oneiron_store::code_tree_blob::CodeTreeBlob;
pub use oneiron_verb_wire::memory::origin_doors::workbench_types::CodeForkGetRequest;
pub use oneiron_verb_wire::memory::origin_doors::workbench_types::CodePushIngressGetRequest;
pub use oneiron_verb_wire::memory::origin_doors::workbench_types::CodeRepoGetRequest;
use oneiron_verb_wire::origin::document_candidate_types::CodePushCandidateView;
use oneiron_verb_wire::origin::document_ingress::ReceivedFileOperation;
use serde::Deserialize;
use serde::Serialize;

/// A received ref's link: its push and full ref.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CodeIngressRef {
    pub provenance: EntityId,
    pub ref_name: String,
}

/// One immutable import manifest of the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRepoImportLink {
    pub manifest: EntityId,
    pub anchor: CodeImportAnchor,
}

/// One file a run's work view held, by its content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRunWorkFile {
    pub path: String,
    pub content_hash_blake3: String,
}

/// One run's work on the repository, as its saved view receipt recorded
/// it: historical evidence, not a live lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRunWorkLink {
    pub work: EntityId,
    pub task: EntityId,
    pub executor_run: EntityId,
    pub ref_name: String,
    pub base_green: String,
    pub base_snapshot: String,
    pub fork_hash: String,
    pub files: Vec<CodeRunWorkFile>,
}

/// One served code repository and its stored workbench links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeRepoView {
    pub repo: EntityId,
    pub project: EntityId,
    pub served_repo: String,
    pub imports: Vec<CodeRepoImportLink>,
    pub queue: Option<MergeQueuePointersView>,
    /// The queue's exact verified current-green seal, never a live head.
    pub green_revision: Option<EntityId>,
    pub batch_refs: Vec<String>,
    pub check_work_refs: Vec<String>,
    pub task_refs: Vec<EntityId>,
    pub fork_sessions: Vec<EntityId>,
    pub ingress: Vec<CodeIngressRef>,
    pub run_works: Vec<CodeRunWorkLink>,
}

/// One document of a fork: its base, what landed, the target identity its
/// proposal asks for and the reviewed metadata change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeForkDocumentView {
    /// The document id, 64 lower-hex, once the path has one.
    pub document_id: Option<String>,
    pub path: String,
    pub base: Option<CodeDocumentFrontier>,
    /// Earned only from a saved matching operation receipt.
    pub landed: Option<CodeDocumentFrontier>,
    /// The desired file identity, not an earned frontier.
    pub target: Option<CodeTreeBlob>,
    pub metadata_edit: Option<CodeFileMetadataEdit>,
    pub proposal_ref: Option<EntityId>,
}

/// One durable revision fork and its recorded base, documents and links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeForkView {
    pub repo: EntityId,
    pub fork_session: EntityId,
    pub parent_session: EntityId,
    pub base_revision: EntityId,
    pub forked_at: u64,
    pub documents: Vec<CodeForkDocumentView>,
    pub proposal_refs: Vec<EntityId>,
    pub revision_refs: Vec<EntityId>,
    /// The TASKs this fork's own operations worked under or served (FIX
    /// 7536), sorted by id.
    pub task_refs: Vec<EntityId>,
    pub ingress: Option<CodeIngressRef>,
}

/// One authenticated received ref, its operations and candidate progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodePushIngressView {
    pub repo: EntityId,
    pub provenance: EntityId,
    pub ref_name: String,
    pub old_oid: Option<String>,
    pub new_oid: Option<String>,
    pub received_at: u64,
    pub published: bool,
    pub publication: Option<EntityId>,
    pub operations: Vec<ReceivedFileOperation>,
    pub candidate: Option<CodePushCandidateView>,
}
