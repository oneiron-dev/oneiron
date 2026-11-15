//! Code symbol lease, proposal and mutation-log request and view records.
//! `CodeSymbolsDeclareRequest` is the first of its records.
//! These are local definitions; `memory::code_doors` re-exports them.

use serde::{Deserialize, Serialize};

use crate::EntityId;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::code_doors::types::{
    CodeProposalRereviewRequest, CodeProposalSubmitRequest, CodeProposalSubmitted, CodeRepoRequest,
    CodeSymbolsDeclareRequest, CodeSymbolsTaskRequest,
};

/// A stored symbol declaration, as the engine holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSymbolLeaseView {
    pub task: EntityId,
    /// The caller that declared it.
    pub holder: EntityId,
    pub symbols: Vec<EntityId>,
    /// Engine host time plus the declared lifetime, in Unix seconds.
    pub expires_at: u64,
    /// False while the declaration waits behind an overlapping live one.
    pub held: bool,
}

/// A declaration, granted or waiting. A waiting declaration is retained,
/// never refused; it grants no write, approval or landing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSymbolsDeclared {
    pub declaration: CodeSymbolLeaseView,
    /// The TASK ids whose live overlapping declarations it waits behind;
    /// empty when granted. Task refs, not proposal refs.
    pub blockers: Vec<EntityId>,
}

/// What a release did. It is not fenced by any lease generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSymbolsReleased {
    pub task: EntityId,
    /// False when the task held no declaration.
    pub released: bool,
}

/// The durable repository mutation log, in sequence order. It records
/// mutations the engine prepared or ran; a pending proposal is not in it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeMutationLog {
    pub repo: EntityId,
    pub entries: Vec<CodeMutationEntry>,
}

/// Where one mutation stands, as its oplog row records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeMutationState {
    Prepared,
    Applied,
    Failed,
}

/// One oplog row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeMutationEntry {
    /// The engine's canonical repo_ref.
    pub repo_ref: String,
    pub seq: u64,
    pub operation_kind: String,
    pub operation_subject: Option<String>,
    /// None when the engine recorded no actor, or once that actor was erased
    /// (FIX 3520).
    pub actor: Option<EntityId>,
    pub session: Option<EntityId>,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    /// 64 lower-hex BLAKE3 fork hashes.
    pub pre_action_fork_hash: String,
    pub expected_post_action_fork_hash: Option<String>,
    pub status: CodeMutationState,
    pub failure: Option<String>,
}
