//! Moved from `crates/oneiron/src/code_document/verbs.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::code_document::verbs::CodeDiffRequest;
pub use oneiron_verb_wire::code_document::verbs::CodeStateRequest;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// One tested state of a document, as a view names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeStateView {
    pub document_ref: String,
    pub repo: String,
    pub path: String,
    pub revision_ref: Option<String>,
    pub text_hash: String,
}

/// One operation on a code document, with who made it and why. Each ref is
/// one the caller reads: a session, actor, turn, activity, intent or model it
/// cannot read is `None`, and renders as `-`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeOperationView {
    pub operation_ref: String,
    /// Its order within the document.
    pub sequence: u64,
    pub session_ref: Option<String>,
    pub actor_ref: Option<String>,
    pub actor_class: String,
    pub turn_ref: Option<String>,
    pub activity_ref: Option<String>,
    pub intent_ref: Option<String>,
    pub model_ref: Option<String>,
    pub reasoning_effort: Option<String>,
}

/// One unit's text at one state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeUnitVersionView {
    pub content_hash: String,
    pub text: String,
    pub start_line: u32,
    pub end_line: u32,
}

/// One semantic change, with the operations made between the two states
/// that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeChangeView {
    pub path: String,
    pub symbol: String,
    pub before: Option<CodeUnitVersionView>,
    pub after: Option<CodeUnitVersionView>,
    /// Operations whose text survives in the newer unit.
    pub inserted_by: Vec<CodeOperationView>,
    /// Operations that deleted text of the older unit.
    pub deleted_by: Vec<CodeOperationView>,
}

/// `vault.code.diff`: the changes between two states, unit by unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeDiffView {
    pub before: CodeStateView,
    pub after: CodeStateView,
    pub changes: Vec<CodeChangeView>,
    /// The changes as text: each unit's operations, then its hunk.
    pub rendered: String,
}

/// A run of characters one operation wrote; `op` is absent for birth text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeSpanView {
    pub start: usize,
    pub end: usize,
    pub op: Option<CodeOperationView>,
}

/// One unit of the file and the runs that wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeUnitBlameView {
    pub path: String,
    pub symbol: String,
    pub version: CodeUnitVersionView,
    pub spans: Vec<CodeSpanView>,
}

/// `vault.code.blame`: every unit of one state, blamed by op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeBlameView {
    pub at: CodeStateView,
    pub units: Vec<CodeUnitBlameView>,
}
