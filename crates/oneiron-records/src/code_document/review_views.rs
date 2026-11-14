//! Moved from `crates/oneiron/src/code_document/review_views.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_document::verbs::CodeChangeView;
use crate::code_document::verbs::CodeOperationView;
use crate::code_document::verbs::CodeStateView;
use oneiron_store::repo_proposal_record::RepoProposalStatus;
pub use oneiron_verb_wire::code_document::review_views::CodeProposalViewRequest;
pub use oneiron_verb_wire::code_document::review_views::CodeRepoDiffRequest;
pub use oneiron_verb_wire::code_document::review_views::CodeTreeRequest;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Who proposed a change, and why: the stamp its landed operation carries,
/// each ref as the caller reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeProposedStamp {
    pub actor_ref: Option<String>,
    pub session_ref: Option<String>,
    pub provenance_claim_ref: Option<String>,
    pub turn_ref: Option<String>,
    pub activity_ref: Option<String>,
    pub intent_ref: Option<String>,
    pub model_ref: Option<String>,
    pub reasoning_effort: Option<String>,
}

/// `vault.code.proposal_view`: one proposal as a reviewer reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeProposalView {
    pub proposal_ref: String,
    pub repo: String,
    /// The repo mutation kind it lands as (G4 PR2).
    pub operation_kind: String,
    /// An ordinary proposal's one path; `None` for a received bundle,
    /// whose every file is in `files`.
    pub path: Option<String>,
    pub message: String,
    pub status: RepoProposalStatus,
    pub proposed: CodeProposedStamp,
    /// The candidate against the file at the proposal's base, unit by unit.
    /// Every change is the proposal's; once it landed, each names that
    /// operation. `None` for a received bundle.
    pub changes: Option<Vec<CodeChangeView>>,
    /// The document operation the proposal landed as, once applied.
    pub landed: Option<CodeOperationView>,
    /// Every reviewed file: an ordinary proposal's one, a received
    /// bundle's all, each with its exact metadata change.
    pub files: Vec<CodeProposalFileView>,
    /// The changes as text, under the proposed stamp.
    pub rendered: String,
}

/// One reviewed file of a proposal: its path, its changes against its
/// base, the document operation it landed as, and its reviewed Git state
/// change, so a removal or a mode-only change is never shown as unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeProposalFileView {
    pub path: String,
    pub changes: Vec<CodeChangeView>,
    pub landed: Option<CodeOperationView>,
    pub metadata_edit: Option<super::CodeFileMetadataEdit>,
}

/// How one file changed between the trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeFileChange {
    Added,
    Removed,
    Modified,
    Renamed,
}

/// One changed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeFileDiffView {
    pub path: String,
    pub change: CodeFileChange,
    /// Its path before, when it moved.
    pub renamed_from: Option<String>,
    /// The tested document state on each side; absent on a snapshot side
    /// and on the side the file is missing from.
    pub before: Option<CodeStateView>,
    pub after: Option<CodeStateView>,
    pub changes: Vec<CodeChangeView>,
}

/// `vault.code.repo_diff`: every changed file, by path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRepoDiffView {
    pub files: Vec<CodeFileDiffView>,
    /// Files a snapshot holds that are not UTF-8 text, so not compared.
    pub not_text: Vec<String>,
    /// The changes as text, file by file.
    pub rendered: String,
}
