//! Moved from `crates/oneiron/src/code_document/review_views.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// One repo proposal, by ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalViewRequest {
    pub proposal_ref: String,
}

/// One side of a repo diff: a code revision's tested files
/// (`revision_ref`), or a git snapshot's files (`repo` and `snapshot_ref`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeTreeRequest {
    #[serde(default)]
    pub revision_ref: Option<String>,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub snapshot_ref: Option<String>,
}

/// Two trees of a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRepoDiffRequest {
    pub before: CodeTreeRequest,
    pub after: CodeTreeRequest,
}
