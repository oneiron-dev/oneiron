//! Moved from `crates/oneiron/src/verbs/repo_manifest_conflict.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoManifestConflictReviewRequest {
    pub window: String,
    pub portable_repo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoManifestConflictDiscardRequest {
    pub binding: String,
}

/// Queue acceptance is not delivery or convergence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RepoManifestConflictQueueView {
    Queued { sequence: u64 },
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RepoManifestConflictDiscardView {
    Discarded {
        /// The exact ordinary delta, retained even when queueing fails.
        update_base64: String,
        queue: RepoManifestConflictQueueView,
    },
    Stale,
    WindowLive,
}
