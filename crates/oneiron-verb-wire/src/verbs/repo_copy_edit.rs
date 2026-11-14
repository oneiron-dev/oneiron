//! Moved from `crates/oneiron/src/verbs/repo_copy_edit.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.sync.documents.copy_edit.review`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoCopyEditReviewRequest {
    /// The source document (32 hex) whose retained copy holds the edit.
    pub source: String,
}

/// One held document-copy edit, as its owner reviews it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoCopyEditReviewView {
    /// The source document (32 hex).
    pub source: String,
    /// Why the edit is held: `sealed_file_edited` or
    /// `projection_edit_conflict`.
    pub cause: String,
    /// The retained, masked text the copy submitted.
    pub submitted: String,
    /// The review's revision (64 hex): pass it back unchanged to settle. A
    /// token, not authority.
    pub revision: String,
}

/// `vault.sync.documents.copy_edit.settle`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoCopyEditSettleRequest {
    /// The source document (32 hex).
    pub source: String,
    /// The revision the owner reviewed (64 hex), exactly as the review
    /// answered it.
    pub revision: String,
    /// The whole canonical text the owner settles the source to.
    pub replacement: String,
}

/// A settled document-copy edit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoCopyEditSettleView {
    /// The source document (32 hex).
    pub source: String,
    /// The committed DOCUMENT frame, standard base64: a local commit, not a
    /// delivery or convergence report.
    pub frame_base64: String,
}
