//! Moved from `crates/oneiron/src/memory/chat.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::*;
use serde::Deserialize;
use serde::Serialize;

/// Chat uses the same closed five-level effort vocabulary as retrieval.
pub type ChatDepth = Effort;

/// Why a `.chat` call answered nothing. Each reason is a fact about the
/// evidence or the composer, so a caller can tell "the vault does not know"
/// apart from "the host would not say".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatAbstentionReason {
    /// The retrieval carried nothing, or the proposed answer could not be
    /// tied to the pack it was built from.
    InsufficientEvidence,
    /// Document scope: not one of the named refs resolved, so there was
    /// nothing in scope to read — and ranked retrieval is not a fallback.
    NoInScopeDocuments,
    /// The composer declined to answer.
    BackendDeclined,
}
