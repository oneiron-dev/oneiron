//! Moved from `crates/oneiron/src/saved_query/evidence.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::query_health::WakeEvaluationReport;
pub use oneiron_store::query_memos::EVIDENCE_HASH_LEN;
pub use oneiron_store::query_memos::MatchVerdict;
pub use oneiron_store::query_memos::SavedQueryDerivationEnvelope;
pub use oneiron_store::query_memos::VerdictMemoKey;
pub use oneiron_store::query_memos::VerdictMemoRow;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;

/// A verdict plus the reason it was reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchDecision {
    /// The verdict.
    pub verdict: MatchVerdict,
    /// Human-readable justification, persisted with the memo.
    pub why: String,
}
