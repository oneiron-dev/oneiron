//! Moved from `crates/oneiron/src/snapshot_read/policy_preflight.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The derive verdict on one readable ref, for the acts `derive` and
/// `archive`: what a `vault.derive.commit` item of the caller's that changes
/// the row would be told by its grant, judged now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PolicyPreflightVerdict {
    /// The caller's live grant allows the act.
    Allowed {
        /// The grant a commit's receipt names: the newest standing Steward
        /// grant row's id, or the policy rows' ref for a base agent no grant
        /// row names yet.
        grant: String,
    },
    /// The caller's live grant refuses the act.
    Refused {
        /// The stable refusal token a commit's receipt carries
        /// (`gate.deny.derive.*`).
        reason: String,
    },
}
