//! Moved from `crates/oneiron/src/feedback/report/disclosure.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What lets one report's text reach its publisher (FIX 8747). The issue's
/// `disclosure` is the view this basis and the live consent registry give.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "basis", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportDisclosureBasis {
    /// The owner approved this issue's exact text once, for its publisher.
    /// Revoking a standing grant does not end it.
    IssueOnce {
        /// The publisher the issue routes to.
        publisher_ref: String,
        /// 64 lower hex: the digest of the exact report request approved.
        request_digest: String,
        /// Vault seconds the owner decided.
        decided_at: u64,
    },
    /// The owner's standing disclosure grant for this publisher, live in the
    /// consent registry, where one tap revokes it.
    StandingGrant {
        /// The grant's registry reference.
        grant_ref: String,
    },
}
