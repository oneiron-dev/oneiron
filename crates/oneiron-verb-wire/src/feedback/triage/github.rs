//! Moved from `crates/oneiron/src/feedback/triage/github.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where a GitHub source's walk resumes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GithubSweepContinuation {
    /// The walk: one more each time a walk reaches the last page.
    pub generation: u64,
    /// The next page, as the last page's `Link: rel="next"` named it;
    /// `None` when the walk starts at the first page.
    pub next: Option<String>,
    /// The ETag the last page carried: HTTP evidence of the listing, never
    /// an item's revision.
    pub etag: Option<String>,
}
