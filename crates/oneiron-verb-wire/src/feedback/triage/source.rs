//! Moved from `crates/oneiron/src/feedback/triage/source.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::feedback::triage::FeedbackTriageContinuation;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What stopped a source's walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackTriageSourceErrorKind {
    /// The repository refused the deployment's credential, or wants one
    /// the deployment does not have: a 401, a 403 that is not a rate limit,
    /// or a 404. A managed vault has no credential for a private repository.
    AuthUnavailable,
    /// The source's rate limit: a 429, or a 403 with no requests left or
    /// with a `Retry-After`.
    RateLimited,
    /// Any other answer that is not a page.
    Upstream,
    /// No answer: the request did not complete.
    Transport,
    /// An answer the sweep cannot read: a page that does not parse, or a
    /// next page off the bound repository's listing.
    Unreadable,
    /// The engine's own failure while it walked the source.
    Engine,
}

/// What stopped a source's last walk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageSourceError {
    /// What it was.
    pub kind: FeedbackTriageSourceErrorKind,
    /// The HTTP status, when the source answered.
    pub status: Option<u16>,
    /// 32 hex: the sweep that met it.
    pub sweep: EntityId,
    /// Vault seconds it was met.
    pub at: u64,
}
