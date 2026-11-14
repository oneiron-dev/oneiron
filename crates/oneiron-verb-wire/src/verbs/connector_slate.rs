//! Moved from `crates/oneiron/src/verbs/connector_slate.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Why a re-draft names no proposal on a host with no slate drafter: one
/// sentence, so a later ruling changes one line.
pub const SLATE_REDRAFT_UNAVAILABLE: &str =
    "this host has no connector slate drafter configured; the slate is unchanged";

/// `vault.connectors.slates.redraft`: the owner's instruction for re-drafting
/// one connector grant slate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSlateRedraftRequest {
    /// The slate to re-draft, 32 hex.
    pub slate_ref: String,
    /// The slate revision the owner reviewed.
    pub expected_revision: u64,
    /// What the owner wants changed, in his own words.
    pub instruction: String,
}
