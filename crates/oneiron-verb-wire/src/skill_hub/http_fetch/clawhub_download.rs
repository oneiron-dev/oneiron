//! Moved from `crates/oneiron/src/skill_hub/http_fetch/clawhub_download.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::io::Read;
use std::time::Duration;
use std::time::Instant;

/// Untrusted provider metadata. `content_hash` has no qualified native hash
/// algorithm; neither it nor the archive URL is an admission proof.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClawHubGitHubHandoff {
    pub source_ref: String,
    pub repo: String,
    pub commit: String,
    pub path: String,
    pub content_hash: String,
    pub archive_url: String,
}
