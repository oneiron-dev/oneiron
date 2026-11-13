//! Moved from `crates/oneiron/src/skill_hub/http_fetch/clawhub.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::io::Read;

/// Public provider metadata. Missing fields do not become package identity.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClawHubSearchHit {
    pub score: Option<f64>,
    pub slug: Option<String>,
    pub display_name: Option<String>,
    pub summary: Option<String>,
    pub version: Option<String>,
    pub updated_at: Option<f64>,
    pub owner_handle: Option<String>,
    pub owner: Option<ClawHubSearchOwner>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClawHubSearchOwner {
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub image: Option<String>,
}

/// Provider failures remain distinct from a successful search with no hits.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ClawHubSearchReply {
    Results {
        /// None means the provider omitted its list, not a confirmed empty list.
        results: Option<Vec<ClawHubSearchHit>>,
    },
    ProviderError {
        status: u16,
        retry_after: Option<String>,
        body: String,
    },
}
