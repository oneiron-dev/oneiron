//! Moved from `crates/oneiron/src/verbs/connector.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `connector.list`'s input: a name or summary fragment; all catalogued
/// keys and first-party interfaces in the discovery lens when blank.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorListRequest {
    #[serde(default)]
    pub query: Option<String>,
}

/// `connector.status`'s input: a catalogued connector's name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorNameRequest {
    pub name: String,
}
