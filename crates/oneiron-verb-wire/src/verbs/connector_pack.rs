//! Moved from `crates/oneiron/src/verbs/connector_pack.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::qualification::ConnectorQualificationKit;
use crate::skill_hub::pack_catalog::admission_types::PackRuntimeRecipe;
pub use crate::task_verb::revoke_lands::ConnectorPackBasis;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackGetRequest {
    pub connector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackQualifyRequest {
    pub basis: ConnectorPackBasis,
    pub kit: ConnectorQualificationKit,
    #[serde(default)]
    pub runtime: Option<PackRuntimeRecipe>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackGrantsGetRequest {
    pub basis: ConnectorPackBasis,
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackGrantRow {
    pub tool: String,
    pub ceiling: oneiron_consent_state::consent::tool_scope::DataClass,
    #[serde(default)]
    pub headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackGrantsPutRequest {
    pub basis: ConnectorPackBasis,
    /// Must still equal this host's installed endpoint.
    pub endpoint: String,
    #[serde(default)]
    pub actor: Option<String>,
    pub rows: Vec<ConnectorPackGrantRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorPackAdvisory {
    pub content_hash: String,
    pub provider: String,
    pub scanned_at: u64,
    pub verdict: String,
    pub risk_level: String,
    pub completeness: String,
    pub governance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned_at_declared: Option<u64>,
}
