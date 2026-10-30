//! Typed, source-bound connector-pack admission and delta re-consent.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::connector_key::qualification::{
    ConnectorQualificationKit, ConnectorQualificationReceipt,
};
use crate::connector_key::{SlateDisposition, SlateManifest, SlatePackSource, SlateRow};
use crate::skill_hub::pack_catalog::{PackInstallReceipt, PackRuntimeRecipe};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackPrepareRequest {
    pub connector: String,
    pub source: SlatePackSource,
    pub summary: String,
    #[serde(default)]
    pub secret_ref: Option<String>,
    pub protocol_revision: String,
    /// Exact resolved declaration to compare with host-observed discovery.
    pub manifest: SlateManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackGetRequest {
    pub connector: String,
}

/// What the owner reviewed, not a mutable pack name or source alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackBasis {
    pub connector: String,
    pub source: SlatePackSource,
    pub key_ref: String,
    pub slate_ref: String,
    pub slate_revision: u64,
    pub manifest_hash: String,
    pub grant_hash: String,
    pub advisory_hash: String,
    pub protocol_revision: String,
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
pub struct ConnectorPackAcceptRequest {
    pub basis: ConnectorPackBasis,
    #[serde(default)]
    pub rows: BTreeMap<String, SlateDisposition>,
    #[serde(default)]
    pub facets: Option<Vec<String>>,
    #[serde(default)]
    pub all_manual: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackUpdateRequest {
    pub prior: ConnectorPackBasis,
    pub source: SlatePackSource,
    pub protocol_revision: String,
    pub manifest: SlateManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorPackView {
    pub basis: ConnectorPackBasis,
    pub status: String,
    pub consent_required: bool,
    pub stamped: bool,
    /// The shown slate waits beside the one the key routes on; the key keeps
    /// routing until the owner stamps this one and a fresh suite passes.
    pub staged: bool,
    pub manifest: SlateManifest,
    pub rows: Vec<SlateRow>,
    pub qualification: Option<ConnectorQualificationReceipt>,
    /// Exact installed source, or its Candidate receipt before qualification.
    pub pack: Option<PackInstallReceipt>,
    /// Hash-bound scanner findings, read by the install gate, never a passing grade.
    pub advisories: Vec<ConnectorPackAdvisory>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorPackDelta {
    pub prior: ConnectorPackBasis,
    pub current: ConnectorPackView,
    pub changed: bool,
    pub reask: Vec<String>,
    pub carried: Vec<String>,
    pub dropped: Vec<String>,
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
    pub ceiling: crate::outbound_consent::DataClass,
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
pub struct ConnectorPackGrants {
    pub basis: ConnectorPackBasis,
    pub endpoint: Option<String>,
    pub authority: crate::connector_key::ConnectorConsentView,
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
