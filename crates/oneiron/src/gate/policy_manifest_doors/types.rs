//! Typed DEC-0005 policy axes. Other manifest tables stay at their own doors.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCeiling {
    Auto,
    Proposed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCriticality {
    Normal,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicySensitivity {
    Normal,
    Sensitive,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAxes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criticality: Option<PolicyCriticality>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<PolicySensitivity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub prefix: String,
    #[serde(default)]
    pub exact: bool,
    pub axes: PolicyAxes,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActorCeiling {
    pub actor_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<String>,
    pub ceiling: PolicyCeiling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicySource {
    UserStated,
    Observed,
    Inferred,
    Generated,
    Imported,
    ToolOutput,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityName {
    Public,
    Private,
    Internal,
    Sensitive,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum SensitivityBand {
    Number(u8),
    Name(SensitivityName),
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceTrustRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_auto_sensitivity: Option<SensitivityBand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto: Option<bool>,
    #[serde(default)]
    pub receipted: bool,
    #[serde(default)]
    pub warned: bool,
}

/// All source-trust forms the engine decoder accepts, including actor-bound rows.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum SourceTrust {
    Row(SourceTrustRow),
    Rows(Vec<SourceTrustRow>),
    Disabled(bool),
    Band(SensitivityBand),
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicySignature {
    pub alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub sig: String,
}

/// The Gate policy envelope and write axes. Editing an existing manifest
/// replaces these fields only; unrelated policy tables are preserved.
/// Signature text is data, never a substitute for the owner's credential.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifest {
    pub schema_version: String,
    pub pack_id: String,
    pub pack_version: String,
    pub min_engine_version: String,
    pub defaults: PolicyAxes,
    pub rules: Vec<PolicyRule>,
    pub actor_ceilings: Vec<ActorCeiling>,
    #[serde(default)]
    pub source_trust: BTreeMap<PolicySource, SourceTrust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PolicySignature>,
    #[serde(default)]
    pub signatures: Vec<PolicySignature>,
    /// The host checker reference, as the existing manifest decoder stores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_checker: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifestRead {
    /// Omit to list all ordinary manifest contributions, including proposals.
    #[serde(default)]
    pub manifest_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifestPut {
    /// Omit for a new contribution. Use the returned default ref to edit defaults.
    #[serde(default)]
    pub manifest_ref: Option<String>,
    /// Required when editing: the exact body hash returned by the read door.
    #[serde(default)]
    pub expected_body_hash: Option<String>,
    pub manifest: PolicyManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifestPropose {
    pub manifest: PolicyManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyManifestView {
    pub manifest_ref: String,
    pub body_hash: String,
    pub trusted: bool,
    pub quarantined: bool,
    pub manifest: PolicyManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyManifestsView {
    pub default_manifest_ref: String,
    pub read_frontier_hash: String,
    pub manifests: Vec<PolicyManifestView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyManifestReceipt {
    pub manifest: PolicyManifestView,
    pub approval: PolicyCeiling,
    pub receipt_ref: String,
    pub read_frontier_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GateCheckerSet {
    pub binding: crate::llm::manifest::VerdictBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCheckerView {
    pub binding: Option<crate::llm::manifest::VerdictBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCheckerReceipt {
    pub binding: crate::llm::manifest::VerdictBinding,
    pub receipt_ref: String,
}
