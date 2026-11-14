//! Moved from `crates/oneiron/src/gate/policy_manifest_doors/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCriticality {
    Normal,
    Critical,
}

/// A predicate class's rung on the DEC-0005 content ladder: `public`,
/// `private`, `sensitive`, `restricted`. `normal` is the ordinary,
/// non-sensitive label the shipped packs carry; it keeps that meaning.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicySensitivity {
    Public,
    Private,
    Sensitive,
    Restricted,
    Normal,
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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
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
    /// Native checker selected for this source and actor binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_checker: Option<String>,
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

/// A manifest's teacher-probe floor, as the manifest decoder reads it: the
/// shipped probe's id, the vault floor in millionths of F1, and stricter
/// per-holder floors.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TeacherProbePolicy {
    pub probe_id: String,
    pub min_f1_millionths: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub holders: Vec<TeacherProbeHolderFloor>,
}

/// One holder's teacher-probe floor, at least the vault's.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TeacherProbeHolderFloor {
    pub holder_ref: String,
    pub min_f1_millionths: u32,
}

/// One sheet-answer limit row: the vault's (no artifact), an artifact's, or
/// one sheet of an artifact.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SheetAnswerLimit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sheet: Option<String>,
    pub max_count: u64,
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
pub struct GateCheckerSet {
    pub binding: oneiron_model::model_binding::VerdictBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GateCheckerView {
    pub binding: Option<oneiron_model::model_binding::VerdictBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GateCheckerReceipt {
    pub binding: oneiron_model::model_binding::VerdictBinding,
    pub receipt_ref: String,
}
