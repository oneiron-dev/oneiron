//! Moved from `crates/oneiron/src/memory/scoped_export.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::Scope;
use serde::Deserialize;
use serde::Serialize;

/// A position may select rows but cannot be supplied as a permission ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "scope",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RecordPosition {
    Position(Scope),
}

/// A permission limit, never a record position. Reading this value projects
/// the authenticated credential; supplying it to attenuation can only narrow it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "scope",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CredentialCeiling {
    Ceiling(Scope),
}

/// Reads the stored position of a record the caller may read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordPositionRequest {
    pub record_ref: String,
}

/// Requested read axes: empty lists add no narrowing, unlike an empty grant axis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RecordSelector {
    pub worlds: Option<super::RecallWorlds>,
    pub facet_refs: Vec<String>,
    pub kinds: Vec<String>,
    pub project_refs: Vec<String>,
}

/// The channel's wire axes are ceilings: omitted or empty axes grant nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "values",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ScopeAxisInput<T> {
    Bottom,
    All,
    Some(Vec<T>),
}

impl<T> Default for ScopeAxisInput<T> {
    fn default() -> Self {
        Self::Bottom
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSensitivityBand {
    Public,
    Private,
    Sensitive,
    Restricted,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ScopeSensitivityInput {
    #[default]
    Bottom,
    /// The top ceiling, as `all` reads on every other channel axis.
    All,
    AtMost(ScopeSensitivityBand),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ChannelCeiling {
    pub worlds: ScopeAxisInput<String>,
    pub facets: ScopeAxisInput<String>,
    pub bands: ScopeAxisInput<u8>,
    pub audience: ScopeAxisInput<String>,
    pub verbs: ScopeAxisInput<String>,
    pub sensitivity: ScopeSensitivityInput,
}

impl<T: Ord + Clone> ScopeAxisInput<T> {
    fn axis(&self) -> oneiron_authority::federation::ScopeAxis<T> {
        match self {
            Self::Bottom => oneiron_authority::federation::ScopeAxis::Bottom,
            Self::All => oneiron_authority::federation::ScopeAxis::All,
            Self::Some(values) => values.iter().cloned().collect(),
        }
    }
}

/// A destination selection meets the credential; it never replaces it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportChannel {
    pub channel_ref: String,
    pub scope: ChannelCeiling,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopedExportRequest {
    pub selector: RecordSelector,
    pub channel: ExportChannel,
}
