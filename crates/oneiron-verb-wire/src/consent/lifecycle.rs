//! Moved from `crates/oneiron/src/consent/lifecycle.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Approve the exact engine-emitted effect digest, never a caller's description.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveOnceRequest {
    pub effect_digest: String,
}

/// Deny the exact effect the engine emitted, with the same digest grammar as approval.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DenyConsentRequest {
    pub effect_digest: String,
}

/// Actor (a lineage for stop-asking), action class and bounded envelope.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionBoundRequest {
    pub actor: String,
    pub class: String,
    pub envelope: ActionEnvelopeRequest,
}

/// Project and audience selectors, pinned to that project, with a per-use cap.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionEnvelopeRequest {
    pub project: String,
    pub audience: Vec<String>,
    /// A reviewed batch's count; absent for a standing no-press grant.
    /// Zero leaves every send needing the person's press.
    #[serde(default)]
    pub budget: Option<u64>,
    /// The compute envelope of a `compute.pin` standing grant (pass 34, row R7): the pins it
    /// covers at rung 0, and the machines their runs may start on. Absent on every other bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute: Option<ComputeEnvelopeRequest>,
}

/// The compute envelope of a `compute.pin` standing grant: each list names what a covered pin
/// may use, and a pin is covered only when every one of its values is listed. Each list holds
/// at least one value. A template fixes its entry, its repository and its ceilings, so the
/// grant names templates, never commits or sizes: a new revision is a new pin inside the bound.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComputeEnvelopeRequest {
    /// The template names a covered pin may name.
    pub templates: Vec<String>,
    /// The network modes a covered pin may ask for.
    pub network: Vec<ComputeNetwork>,
    /// The scope kinds a covered pin may run in.
    pub scopes: Vec<ComputeScope>,
    /// The MACHINE ids (hex) a covered pin's run may start on; the start gate reads them again
    /// before every reservation.
    pub machines: Vec<String>,
}

/// A network mode a compute envelope admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComputeNetwork {
    /// No network: the run's own empty namespace.
    None,
    /// The host's network, where the template lists it.
    Host,
}

/// A scope kind a compute envelope admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComputeScope {
    /// The host scope: the job unit's own account and cgroup.
    Host,
    /// A container from an image pinned by digest.
    Container,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureBoundRequest {
    pub audience: Vec<String>,
    pub class: String,
    pub envelope: DisclosureEnvelopeRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureEnvelopeRequest {
    pub selectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeGrantRequest {
    /// The standing grant's bound digest, as emitted by its receipt or registry.
    pub grant: String,
}
