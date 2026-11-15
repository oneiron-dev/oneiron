//! Moved from `crates/oneiron/src/authority/federation_status.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::FederationPactStatus;
use serde::Deserialize;
use serde::Serialize;

/// A local reason a pact does not confer access, beyond its folded status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FederationPactInactiveReason {
    /// The folded scope differs from the signed commitment under the live opening.
    ScopeCommitmentMismatch,
}

/// One pact as this install's current authority view admits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationPactStatusRow {
    /// The pact id, in lowercase hexadecimal.
    pub pact: String,
    /// Activation, suspension or a terminal lifecycle status from the native view.
    pub status: FederationPactStatus,
    /// The pact's current consent epoch.
    pub epoch: u64,
    /// A known local reason; absence does not imply the pact is active.
    pub inactive_reason: Option<FederationPactInactiveReason>,
}

/// All pacts in one read-only authority snapshot, in ascending pact-id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationStatus {
    pub pacts: Vec<FederationPactStatusRow>,
}
