//! Moved from `crates/oneiron/src/verbs/shared_admin.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::Scope;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::batch::shared_vault_write::OrgAdminPower;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgAdminConfigured {
    pub org_ref: EntityId,
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrgAdminPowersRequest {
    pub org_ref: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrgAdminPowers {
    pub powers: Vec<OrgAdminPower>,
}

/// One explicit six-axis narrowing; the host, not the caller, supplies mint time.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationDelegateRequest {
    pub parent_grant: EntityId,
    pub member_ref: EntityId,
    pub authority_scope: Scope,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SharedProjectAccessReset {
    pub project: EntityId,
    pub installed: bool,
    pub invitations: Vec<String>,
}
