//! `vault.audit_read.grant` and `vault.audit_read.revoke` (RULING
//! AUDIT-READ-POWER-LIST = B; Engine RULING AUDITREAD-GRANT-HOME = A): the
//! owner's own acts on the one audit_read power, and who holds it.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.audit_read.grant`'s input: the holder, and when its power ends.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditReadGrantRequest {
    /// The person or agent to hold the power: its PERSON or AGENT_DEF row
    /// (32 hex).
    pub holder: EntityId,
    /// When the power ends (Unix seconds, exclusive, the vault's clock); it
    /// must lie after the grant. None holds until the owner revokes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// `vault.audit_read.revoke`'s input: the holder.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditReadRevokeRequest {
    /// The person or agent whose power ends (32 hex).
    pub holder: EntityId,
}

/// One live holder of the audit_read power.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditReadHolderRow {
    /// The person or agent that holds it.
    pub holder: EntityId,
    /// Its audit_read grant row (32 hex).
    pub grant_ref: EntityId,
    /// When the owner granted it (Unix seconds, the vault's clock).
    pub granted_at: u64,
    /// When it ends, if the owner named an end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// What the owner's grant or revoke did, and who holds the power now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditReadChanged {
    /// The holder's audit_read grant row (32 hex).
    pub grant_ref: EntityId,
    /// The person or agent the call named.
    pub holder: EntityId,
    /// False when the power already stood so and the call changed nothing.
    pub changed: bool,
    /// The grant as it now stands: `active`, `expired` or `revoked`.
    pub status: String,
    /// When the standing grant was made (Unix seconds, the vault's clock).
    pub granted_at: u64,
    /// When it ends, if the owner named an end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// When it was revoked, once it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    /// Every live holder after this call, in grant id order.
    pub holders: Vec<AuditReadHolderRow>,
}
