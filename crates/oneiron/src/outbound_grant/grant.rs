//! Standing grant record, status, and its validators.

use super::codec::{
    canonical_scoped_server, invalid_grant, non_empty_optional, non_empty_str, non_empty_string,
};
use super::scope::{ScopedMcpGrantMintIntent, StandingOutboundGrantScope, validate_scope};
use crate::error::Result;
use crate::genui::GrantMintIntent;

/// StandingOutboundGrant lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StandingOutboundGrantStatus {
    /// Grant is live and can authorize a matching outbound effect.
    Active,
    /// Grant has been revoked and must fail closed immediately.
    Revoked,
}

impl StandingOutboundGrantStatus {
    /// Returns the pinned on-disk status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// Parses a pinned on-disk status string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Vault-resident standing outbound-grant claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StandingOutboundGrant {
    /// Principal that authenticated the consent action.
    pub principal_ref: String,
    /// OF-336 component that originated the grant.
    pub origin_component_id: String,
    /// OF-336 typed action that originated the grant.
    pub origin_action_id: String,
    /// Optional origin ask/gate receipt reference.
    pub origin_receipt_ref: Option<String>,
    /// Owner-selected grant scope dial.
    pub scope: StandingOutboundGrantScope,
    /// Grant lifecycle status.
    pub status: StandingOutboundGrantStatus,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Revocation time in Unix seconds.
    pub revoked_at: Option<u64>,
    /// Last successful gate use in Unix seconds.
    pub last_used_at: Option<u64>,
    /// Content address for the originating consent binding.
    pub binding_diff_handle: Vec<u8>,
    /// Policy-floor hash in effect when the grant was minted.
    pub read_frontier_hash: [u8; 32],
}

impl StandingOutboundGrant {
    /// Constructs an active grant from an OF-336 grant mint intent.
    pub fn from_grant_mint_intent(
        intent: &GrantMintIntent,
        created_at: u64,
        binding_diff_handle: Vec<u8>,
        read_frontier_hash: [u8; 32],
    ) -> Result<Self> {
        let grant = Self {
            principal_ref: non_empty_string(&intent.principal_ref)?,
            origin_component_id: non_empty_string(&intent.origin_component_id)?,
            origin_action_id: non_empty_string(&intent.origin_action_id)?,
            origin_receipt_ref: non_empty_optional(intent.origin_receipt_ref.as_deref())?,
            scope: StandingOutboundGrantScope::from_grant_mint_scope(&intent.scope)?,
            status: StandingOutboundGrantStatus::Active,
            created_at,
            revoked_at: None,
            last_used_at: None,
            binding_diff_handle,
            read_frontier_hash,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Constructs an active payload-aware grant from authenticated grant-time
    /// input whose resolved endpoints were shown to the consenting principal.
    pub fn from_scoped_mcp_grant_mint_intent(
        intent: &ScopedMcpGrantMintIntent,
        created_at: u64,
        binding_diff_handle: Vec<u8>,
        read_frontier_hash: [u8; 32],
    ) -> Result<Self> {
        let grant = Self {
            principal_ref: non_empty_string(&intent.principal_ref)?,
            origin_component_id: non_empty_string(&intent.origin_component_id)?,
            origin_action_id: non_empty_string(&intent.origin_action_id)?,
            origin_receipt_ref: non_empty_optional(intent.origin_receipt_ref.as_deref())?,
            scope: StandingOutboundGrantScope::ScopedMcp {
                // The stored scope carries the ONE exact canonical server
                // segment, so the grant, key producer, admission, and charter
                // compiler all retain the same identity bytes. Mixed-case,
                // trimmed, or otherwise non-canonical spellings fail closed at
                // mint instead of becoming aliases (ONE-1885).
                server: canonical_scoped_server(&intent.server)?,
                tool: intent.tool.clone(),
                data_class_ceiling: intent.data_class_ceiling,
                endpoint_allowlist: intent.endpoint_allowlist.clone(),
            },
            status: StandingOutboundGrantStatus::Active,
            created_at,
            revoked_at: None,
            last_used_at: None,
            binding_diff_handle,
            read_frontier_hash,
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Returns a revoked version of this grant.
    pub fn revoked(self, revoked_at: u64) -> Result<Self> {
        let grant = Self {
            status: StandingOutboundGrantStatus::Revoked,
            revoked_at: Some(revoked_at),
            ..self
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Returns a last-used version of this grant.
    pub fn touched(self, used_at: u64) -> Result<Self> {
        if self.status != StandingOutboundGrantStatus::Active {
            return Err(invalid_grant());
        }
        let grant = Self {
            last_used_at: Some(used_at),
            ..self
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Returns whether this active grant can still be evaluated under the
    /// supplied current policy-floor hash.
    #[must_use]
    pub fn is_active_under_policy(&self, read_frontier_hash: &[u8; 32]) -> bool {
        self.status == StandingOutboundGrantStatus::Active
            && self.revoked_at.is_none()
            && &self.read_frontier_hash == read_frontier_hash
    }

    /// Validates revocation, timestamp, and binding invariants.
    pub fn validate(&self) -> Result<()> {
        non_empty_str(&self.principal_ref)?;
        non_empty_str(&self.origin_component_id)?;
        non_empty_str(&self.origin_action_id)?;
        if let Some(origin_receipt_ref) = self.origin_receipt_ref.as_deref() {
            non_empty_str(origin_receipt_ref)?;
        }
        validate_scope(&self.scope)?;
        if self.binding_diff_handle.is_empty() {
            return Err(invalid_grant());
        }
        match (self.status, self.revoked_at) {
            (StandingOutboundGrantStatus::Active, None) => {}
            (StandingOutboundGrantStatus::Active, Some(_)) => return Err(invalid_grant()),
            (StandingOutboundGrantStatus::Revoked, Some(revoked_at))
                if revoked_at >= self.created_at => {}
            (StandingOutboundGrantStatus::Revoked, Some(_))
            | (StandingOutboundGrantStatus::Revoked, None) => return Err(invalid_grant()),
        }
        if let Some(last_used_at) = self.last_used_at
            && last_used_at < self.created_at
        {
            return Err(invalid_grant());
        }
        Ok(())
    }
}
