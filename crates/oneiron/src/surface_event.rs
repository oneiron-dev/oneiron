//! Inbound SurfaceEvent adapter contract (OF-347 CID-6).
//!
//! Adapters normalize inbound provider payloads through this module after
//! resolving the receiving channel identity. The contract is intentionally
//! storage-light: it returns a route receipt and, when accepted, the
//! identity-stamped SurfaceEvent for downstream ingestion.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState};
use crate::error::{Error, Result};
use crate::types::EntityId;

/// Current inbound SurfaceEvent schema version.
pub const SURFACE_EVENT_SCHEMA_VERSION: u64 = 1;

/// Stable receipt family label for inbound SurfaceEvent routing.
pub const INBOUND_SURFACE_RECEIPT_KIND: &str = "inbound_surface_event_route";

/// Counterparty identity known at inbound normalization time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SurfaceCounterpartyStamp {
    /// A known counterparty/contact record. CID-7 owns consent semantics.
    Known { counterparty_ref: String },
    /// A provider-native sender key not yet attached to a contact record.
    Unknown { counterparty_key: String },
}

impl SurfaceCounterpartyStamp {
    /// Builds a known-counterparty stamp from an entity id.
    #[must_use]
    pub fn known(counterparty_ref: EntityId) -> Self {
        Self::Known {
            counterparty_ref: counterparty_ref.to_hex(),
        }
    }

    /// Builds an unknown-counterparty stamp from provider-native sender data.
    #[must_use]
    pub fn unknown(counterparty_key: impl Into<String>) -> Self {
        Self::Unknown {
            counterparty_key: counterparty_key.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Known { counterparty_ref } => validate_non_blank(
                counterparty_ref,
                "surface counterparty ref must be non-empty",
            ),
            Self::Unknown { counterparty_key } => validate_non_blank(
                counterparty_key,
                "surface counterparty key must be non-empty",
            ),
        }
    }
}

/// Adapter-normalized inbound payload before identity routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundSurfaceEventInput {
    pub event_id: String,
    pub channel: String,
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    pub counterparty: SurfaceCounterpartyStamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
    /// Foreign/provider-authored inbound is claims-not-instructions canon.
    pub foreign_inbound: bool,
}

impl InboundSurfaceEventInput {
    /// Builds an inbound payload for identity routing.
    #[must_use]
    pub fn new(
        event_id: impl Into<String>,
        channel: impl Into<String>,
        receiving_address_or_handle: impl Into<String>,
        counterparty: SurfaceCounterpartyStamp,
        received_at: u64,
        foreign_inbound: bool,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            channel: channel.into(),
            receiving_address_or_handle: receiving_address_or_handle.into(),
            workspace_ref: None,
            counterparty,
            payload_ref: None,
            received_at,
            foreign_inbound,
        }
    }

    /// Attaches a provider-native workspace/team stamp.
    #[must_use]
    pub fn with_workspace_ref(mut self, workspace_ref: impl Into<String>) -> Self {
        self.workspace_ref = Some(workspace_ref.into());
        self
    }

    /// Attaches an adapter-local payload reference.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: impl Into<String>) -> Self {
        self.payload_ref = Some(payload_ref.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_non_blank(&self.event_id, "surface event id must be non-empty")?;
        validate_non_blank(&self.channel, "surface event channel must be non-empty")?;
        validate_non_blank(
            &self.receiving_address_or_handle,
            "surface event receiving address must be non-empty",
        )?;
        if let Some(payload_ref) = &self.payload_ref {
            validate_non_blank(payload_ref, "surface event payload ref must be non-empty")?;
        }
        if let Some(workspace_ref) = &self.workspace_ref {
            validate_non_blank(
                workspace_ref,
                "surface event workspace ref must be non-empty",
            )?;
        }
        self.counterparty.validate()
    }
}

/// Identity-stamped inbound event passed to downstream surface ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceEvent {
    pub schema_version: u64,
    pub event_id: String,
    pub channel: String,
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    /// ChannelIdentity entity addressed by this inbound payload.
    pub receiving_identity_ref: String,
    /// Agent resolved from the receiving ChannelIdentity binding.
    pub agent_ref: String,
    pub counterparty: SurfaceCounterpartyStamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
    pub foreign_inbound: bool,
    /// Foreign inbound is claims, not executable owner instructions.
    pub claims_not_instructions: bool,
    /// Quarantined/released identities still route so replies are not dropped.
    pub identity_retiring: bool,
}

/// Inbound routing result class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InboundSurfaceRouteOutcome {
    Routed,
    Rejected,
}

/// Stable rejection reasons for inbound SurfaceEvent routing receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InboundSurfaceRejectionReason {
    UnknownReceivingIdentity,
    NonAgentBoundIdentity,
    InactiveReceivingIdentity,
    TombstonedReceivingIdentity,
}

impl InboundSurfaceRejectionReason {
    /// Stable string used in adapter logs and receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownReceivingIdentity => "unknown_receiving_identity",
            Self::NonAgentBoundIdentity => "non_agent_bound_identity",
            Self::InactiveReceivingIdentity => "inactive_receiving_identity",
            Self::TombstonedReceivingIdentity => "tombstoned_receiving_identity",
        }
    }
}

/// Adapter-facing receipt for accepted and rejected inbound routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundSurfaceRouteReceipt {
    pub schema_version: u64,
    pub receipt_kind: String,
    pub event_id: String,
    pub outcome: InboundSurfaceRouteOutcome,
    pub channel: String,
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiving_identity_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_ref: Option<String>,
    pub counterparty: SurfaceCounterpartyStamp,
    pub foreign_inbound: bool,
    pub claims_not_instructions: bool,
    pub identity_retiring: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<InboundSurfaceRejectionReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_event: Option<SurfaceEvent>,
}

impl InboundSurfaceRouteReceipt {
    /// Returns the stable rejection reason string, when rejected.
    #[must_use]
    pub fn rejection_reason_str(&self) -> Option<&'static str> {
        self.rejection_reason
            .map(InboundSurfaceRejectionReason::as_str)
    }
}

impl Vault {
    /// Resolves an inbound adapter payload into an identity-stamped
    /// SurfaceEvent or a typed route rejection receipt.
    pub fn route_inbound_surface_event(
        &self,
        input: InboundSurfaceEventInput,
    ) -> Result<InboundSurfaceRouteReceipt> {
        route_inbound_surface_event(self, input)
    }
}

fn route_inbound_surface_event(
    vault: &Vault,
    input: InboundSurfaceEventInput,
) -> Result<InboundSurfaceRouteReceipt> {
    input.validate()?;
    let claims_not_instructions = input.foreign_inbound;
    let Some((identity_ref, identity)) =
        vault.channel_identity_by_assignment(&input.channel, &input.receiving_address_or_handle)?
    else {
        return Ok(rejected_receipt(
            input,
            None,
            None,
            false,
            claims_not_instructions,
            InboundSurfaceRejectionReason::UnknownReceivingIdentity,
        ));
    };

    let agent_ref = match identity.binding {
        ChannelIdentityBinding::Agent { agent_ref } => agent_ref,
        ChannelIdentityBinding::Vault { .. } => {
            return Ok(rejected_receipt(
                input,
                Some(identity_ref),
                None,
                false,
                claims_not_instructions,
                InboundSurfaceRejectionReason::NonAgentBoundIdentity,
            ));
        }
    };

    match identity.state {
        ChannelIdentityState::Active | ChannelIdentityState::Rotating => Ok(routed_receipt(
            input,
            identity_ref,
            agent_ref,
            false,
            claims_not_instructions,
        )),
        ChannelIdentityState::Released | ChannelIdentityState::Quarantine => Ok(routed_receipt(
            input,
            identity_ref,
            agent_ref,
            true,
            claims_not_instructions,
        )),
        ChannelIdentityState::Tombstone => Ok(rejected_receipt(
            input,
            Some(identity_ref),
            Some(agent_ref),
            false,
            claims_not_instructions,
            InboundSurfaceRejectionReason::TombstonedReceivingIdentity,
        )),
        ChannelIdentityState::Requested | ChannelIdentityState::PendingFulfillment => {
            Ok(rejected_receipt(
                input,
                Some(identity_ref),
                Some(agent_ref),
                false,
                claims_not_instructions,
                InboundSurfaceRejectionReason::InactiveReceivingIdentity,
            ))
        }
    }
}

fn routed_receipt(
    input: InboundSurfaceEventInput,
    identity_ref: EntityId,
    agent_ref: EntityId,
    identity_retiring: bool,
    claims_not_instructions: bool,
) -> InboundSurfaceRouteReceipt {
    let surface_event = SurfaceEvent {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        event_id: input.event_id.clone(),
        channel: input.channel.clone(),
        receiving_address_or_handle: input.receiving_address_or_handle.clone(),
        workspace_ref: input.workspace_ref.clone(),
        receiving_identity_ref: identity_ref.to_hex(),
        agent_ref: agent_ref.to_hex(),
        counterparty: input.counterparty.clone(),
        payload_ref: input.payload_ref.clone(),
        received_at: input.received_at,
        foreign_inbound: input.foreign_inbound,
        claims_not_instructions,
        identity_retiring,
    };

    InboundSurfaceRouteReceipt {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        receipt_kind: INBOUND_SURFACE_RECEIPT_KIND.to_owned(),
        event_id: input.event_id,
        outcome: InboundSurfaceRouteOutcome::Routed,
        channel: input.channel,
        receiving_address_or_handle: input.receiving_address_or_handle,
        workspace_ref: input.workspace_ref,
        receiving_identity_ref: Some(identity_ref.to_hex()),
        agent_ref: Some(agent_ref.to_hex()),
        counterparty: input.counterparty,
        foreign_inbound: input.foreign_inbound,
        claims_not_instructions,
        identity_retiring,
        rejection_reason: None,
        surface_event: Some(surface_event),
    }
}

fn rejected_receipt(
    input: InboundSurfaceEventInput,
    identity_ref: Option<EntityId>,
    agent_ref: Option<EntityId>,
    identity_retiring: bool,
    claims_not_instructions: bool,
    rejection_reason: InboundSurfaceRejectionReason,
) -> InboundSurfaceRouteReceipt {
    InboundSurfaceRouteReceipt {
        schema_version: SURFACE_EVENT_SCHEMA_VERSION,
        receipt_kind: INBOUND_SURFACE_RECEIPT_KIND.to_owned(),
        event_id: input.event_id,
        outcome: InboundSurfaceRouteOutcome::Rejected,
        channel: input.channel,
        receiving_address_or_handle: input.receiving_address_or_handle,
        workspace_ref: input.workspace_ref,
        receiving_identity_ref: identity_ref.map(|id| id.to_hex()),
        agent_ref: agent_ref.map(|id| id.to_hex()),
        counterparty: input.counterparty,
        foreign_inbound: input.foreign_inbound,
        claims_not_instructions,
        identity_retiring,
        rejection_reason: Some(rejection_reason),
        surface_event: None,
    }
}

fn validate_non_blank(value: &str, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidConfig(reason.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
