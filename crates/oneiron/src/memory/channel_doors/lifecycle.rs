use serde::{Deserialize, Serialize};

use super::*;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
    ChannelIdentityState, DelegatedGrant, DelegatedProvisionRequest, SelfHeldShape,
};
use crate::channel_identity_lifecycle::{
    BindIntent, ChannelIdentityFulfillmentInput, ChannelIdentityLifecycleActor,
    ChannelIdentityLifecycleGate, ChannelIdentityLifecycleIntent, ChannelIdentityLifecycleRequest,
    ChannelIdentityLifecycleResult, ProvisionIntent, ReleaseIntent, RotateIntent,
    RouteInboundIntent,
};

/// Creates an engine-held address, handle or shared presence. Delegated
/// accounts have their own bind input and cannot enter this constructor.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentityProvisionRequest {
    pub channel: String,
    pub address_or_handle: String,
    pub shape: SelfHeldShape,
    pub binding: ChannelIdentityBinding,
    pub fulfillment_mode: ChannelIdentityFulfillment,
}

/// Binds a requested row, or records custody of an existing member-held
/// account and binds it. No provider token or custody proof is a wire input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChannelIdentityBindRequest {
    Existing {
        identity_ref: EntityId,
        fulfillment_mode: ChannelIdentityFulfillment,
    },
    Delegated {
        channel: String,
        address_or_handle: String,
        binding: ChannelIdentityBinding,
        grant: DelegatedGrant,
        fulfillment_mode: ChannelIdentityFulfillment,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentityRequest {
    pub identity_ref: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentityReleaseRequest {
    pub identity_ref: EntityId,
    /// The engine enforces the manifest's quarantine floor for self-held
    /// addresses. Delegated accounts are released, never quarantined.
    pub quarantine_until: u64,
}

/// The live fact projection plus local custody and capability information.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelIdentityView {
    pub identity_ref: EntityId,
    pub channel: String,
    pub address_or_handle: String,
    pub shape: ChannelIdentityShape,
    pub binding: ChannelIdentityBinding,
    pub custody: ChannelIdentityCustody,
    pub state: ChannelIdentityState,
    pub pending_fulfillment: Option<String>,
    pub state_changed_at: u64,
    pub quarantine_until: Option<u64>,
    /// Capability preflight only. Every send still needs its live gate,
    /// grant, budget and delivery-window checks at dispatch.
    pub outbound_eligible: bool,
    pub occupies_assignment_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentityCustody {
    SelfHeld,
    Delegated,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelIdentityLifecycleReceipt {
    pub identity_ref: EntityId,
    pub receipt_ref: String,
    pub gate_receipt_ref: Option<String>,
    pub outcome: String,
    pub reason_codes: Vec<String>,
    pub owner_visible_state: String,
    pub identity: Option<ChannelIdentityView>,
    pub outbound_closed: bool,
    pub identity_retiring: bool,
}

impl Memory<'_> {
    fn channel_binding_readable(&self, binding: ChannelIdentityBinding) -> MemoryResult<()> {
        if let Some(actor) = binding.actor_ref() {
            self.channel_readable(actor)?;
        }
        if let Some(facet) = binding.facet_ref() {
            self.channel_readable(facet)?;
        }
        Ok(())
    }

    pub fn channel_identity_get(
        &self,
        input: ChannelIdentityRequest,
    ) -> MemoryResult<ChannelIdentityView> {
        self.channel_readable(input.identity_ref)?;
        let row = self
            .vault
            .get_channel_identity(&input.identity_ref)?
            .ok_or_else(|| MemoryError::not_found("channel identity not found"))?;
        self.channel_identity_view(input.identity_ref, &row)
    }

    fn channel_identity_view(
        &self,
        id: EntityId,
        row: &ChannelIdentity,
    ) -> MemoryResult<ChannelIdentityView> {
        let facts = self
            .vault
            .channel_identity_facts(&id)?
            .ok_or_else(|| MemoryError::not_found("channel identity has no live facts"))?;
        Ok(ChannelIdentityView {
            identity_ref: id,
            channel: facts.channel,
            address_or_handle: facts.address_or_handle,
            shape: facts.shape,
            binding: facts.binding,
            custody: if row.is_delegated() {
                ChannelIdentityCustody::Delegated
            } else {
                ChannelIdentityCustody::SelfHeld
            },
            state: facts.state,
            pending_fulfillment: facts.pending_fulfillment,
            state_changed_at: facts.state_changed_at,
            quarantine_until: facts.quarantine_until,
            outbound_eligible: row.may_send() && facts.state == ChannelIdentityState::Active,
            occupies_assignment_key: row.occupies_assignment_key(),
        })
    }

    fn channel_lifecycle_receipt(
        &self,
        id: EntityId,
        result: ChannelIdentityLifecycleResult,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        // A held provision has a requested snapshot, but no stored identity.
        let identity = if self.vault.get_channel_identity(&id)?.is_some() {
            result
                .identity
                .as_ref()
                .map(|row| self.channel_identity_view(id, row))
                .transpose()?
        } else {
            None
        };
        Ok(ChannelIdentityLifecycleReceipt {
            identity_ref: id,
            receipt_ref: result.receipt_id,
            gate_receipt_ref: result.gate_receipt_id,
            outcome: result.outcome,
            reason_codes: result.reason_codes,
            owner_visible_state: result.owner_visible_state,
            identity,
            outbound_closed: result.outbound_closed,
            identity_retiring: result.identity_retiring,
        })
    }

    fn channel_lifecycle_actor(
        &self,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<ChannelIdentityLifecycleActor> {
        let actor = self.channel_owner(owner)?;
        Ok(ChannelIdentityLifecycleActor {
            actor_class: "human".to_owned(),
            actor_ref: Some(actor.to_hex()),
            actor_entity_ref: Some(actor),
        })
    }

    fn channel_lifecycle_as(
        &self,
        owner: &AuthenticatedOwner,
        intent: ChannelIdentityLifecycleIntent,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        let actor = self.channel_lifecycle_actor(owner)?;
        let id = intent.identity_id();
        let result = self.vault.apply_channel_identity_lifecycle_intent(
            ChannelIdentityLifecycleRequest {
                actor,
                // Opt-in and permission come from the owner's live proof, not
                // request flags. The existing ExternalEffect gate still decides.
                gate: ChannelIdentityLifecycleGate::allow_when_policy_grants(),
                requested_at: self.vault.now_recorded_at(),
                intent,
            },
        )?;
        self.channel_lifecycle_receipt(id, result)
    }

    pub fn channel_identity_provision_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ChannelIdentityProvisionRequest,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        self.channel_owner(owner)?;
        self.channel_binding_readable(input.binding)?;
        let identity_id = self.vault.store.clock.entity_id()?;
        let identity = ChannelIdentity::requested(
            input.channel,
            input.address_or_handle,
            input.shape,
            input.binding,
            self.vault.now_recorded_at(),
        );
        self.channel_lifecycle_as(
            owner,
            ChannelIdentityLifecycleIntent::Provision(ProvisionIntent {
                identity_id,
                identity,
                fulfillment_mode: input.fulfillment_mode,
            }),
        )
    }

    pub fn channel_identity_bind_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ChannelIdentityBindRequest,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        self.channel_owner(owner)?;
        let (identity_id, fulfillment_mode) = match input {
            ChannelIdentityBindRequest::Existing {
                identity_ref,
                fulfillment_mode,
            } => {
                self.channel_readable(identity_ref)?;
                (identity_ref, fulfillment_mode)
            }
            ChannelIdentityBindRequest::Delegated {
                channel,
                address_or_handle,
                binding,
                grant,
                fulfillment_mode,
            } => {
                self.channel_binding_readable(binding)?;
                let id = self.vault.store.clock.entity_id()?;
                self.vault.provision_delegated_identity(
                    &id,
                    DelegatedProvisionRequest {
                        channel,
                        address_or_handle,
                        binding,
                        grant,
                    },
                    self.vault.now_recorded_at(),
                )?;
                (id, fulfillment_mode)
            }
        };
        self.channel_lifecycle_as(
            owner,
            ChannelIdentityLifecycleIntent::Bind(BindIntent {
                identity_id,
                fulfillment_mode,
            }),
        )
    }

    pub fn channel_identity_fulfill_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ChannelIdentityRequest,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        let actor = self.channel_lifecycle_actor(owner)?;
        self.channel_readable(input.identity_ref)?;
        let result = self
            .vault
            .fulfill_channel_identity(ChannelIdentityFulfillmentInput {
                actor,
                identity_id: input.identity_ref,
                fulfilled_at: self.vault.now_recorded_at(),
            })?;
        self.channel_lifecycle_receipt(input.identity_ref, result)
    }

    pub fn channel_identity_rotate_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ChannelIdentityRequest,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        self.channel_readable(input.identity_ref)?;
        self.channel_lifecycle_as(
            owner,
            ChannelIdentityLifecycleIntent::Rotate(RotateIntent {
                identity_id: input.identity_ref,
            }),
        )
    }

    pub fn channel_identity_release_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ChannelIdentityReleaseRequest,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        self.channel_readable(input.identity_ref)?;
        self.channel_lifecycle_as(
            owner,
            ChannelIdentityLifecycleIntent::Release(ReleaseIntent {
                identity_id: input.identity_ref,
                quarantine_until: input.quarantine_until,
            }),
        )
    }

    pub fn channel_identity_route_inbound_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ChannelIdentityRequest,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        self.channel_readable(input.identity_ref)?;
        self.channel_lifecycle_as(
            owner,
            ChannelIdentityLifecycleIntent::RouteInbound(RouteInboundIntent {
                identity_id: input.identity_ref,
            }),
        )
    }
}
