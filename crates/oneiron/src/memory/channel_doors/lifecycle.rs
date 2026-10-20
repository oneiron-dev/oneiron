use serde::{Deserialize, Serialize};

use super::*;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
    ChannelIdentityState, DelegatedGrant, DelegatedProvisionRequest, SelfHeldShape,
};
use crate::channel_identity_lifecycle::{
    BindIntent, ChannelIdentityFulfillmentInput, ChannelIdentityLifecycleActor,
    ChannelIdentityLifecycleGate, ChannelIdentityLifecycleIntent, ChannelIdentityLifecycleRequest,
    ChannelIdentityLifecycleResult, ChannelIdentityLifecycleVerb, LifecycleCall,
    LifecycleCallState, ProvisionIntent, ReleaseIntent, RotateIntent, RouteInboundIntent,
    lifecycle_input_digest,
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
    /// FIX 6424 part 3 (CALLS `FIX 6424 lifecycle retry token`): the
    /// `request_ref` an earlier receipt of this same request named, to retry
    /// exactly that request (one that completed answers its recorded
    /// receipt). Omitted, the call is a request of its own, keyed by its
    /// host's invocation id when it names one, else by a fresh ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<EntityId>,
}

/// Binds a requested row, or records custody of an existing member-held
/// account and binds it. No provider token or custody proof is a wire input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChannelIdentityBindRequest {
    Existing {
        identity_ref: EntityId,
        fulfillment_mode: ChannelIdentityFulfillment,
        /// FIX 6424 part 3 (CALLS `FIX 6424 lifecycle retry token`): the
        /// `request_ref` an earlier receipt of this same request named, to retry
        /// exactly that request (one that completed answers its recorded
        /// receipt). Omitted, the call is a request of its own, keyed by its
        /// host's invocation id when it names one, else by a fresh ref.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_ref: Option<EntityId>,
    },
    Delegated {
        channel: String,
        address_or_handle: String,
        binding: ChannelIdentityBinding,
        grant: DelegatedGrant,
        fulfillment_mode: ChannelIdentityFulfillment,
        /// FIX 6424 part 3: as on `existing`. A retry of a delegated bind
        /// binds the row its first call provisioned, never another.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_ref: Option<EntityId>,
    },
}

impl ChannelIdentityBindRequest {
    /// The request ref this bind names, if any (FIX 6424 part 3).
    fn request_ref(&self) -> Option<EntityId> {
        match self {
            Self::Existing { request_ref, .. } | Self::Delegated { request_ref, .. } => {
                *request_ref
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentityRequest {
    pub identity_ref: EntityId,
    /// FIX 6424 part 3: on `rotate` and `route_inbound`, the `request_ref`
    /// an earlier receipt of this same request named, to retry exactly that
    /// request (one that completed answers its recorded receipt); omitted,
    /// the call is a request of its own (its host's invocation id, else a
    /// fresh ref). `get` and `fulfill` read none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentityReleaseRequest {
    pub identity_ref: EntityId,
    /// The engine enforces the manifest's quarantine floor for self-held
    /// addresses. Delegated accounts are released, never quarantined.
    pub quarantine_until: u64,
    /// FIX 6424 part 3 (CALLS `FIX 6424 lifecycle retry token`): the
    /// `request_ref` an earlier receipt of this same request named, to retry
    /// exactly that request (one that completed answers its recorded
    /// receipt). Omitted, the call is a request of its own, keyed by its
    /// host's invocation id when it names one, else by a fresh ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<EntityId>,
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
    /// FIX 6424 part 3: while the Gate holds the request, the approve-once
    /// digest (64 lower-hex) the owner presses to release exactly this
    /// request; a retry naming `request_ref` is then let through. Absent
    /// otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_digest: Option<String>,
    /// FIX 6424 part 3: the request's ref, which a retry of exactly this
    /// request names. Absent on `fulfill`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<EntityId>,
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
            approval_digest: result.approval_digest,
            request_ref: result.request_ref,
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

    /// FIX 6424 part 3: the lifecycle request this call names, resolved
    /// before its ask: `request_ref`, else the one its host's invocation
    /// fixes for this input, else a fresh one. A ref that names another
    /// request (another owner, verb or input) is refused.
    fn channel_lifecycle_call(
        &self,
        actor: EntityId,
        verb: ChannelIdentityLifecycleVerb,
        request_ref: Option<EntityId>,
        input: &impl Serialize,
    ) -> MemoryResult<LifecycleCall> {
        let call = self.vault.channel_identity_lifecycle_call(
            actor,
            verb.as_str(),
            request_ref,
            self.invocation(),
            lifecycle_input_digest(verb.as_str(), input),
        );
        if matches!(call.state, LifecycleCallState::Conflict) {
            return Err(MemoryError::bad_request(
                "request_ref names another channel identity lifecycle request",
            ));
        }
        Ok(call)
    }

    /// The recorded receipt a completed request answers again, if `call`'s
    /// request completed: nothing applies twice.
    fn channel_lifecycle_replay(
        &self,
        call: &LifecycleCall,
    ) -> Option<MemoryResult<ChannelIdentityLifecycleReceipt>> {
        match &call.state {
            LifecycleCallState::Completed {
                identity_id,
                result,
            } => Some(self.channel_lifecycle_receipt(*identity_id, (**result).clone())),
            _ => None,
        }
    }

    fn channel_lifecycle_as(
        &self,
        owner: &AuthenticatedOwner,
        call: &LifecycleCall,
        requested_at: u64,
        intent: ChannelIdentityLifecycleIntent,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        let actor = self.channel_lifecycle_actor(owner)?;
        let id = intent.identity_id();
        // FIX 6424 part 3: the Gate pins this request by its ref.
        let result = self.vault.apply_channel_identity_lifecycle_request(
            ChannelIdentityLifecycleRequest {
                actor,
                // Opt-in and permission come from the owner's live proof, not
                // request flags. The existing ExternalEffect gate still decides.
                gate: ChannelIdentityLifecycleGate::allow_when_policy_grants(),
                requested_at: self.vault.now_recorded_at(),
                intent,
            },
            call.request_ref,
        )?;
        self.vault
            .keep_channel_identity_lifecycle_request(call, id, requested_at, &result)?;
        self.channel_lifecycle_receipt(id, result)
    }

    pub fn channel_identity_provision_as(
        &self,
        owner: &AuthenticatedOwner,
        input: ChannelIdentityProvisionRequest,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        let actor = self.channel_owner(owner)?;
        self.channel_binding_readable(input.binding)?;
        let call = self.channel_lifecycle_call(
            actor,
            ChannelIdentityLifecycleVerb::Provision,
            input.request_ref,
            &input,
        )?;
        if let Some(replay) = self.channel_lifecycle_replay(&call) {
            return replay;
        }
        // FIX 6424 part 3: a retry of a kept request rebuilds the identity
        // it first requested, under the id it was given.
        let (identity_id, requested_at) = match &call.state {
            LifecycleCallState::Retained {
                identity_id,
                requested_at,
            } => (*identity_id, *requested_at),
            _ => (
                self.vault.store.clock.entity_id()?,
                self.vault.now_recorded_at(),
            ),
        };
        let identity = ChannelIdentity::requested(
            input.channel,
            input.address_or_handle,
            input.shape,
            input.binding,
            requested_at,
        );
        self.channel_lifecycle_as(
            owner,
            &call,
            requested_at,
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
        let actor = self.channel_owner(owner)?;
        match &input {
            ChannelIdentityBindRequest::Existing { identity_ref, .. } => {
                self.channel_readable(*identity_ref)?;
            }
            ChannelIdentityBindRequest::Delegated { binding, .. } => {
                self.channel_binding_readable(*binding)?;
            }
        }
        let call = self.channel_lifecycle_call(
            actor,
            ChannelIdentityLifecycleVerb::Bind,
            input.request_ref(),
            &input,
        )?;
        if let Some(replay) = self.channel_lifecycle_replay(&call) {
            return replay;
        }
        let kept = match &call.state {
            LifecycleCallState::Retained {
                identity_id,
                requested_at,
            } => Some((*identity_id, *requested_at)),
            _ => None,
        };
        let (identity_id, requested_at, fulfillment_mode) = match (input, kept) {
            (
                ChannelIdentityBindRequest::Existing {
                    identity_ref,
                    fulfillment_mode,
                    ..
                },
                kept,
            ) => (
                identity_ref,
                kept.map_or_else(|| self.vault.now_recorded_at(), |(_, at)| at),
                fulfillment_mode,
            ),
            // FIX 6424 part 3: a retry of a kept delegated bind binds the row
            // its first call provisioned; it is never provisioned twice.
            (
                ChannelIdentityBindRequest::Delegated {
                    fulfillment_mode, ..
                },
                Some((id, at)),
            ) => (id, at, fulfillment_mode),
            (
                ChannelIdentityBindRequest::Delegated {
                    channel,
                    address_or_handle,
                    binding,
                    grant,
                    fulfillment_mode,
                    ..
                },
                None,
            ) => {
                let id = self.vault.store.clock.entity_id()?;
                let at = self.vault.now_recorded_at();
                self.vault.provision_delegated_identity(
                    &id,
                    DelegatedProvisionRequest {
                        channel,
                        address_or_handle,
                        binding,
                        grant,
                    },
                    at,
                )?;
                (id, at, fulfillment_mode)
            }
        };
        self.channel_lifecycle_as(
            owner,
            &call,
            requested_at,
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
        self.channel_lifecycle_on(
            owner,
            ChannelIdentityLifecycleVerb::Rotate,
            input.request_ref,
            &input,
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
        self.channel_lifecycle_on(
            owner,
            ChannelIdentityLifecycleVerb::Release,
            input.request_ref,
            &input,
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
        self.channel_lifecycle_on(
            owner,
            ChannelIdentityLifecycleVerb::RouteInbound,
            input.request_ref,
            &input,
            ChannelIdentityLifecycleIntent::RouteInbound(RouteInboundIntent {
                identity_id: input.identity_ref,
            }),
        )
    }

    /// A lifecycle verb on an existing identity (rotate, release, route
    /// inbound) as the request this call names (FIX 6424 part 3): a
    /// completed one answers its recorded receipt, any other is gated.
    fn channel_lifecycle_on(
        &self,
        owner: &AuthenticatedOwner,
        verb: ChannelIdentityLifecycleVerb,
        request_ref: Option<EntityId>,
        input: &impl Serialize,
        intent: ChannelIdentityLifecycleIntent,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        let actor = self.channel_owner(owner)?;
        let call = self.channel_lifecycle_call(actor, verb, request_ref, input)?;
        if let Some(replay) = self.channel_lifecycle_replay(&call) {
            return replay;
        }
        let requested_at = match &call.state {
            LifecycleCallState::Retained { requested_at, .. } => *requested_at,
            _ => self.vault.now_recorded_at(),
        };
        self.channel_lifecycle_as(owner, &call, requested_at, intent)
    }
}
