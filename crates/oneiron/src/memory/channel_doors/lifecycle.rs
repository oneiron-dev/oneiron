use serde::{Deserialize, Serialize};

use super::*;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
    ChannelIdentityState, DelegatedGrant, DelegatedProvisionRequest, SelfHeldShape,
};
use crate::channel_identity_lifecycle::{
    BindIntent, ChannelIdentityFulfillmentInput, ChannelIdentityLifecycleActor,
    ChannelIdentityLifecycleGate, ChannelIdentityLifecycleIntent, ChannelIdentityLifecycleRequest,
    ChannelIdentityLifecycleResult, ChannelIdentityLifecycleVerb, LifecycleApplied, LifecycleCall,
    LifecycleCallState, ProvisionIntent, RecordedIdentityView, ReleaseIntent, RotateIntent,
    RouteInboundIntent, lifecycle_input_digest,
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

    /// FIX 6424 part 3: the lifecycle request this call names, kept before
    /// its ask: `request_ref`, else the one its host's invocation fixes for
    /// this input, else a fresh one, with the identity `mint` gives a new
    /// request. A completed one answers the receipt it answered then; a ref
    /// that names another request (another owner, verb or input) is refused.
    fn channel_lifecycle_call(
        &self,
        actor: EntityId,
        verb: ChannelIdentityLifecycleVerb,
        request_ref: Option<EntityId>,
        input: &impl Serialize,
        mint: impl Fn() -> crate::error::Result<(EntityId, u64)>,
    ) -> MemoryResult<DoorCall> {
        let LifecycleCall { request_ref, state } = self.vault.begin_channel_identity_lifecycle(
            actor,
            verb.as_str(),
            request_ref,
            self.invocation(),
            lifecycle_input_digest(verb.as_str(), input),
            mint,
        )?;
        match state {
            LifecycleCallState::Ready {
                identity_id,
                requested_at,
            } => Ok(DoorCall::Ready {
                request_ref,
                identity_id,
                requested_at,
            }),
            LifecycleCallState::Completed {
                identity_id,
                result,
                view,
            } => Ok(DoorCall::Answered(Box::new(recorded_receipt(
                identity_id,
                *result,
                view,
            )))),
            LifecycleCallState::Conflict => Err(MemoryError::bad_request(
                "request_ref names another channel identity lifecycle request",
            )),
        }
    }

    /// A fresh identity id and the time it is requested at.
    fn channel_lifecycle_mint(&self) -> crate::error::Result<(EntityId, u64)> {
        Ok((
            self.vault.store.clock.entity_id()?,
            self.vault.now_recorded_at(),
        ))
    }

    fn channel_lifecycle_as(
        &self,
        owner: &AuthenticatedOwner,
        request_ref: EntityId,
        intent: ChannelIdentityLifecycleIntent,
    ) -> MemoryResult<ChannelIdentityLifecycleReceipt> {
        let actor = self.channel_lifecycle_actor(owner)?;
        let id = intent.identity_id();
        // FIX 6424 part 3: the Gate pins this request by its ref, kept
        // before this ask.
        let applied = self.vault.apply_channel_identity_lifecycle_gated(
            ChannelIdentityLifecycleRequest {
                actor,
                // Opt-in and permission come from the owner's live proof, not
                // request flags. The existing ExternalEffect gate still decides.
                gate: ChannelIdentityLifecycleGate::allow_when_policy_grants(),
                requested_at: self.vault.now_recorded_at(),
                intent,
            },
            Some(request_ref),
        )?;
        match applied {
            LifecycleApplied::Applied(result) => self.channel_lifecycle_receipt(id, result),
            LifecycleApplied::Replayed(result, view) => Ok(recorded_receipt(id, result, view)),
        }
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
            || self.channel_lifecycle_mint(),
        )?;
        // FIX 6424 part 3: a retry of a kept request rebuilds the identity
        // it first requested, under the id it was given.
        let (request_ref, identity_id, requested_at) = match call {
            DoorCall::Ready {
                request_ref,
                identity_id,
                requested_at,
            } => (request_ref, identity_id, requested_at),
            DoorCall::Answered(receipt) => return Ok(*receipt),
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
            request_ref,
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
        let existing = match &input {
            ChannelIdentityBindRequest::Existing { identity_ref, .. } => Some(*identity_ref),
            ChannelIdentityBindRequest::Delegated { .. } => None,
        };
        // A delegated bind's request is given a fresh id for the row it
        // provisions; an existing one's names its row.
        let call = self.channel_lifecycle_call(
            actor,
            ChannelIdentityLifecycleVerb::Bind,
            input.request_ref(),
            &input,
            || match existing {
                Some(id) => Ok((id, self.vault.now_recorded_at())),
                None => self.channel_lifecycle_mint(),
            },
        )?;
        let (request_ref, identity_id, requested_at) = match call {
            DoorCall::Ready {
                request_ref,
                identity_id,
                requested_at,
            } => (request_ref, identity_id, requested_at),
            DoorCall::Answered(receipt) => return Ok(*receipt),
        };
        let fulfillment_mode = match input {
            ChannelIdentityBindRequest::Existing {
                fulfillment_mode, ..
            } => fulfillment_mode,
            ChannelIdentityBindRequest::Delegated {
                channel,
                address_or_handle,
                binding,
                grant,
                fulfillment_mode,
                ..
            } => {
                // FIX 6424 part 3: a retry of a kept delegated bind binds the
                // row its first call provisioned; it is never provisioned
                // twice.
                let provisioned = self
                    .vault
                    .get_channel_identity(&identity_id)
                    .ok()
                    .flatten()
                    .is_some();
                if !provisioned {
                    self.vault.provision_delegated_identity(
                        &identity_id,
                        DelegatedProvisionRequest {
                            channel,
                            address_or_handle,
                            binding,
                            grant,
                        },
                        requested_at,
                    )?;
                }
                fulfillment_mode
            }
        };
        self.channel_lifecycle_as(
            owner,
            request_ref,
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
        let id = intent.identity_id();
        let call = self.channel_lifecycle_call(actor, verb, request_ref, input, || {
            Ok((id, self.vault.now_recorded_at()))
        })?;
        match call {
            DoorCall::Ready { request_ref, .. } => {
                self.channel_lifecycle_as(owner, request_ref, intent)
            }
            DoorCall::Answered(receipt) => Ok(*receipt),
        }
    }
}

/// One lifecycle door call, as its request stood before its ask (FIX 6424
/// part 3).
enum DoorCall {
    /// To be gated as `request_ref`, with the identity it was given and when
    /// that identity was requested.
    Ready {
        request_ref: EntityId,
        identity_id: EntityId,
        requested_at: u64,
    },
    /// Its request completed: the receipt it answered then.
    Answered(Box<ChannelIdentityLifecycleReceipt>),
}

/// The receipt a completed request answered, exactly as it was returned:
/// the identity as that apply committed it, no live read.
fn recorded_receipt(
    id: EntityId,
    result: ChannelIdentityLifecycleResult,
    view: Option<RecordedIdentityView>,
) -> ChannelIdentityLifecycleReceipt {
    ChannelIdentityLifecycleReceipt {
        identity_ref: id,
        receipt_ref: result.receipt_id,
        gate_receipt_ref: result.gate_receipt_id,
        outcome: result.outcome,
        reason_codes: result.reason_codes,
        owner_visible_state: result.owner_visible_state,
        identity: view.map(|view| ChannelIdentityView {
            identity_ref: id,
            channel: view.channel,
            address_or_handle: view.address_or_handle,
            shape: view.shape,
            binding: view.binding,
            custody: if view.delegated {
                ChannelIdentityCustody::Delegated
            } else {
                ChannelIdentityCustody::SelfHeld
            },
            state: view.state,
            pending_fulfillment: view.pending_fulfillment,
            state_changed_at: view.state_changed_at,
            quarantine_until: view.quarantine_until,
            outbound_eligible: view.outbound_eligible,
            occupies_assignment_key: view.occupies_assignment_key,
        }),
        outbound_closed: result.outbound_closed,
        identity_retiring: result.identity_retiring,
        approval_digest: result.approval_digest,
        request_ref: result.request_ref,
    }
}
