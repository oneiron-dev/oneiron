//! How a declared channel identity is held, bound and fulfilled, as a seed
//! writes it (ARCH-0063). A delegated identity names its custody record,
//! never a token. Apply provisions through the identity's own lifecycle
//! gate, so a row lands only where the vault's policy lets that effect run.
//! A provisioned identity waits for fulfillment, as any other does.
use super::invalid;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityState,
    DelegatedGrant, DelegatedGrantScope, DelegatedProvisionRequest, SelfHeldShape,
};
use crate::channel_identity_lifecycle::{
    BindIntent, ChannelIdentityLifecycleActor, ChannelIdentityLifecycleGate,
    ChannelIdentityLifecycleIntent, ChannelIdentityLifecycleRequest, ProvisionIntent,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What a new identity needs beyond its channel and address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapeChannelProvision {
    pub custody: ShapeChannelCustody,
    pub binding: ShapeChannelBinding,
    /// Who completes the provisioning.
    pub fulfillment: ShapeChannelFulfillment,
}

/// Who holds the address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "held", rename_all = "snake_case")]
pub enum ShapeChannelCustody {
    /// The vault holds it, in one of the self-held shapes.
    SelfHeld { shape: ShapeSelfHeld },
    /// A member's mailbox granted through a custody record, by the record's
    /// name, with the scopes the grant covers.
    Delegated {
        custody_record_ref: String,
        scopes: Vec<ShapeMailScope>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeSelfHeld {
    DedicatedAddress,
    DedicatedHandle,
    SharedPresence,
}

impl From<ShapeSelfHeld> for SelfHeldShape {
    fn from(shape: ShapeSelfHeld) -> Self {
        match shape {
            ShapeSelfHeld::DedicatedAddress => Self::DedicatedAddress,
            ShapeSelfHeld::DedicatedHandle => Self::DedicatedHandle,
            ShapeSelfHeld::SharedPresence => Self::SharedPresence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ShapeMailScope {
    #[serde(rename = "mail.read")]
    MailRead,
    #[serde(rename = "mail.metadata")]
    MailMetadata,
    #[serde(rename = "mail.send")]
    MailSend,
}

impl From<ShapeMailScope> for DelegatedGrantScope {
    fn from(scope: ShapeMailScope) -> Self {
        match scope {
            ShapeMailScope::MailRead => Self::MailRead,
            ShapeMailScope::MailMetadata => Self::MailMetadata,
            ShapeMailScope::MailSend => Self::MailSend,
        }
    }
}

/// Whom the identity speaks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "to", rename_all = "snake_case")]
pub enum ShapeChannelBinding {
    /// An actor on the roster, by agent id, optionally wearing a facet
    /// (entity id hex) on this channel.
    Actor {
        agent_id: String,
        #[serde(default)]
        facet: Option<String>,
    },
    /// A vault, by its shared-vault id.
    Vault { vault_id: u64 },
}

impl ShapeChannelBinding {
    /// The binding, with the actor's definition read through `actor`.
    ///
    /// # Errors
    ///
    /// An actor not on the roster, or a facet that is not entity id hex.
    pub(super) fn resolve(
        &self,
        actor: impl FnOnce(&str) -> Option<EntityId>,
    ) -> Result<ChannelIdentityBinding> {
        match self {
            Self::Actor { agent_id, facet } => {
                let actor = actor(agent_id)
                    .ok_or_else(|| invalid("the identity's actor is not on the roster"))?;
                match facet {
                    Some(facet) => Ok(ChannelIdentityBinding::actor_with_facet(
                        actor,
                        EntityId::from_hex(facet)
                            .map_err(|_| invalid("a facet is named by entity id hex"))?,
                    )),
                    None => Ok(ChannelIdentityBinding::actor(actor)),
                }
            }
            Self::Vault { vault_id } => Ok(ChannelIdentityBinding::vault(*vault_id)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeChannelFulfillment {
    Api,
    Manual,
    Review,
}

impl From<ShapeChannelFulfillment> for ChannelIdentityFulfillment {
    fn from(mode: ShapeChannelFulfillment) -> Self {
        match mode {
            ShapeChannelFulfillment::Api => Self::Api,
            ShapeChannelFulfillment::Manual => Self::Manual,
            ShapeChannelFulfillment::Review => Self::Review,
        }
    }
}

impl ShapeChannelProvision {
    /// The door a new identity of this custody lands through.
    pub(super) const fn door(&self) -> &'static str {
        match self.custody {
            ShapeChannelCustody::SelfHeld { .. } => "apply_channel_identity_lifecycle_intent",
            ShapeChannelCustody::Delegated { .. } => "provision_delegated_identity",
        }
    }
}

impl Vault {
    /// Provisions the identity `channel`/`address` as `owner`. A self-held
    /// one passes the lifecycle gate's provision; a delegated one is
    /// requested against its custody record, then passes the gate's bind.
    /// The item lands once the identity waits for fulfillment.
    pub(super) fn provision_shape_channel(
        &self,
        owner: &AuthenticatedOwner,
        channel: &str,
        address: &str,
        provision: &ShapeChannelProvision,
        binding: ChannelIdentityBinding,
        now: u64,
    ) -> Result<String> {
        let actor = owner.revalidate(self)?;
        let request = |intent: ChannelIdentityLifecycleIntent| ChannelIdentityLifecycleRequest {
            actor: ChannelIdentityLifecycleActor {
                actor_class: "human".to_owned(),
                actor_ref: Some(actor.to_hex()),
                actor_entity_ref: Some(actor),
            },
            gate: ChannelIdentityLifecycleGate::allow_when_policy_grants(),
            requested_at: now,
            intent,
        };
        let fulfillment_mode = provision.fulfillment.into();
        let identity_id = EntityId::now();
        // The live row reads the vault's spelling; a row spelled otherwise
        // would never read as landed.
        let shape = match provision.custody {
            ShapeChannelCustody::SelfHeld { shape } => shape.into(),
            ShapeChannelCustody::Delegated { .. } => SelfHeldShape::DedicatedAddress,
        };
        let identity = ChannelIdentity::requested(channel, address, shape, binding, now);
        if identity.channel() != channel || identity.address_or_handle() != address {
            return Err(invalid(format!(
                "the vault spells this identity {} {}; declare it so",
                identity.channel(),
                identity.address_or_handle()
            )));
        }
        let (result, rests) = match &provision.custody {
            ShapeChannelCustody::SelfHeld { .. } => (
                self.apply_channel_identity_lifecycle_intent(request(
                    ChannelIdentityLifecycleIntent::Provision(ProvisionIntent {
                        identity_id,
                        identity,
                        fulfillment_mode,
                    }),
                ))?,
                String::new(),
            ),
            ShapeChannelCustody::Delegated {
                custody_record_ref,
                scopes,
            } => {
                self.provision_delegated_identity(
                    &identity_id,
                    DelegatedProvisionRequest {
                        channel: channel.to_owned(),
                        address_or_handle: address.to_owned(),
                        binding,
                        grant: DelegatedGrant::new(
                            custody_record_ref.clone(),
                            scopes.iter().map(|scope| (*scope).into()).collect(),
                        ),
                    },
                    now,
                )?;
                (
                    self.apply_channel_identity_lifecycle_intent(request(
                        ChannelIdentityLifecycleIntent::Bind(BindIntent {
                            identity_id,
                            fulfillment_mode,
                        }),
                    ))?,
                    format!("; identity {} waits requested", identity_id.to_hex()),
                )
            }
        };
        if result.outcome != ChannelIdentityState::PendingFulfillment.as_str() {
            return Err(invalid(format!(
                "the provision did not take: {}{rests}",
                result.owner_visible_state
            )));
        }
        Ok(result.receipt_id)
    }
}
