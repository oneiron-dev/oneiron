//! ChannelIdentity lifecycle verbs through the ExternalEffect door (OF-347 CID-2).

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityFulfillment, ChannelIdentityState,
    decode_channel_identity_body, encode_channel_identity_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{
    self, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles,
};
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::{ChannelIdentityLifecycleReceiptId, ChannelIdentityLifecycleReceiptRecord};

/// Actor context used for identity lifecycle effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityLifecycleActor {
    pub actor_class: String,
    pub actor_ref: Option<String>,
    pub actor_entity_ref: Option<EntityId>,
}

impl ChannelIdentityLifecycleActor {
    #[must_use]
    pub fn agent(agent_ref: EntityId) -> Self {
        Self {
            actor_class: "agent".to_owned(),
            actor_ref: Some(agent_ref.to_hex()),
            actor_entity_ref: Some(agent_ref),
        }
    }

    fn gate_actor(&self) -> GateActor {
        GateActor {
            actor_class: self.actor_class.clone(),
            actor_ref: self.actor_ref.clone(),
        }
    }

    fn provenance(&self, identity_id: EntityId) -> GateProvenanceHandles {
        GateProvenanceHandles {
            actor_entity_ref: self.actor_entity_ref,
            substrate_ref: Some(identity_id),
            ..GateProvenanceHandles::default()
        }
    }
}

/// ExternalEffect risk dial for identity lifecycle verbs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityLifecyclePolicyRisk {
    #[default]
    Normal,
    HoldToProposal,
}

impl ChannelIdentityLifecyclePolicyRisk {
    const fn to_gate(self) -> ExternalEffectPolicyRisk {
        match self {
            Self::Normal => ExternalEffectPolicyRisk::Normal,
            Self::HoldToProposal => ExternalEffectPolicyRisk::HoldToProposal,
        }
    }
}

/// Gate inputs common to all CID-2 ExternalEffect verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelIdentityLifecycleGate {
    pub has_opted_in: bool,
    pub has_permission: bool,
    pub policy_risk: ChannelIdentityLifecyclePolicyRisk,
}

impl ChannelIdentityLifecycleGate {
    #[must_use]
    pub const fn allow_when_policy_grants() -> Self {
        Self {
            has_opted_in: true,
            has_permission: true,
            policy_risk: ChannelIdentityLifecyclePolicyRisk::Normal,
        }
    }
}

/// Stable CID-2 lifecycle verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityLifecycleVerb {
    Provision,
    Bind,
    Rotate,
    Release,
    RouteInbound,
}

impl ChannelIdentityLifecycleVerb {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::Bind => "bind",
            Self::Rotate => "rotate",
            Self::Release => "release",
            Self::RouteInbound => "route_inbound",
        }
    }

    #[must_use]
    pub const fn intent_kind(self) -> &'static str {
        match self {
            Self::Provision => "ProvisionIntent",
            Self::Bind => "BindIntent",
            Self::Rotate => "RotateIntent",
            Self::Release => "ReleaseIntent",
            Self::RouteInbound => "RouteInboundIntent",
        }
    }
}

/// Provision a new identity row and enter async fulfillment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionIntent {
    pub identity_id: EntityId,
    pub identity: ChannelIdentity,
    pub fulfillment_mode: ChannelIdentityFulfillment,
}

/// Bind an existing requested identity and enter async fulfillment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindIntent {
    pub identity_id: EntityId,
    pub fulfillment_mode: ChannelIdentityFulfillment,
}

/// Rotate an active identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotateIntent {
    pub identity_id: EntityId,
}

/// Release an identity into quarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseIntent {
    pub identity_id: EntityId,
    pub quarantine_until: u64,
}

/// Route inbound traffic for an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInboundIntent {
    pub identity_id: EntityId,
}

/// Typed CID-2 intent emitted through the ExternalEffect door.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChannelIdentityLifecycleIntent {
    Provision(ProvisionIntent),
    Bind(BindIntent),
    Rotate(RotateIntent),
    Release(ReleaseIntent),
    RouteInbound(RouteInboundIntent),
}

impl ChannelIdentityLifecycleIntent {
    #[must_use]
    pub const fn verb(&self) -> ChannelIdentityLifecycleVerb {
        match self {
            Self::Provision(_) => ChannelIdentityLifecycleVerb::Provision,
            Self::Bind(_) => ChannelIdentityLifecycleVerb::Bind,
            Self::Rotate(_) => ChannelIdentityLifecycleVerb::Rotate,
            Self::Release(_) => ChannelIdentityLifecycleVerb::Release,
            Self::RouteInbound(_) => ChannelIdentityLifecycleVerb::RouteInbound,
        }
    }

    #[must_use]
    pub const fn identity_id(&self) -> EntityId {
        match self {
            Self::Provision(intent) => intent.identity_id,
            Self::Bind(intent) => intent.identity_id,
            Self::Rotate(intent) => intent.identity_id,
            Self::Release(intent) => intent.identity_id,
            Self::RouteInbound(intent) => intent.identity_id,
        }
    }
}

/// Request envelope for a CID-2 lifecycle verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityLifecycleRequest {
    pub actor: ChannelIdentityLifecycleActor,
    pub gate: ChannelIdentityLifecycleGate,
    pub requested_at: u64,
    pub intent: ChannelIdentityLifecycleIntent,
}

/// Completion marker for ops/manual/API fulfillment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityFulfillmentInput {
    pub actor: ChannelIdentityLifecycleActor,
    pub identity_id: EntityId,
    pub fulfilled_at: u64,
}

/// Result of applying or holding a lifecycle verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityLifecycleResult {
    pub receipt_id: String,
    pub gate_receipt_id: Option<String>,
    pub outcome: String,
    pub reason_codes: Vec<String>,
    pub owner_visible_state: String,
    pub identity: Option<ChannelIdentity>,
    pub outbound_closed: bool,
    pub identity_retiring: bool,
}

struct LifecycleReceiptInput {
    identity_id: EntityId,
    actor: ChannelIdentityLifecycleActor,
    verb: String,
    intent_kind: String,
    outcome: String,
    gate_decision_id: Option<crate::store::GateDecisionId>,
    channel: String,
    address_or_handle: String,
    state: String,
    fulfillment_mode: Option<String>,
    owner_visible_state: String,
    outbound_closed: bool,
    identity_retiring: bool,
    quarantine_until: Option<u64>,
}

struct AppliedLifecycle {
    identity: Option<ChannelIdentity>,
    outcome: &'static str,
    owner_visible_state: &'static str,
    outbound_closed: bool,
    identity_retiring: bool,
}

impl Vault {
    /// Evaluates a typed identity lifecycle intent through the ExternalEffect gate.
    pub fn apply_channel_identity_lifecycle_intent(
        &self,
        request: ChannelIdentityLifecycleRequest,
    ) -> Result<ChannelIdentityLifecycleResult> {
        let identity_id = request.intent.identity_id();
        let mut wtxn = self.store.env.write_txn()?;
        let snapshot = match &request.intent {
            ChannelIdentityLifecycleIntent::Provision(intent) => intent.identity.clone(),
            _ => self.read_channel_identity_in_txn(&wtxn, &identity_id)?,
        };
        let policy = gate::resolve_policy_manifest(&self.store, &wtxn)?;
        let effect = ExternalEffectGateInput {
            actor: request.actor.gate_actor(),
            provenance: request.actor.provenance(identity_id),
            verb: request.intent.verb().as_str().to_owned(),
            channel: snapshot.channel.clone(),
            channel_identity_ref: Some(identity_id),
            counterparty: None,
            brief_ref: None,
            send_ref: None,
            standing_grant_ref: None,
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: request.gate.has_opted_in,
            has_permission: request.gate.has_permission,
            policy_risk: request.gate.policy_risk.to_gate(),
        };
        let (gate_decision_id, decision) =
            gate::check_external_effect_policy(&self.store, &mut wtxn, &effect, &policy)?;
        let reason_codes = decision
            .reason_codes()
            .iter()
            .map(|code| code.as_str().to_owned())
            .collect::<Vec<_>>();

        let applied = match decision.outcome() {
            GateOutcome::Allow => self.apply_allowed_lifecycle_intent(
                &mut wtxn,
                &request.intent,
                request.requested_at,
            )?,
            GateOutcome::Pending => AppliedLifecycle {
                identity: Some(snapshot.clone()),
                outcome: "held",
                owner_visible_state: "held",
                outbound_closed: false,
                identity_retiring: false,
            },
            GateOutcome::Deny => AppliedLifecycle {
                identity: Some(snapshot.clone()),
                outcome: "denied",
                owner_visible_state: "denied",
                outbound_closed: false,
                identity_retiring: false,
            },
        };

        let receipt_identity = applied.identity.as_ref().unwrap_or(&snapshot);
        let receipt = self.append_channel_identity_lifecycle_receipt_in_txn(
            &mut wtxn,
            request.requested_at,
            LifecycleReceiptInput {
                identity_id,
                actor: request.actor,
                verb: request.intent.verb().as_str().to_owned(),
                intent_kind: request.intent.verb().intent_kind().to_owned(),
                outcome: applied.outcome.to_owned(),
                gate_decision_id: Some(gate_decision_id),
                channel: receipt_identity.channel.clone(),
                address_or_handle: receipt_identity.address_or_handle.clone(),
                state: receipt_identity.state.as_str().to_owned(),
                fulfillment_mode: receipt_identity
                    .pending_fulfillment
                    .map(|mode| mode.as_str().to_owned()),
                owner_visible_state: applied.owner_visible_state.to_owned(),
                outbound_closed: applied.outbound_closed,
                identity_retiring: applied.identity_retiring,
                quarantine_until: receipt_identity.quarantine_until,
            },
        )?;
        wtxn.commit()?;

        Ok(ChannelIdentityLifecycleResult {
            receipt_id: lifecycle_receipt_ref(receipt.receipt_id),
            gate_receipt_id: Some(format!("gate:{}", gate_decision_id.to_hex())),
            outcome: receipt.outcome,
            reason_codes,
            owner_visible_state: receipt.owner_visible_state,
            identity: applied.identity,
            outbound_closed: receipt.outbound_closed,
            identity_retiring: receipt.identity_retiring,
        })
    }

    /// Marks a pending or rotating identity fulfilled and receipts the transition to ACTIVE.
    pub fn fulfill_channel_identity(
        &self,
        input: ChannelIdentityFulfillmentInput,
    ) -> Result<ChannelIdentityLifecycleResult> {
        let mut wtxn = self.store.env.write_txn()?;
        let current = self.read_channel_identity_in_txn(&wtxn, &input.identity_id)?;
        let next = match current.state {
            ChannelIdentityState::PendingFulfillment | ChannelIdentityState::Rotating => {
                current.transition(ChannelIdentityState::Active, None, input.fulfilled_at, None)?
            }
            _ => {
                return Err(Error::InvalidChannelIdentityBody(
                    "identity is not awaiting fulfillment",
                ));
            }
        };
        self.write_existing_channel_identity_in_txn(&mut wtxn, &input.identity_id, &next)?;

        let receipt = self.append_channel_identity_lifecycle_receipt_in_txn(
            &mut wtxn,
            input.fulfilled_at,
            LifecycleReceiptInput {
                identity_id: input.identity_id,
                actor: input.actor,
                verb: "fulfill".to_owned(),
                intent_kind: "FulfillmentReceipt".to_owned(),
                outcome: ChannelIdentityState::Active.as_str().to_owned(),
                gate_decision_id: None,
                channel: next.channel.clone(),
                address_or_handle: next.address_or_handle.clone(),
                state: next.state.as_str().to_owned(),
                fulfillment_mode: None,
                owner_visible_state: ChannelIdentityState::Active.as_str().to_owned(),
                outbound_closed: false,
                identity_retiring: false,
                quarantine_until: None,
            },
        )?;
        wtxn.commit()?;

        Ok(ChannelIdentityLifecycleResult {
            receipt_id: lifecycle_receipt_ref(receipt.receipt_id),
            gate_receipt_id: None,
            outcome: receipt.outcome,
            reason_codes: Vec::new(),
            owner_visible_state: receipt.owner_visible_state,
            identity: Some(next),
            outbound_closed: receipt.outbound_closed,
            identity_retiring: receipt.identity_retiring,
        })
    }

    fn apply_allowed_lifecycle_intent(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        intent: &ChannelIdentityLifecycleIntent,
        at: u64,
    ) -> Result<AppliedLifecycle> {
        match intent {
            ChannelIdentityLifecycleIntent::Provision(intent) => {
                let next = intent.identity.transition(
                    ChannelIdentityState::PendingFulfillment,
                    Some(intent.fulfillment_mode),
                    at,
                    None,
                )?;
                self.create_channel_identity_in_txn(wtxn, &intent.identity_id, &next)?;
                Ok(AppliedLifecycle {
                    identity: Some(next),
                    outcome: ChannelIdentityState::PendingFulfillment.as_str(),
                    owner_visible_state: ChannelIdentityState::PendingFulfillment.as_str(),
                    outbound_closed: false,
                    identity_retiring: false,
                })
            }
            ChannelIdentityLifecycleIntent::Bind(intent) => {
                let current = self.read_channel_identity_in_txn(wtxn, &intent.identity_id)?;
                let next = current.transition(
                    ChannelIdentityState::PendingFulfillment,
                    Some(intent.fulfillment_mode),
                    at,
                    None,
                )?;
                self.write_existing_channel_identity_in_txn(wtxn, &intent.identity_id, &next)?;
                Ok(AppliedLifecycle {
                    identity: Some(next),
                    outcome: ChannelIdentityState::PendingFulfillment.as_str(),
                    owner_visible_state: ChannelIdentityState::PendingFulfillment.as_str(),
                    outbound_closed: false,
                    identity_retiring: false,
                })
            }
            ChannelIdentityLifecycleIntent::Rotate(intent) => {
                let current = self.read_channel_identity_in_txn(wtxn, &intent.identity_id)?;
                let next = current.transition(ChannelIdentityState::Rotating, None, at, None)?;
                self.write_existing_channel_identity_in_txn(wtxn, &intent.identity_id, &next)?;
                Ok(AppliedLifecycle {
                    identity: Some(next),
                    outcome: ChannelIdentityState::Rotating.as_str(),
                    owner_visible_state: ChannelIdentityState::Rotating.as_str(),
                    outbound_closed: false,
                    identity_retiring: false,
                })
            }
            ChannelIdentityLifecycleIntent::Release(intent) => {
                let current = self.read_channel_identity_in_txn(wtxn, &intent.identity_id)?;
                let released =
                    current.transition(ChannelIdentityState::Released, None, at, None)?;
                let next = released.transition(
                    ChannelIdentityState::Quarantine,
                    None,
                    at,
                    Some(intent.quarantine_until),
                )?;
                self.write_existing_channel_identity_in_txn(wtxn, &intent.identity_id, &next)?;
                Ok(AppliedLifecycle {
                    identity: Some(next),
                    outcome: ChannelIdentityState::Quarantine.as_str(),
                    owner_visible_state: "identity_retiring",
                    outbound_closed: true,
                    identity_retiring: true,
                })
            }
            ChannelIdentityLifecycleIntent::RouteInbound(intent) => {
                let current = self.read_channel_identity_in_txn(wtxn, &intent.identity_id)?;
                let (outcome, owner_visible_state, outbound_closed, identity_retiring) =
                    match current.state {
                        ChannelIdentityState::Tombstone => ("closed", "tombstone", true, false),
                        ChannelIdentityState::Quarantine => {
                            ("routable", "identity_retiring", true, true)
                        }
                        _ => ("routable", "routable", false, false),
                    };
                Ok(AppliedLifecycle {
                    identity: Some(current),
                    outcome,
                    owner_visible_state,
                    outbound_closed,
                    identity_retiring,
                })
            }
        }
    }

    fn create_channel_identity_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        identity: &ChannelIdentity,
    ) -> Result<()> {
        let data = encode_channel_identity_body(identity)?;
        if self.store.entities.get(&*wtxn, id.as_bytes())?.is_some()
            || self.channel_identity_assignment_conflict_in_txn(wtxn, id, identity)?
        {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        self.apply_channel_identity_body(wtxn, id, identity.state_changed_at, data)
    }

    fn write_existing_channel_identity_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        identity: &ChannelIdentity,
    ) -> Result<()> {
        if self.channel_identity_assignment_conflict_in_txn(wtxn, id, identity)? {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        let data = encode_channel_identity_body(identity)?;
        self.apply_channel_identity_body(wtxn, id, identity.state_changed_at, data)
    }

    fn read_channel_identity_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<ChannelIdentity> {
        let raw = self
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])
    }

    fn append_channel_identity_lifecycle_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        created_at: u64,
        input: LifecycleReceiptInput,
    ) -> Result<ChannelIdentityLifecycleReceiptRecord> {
        let receipt = ChannelIdentityLifecycleReceiptRecord {
            version: 0,
            receipt_id: ChannelIdentityLifecycleReceiptId::now(),
            created_at,
            identity_id: *input.identity_id.as_bytes(),
            actor_class: input.actor.actor_class,
            actor_ref: input.actor.actor_ref,
            verb: input.verb,
            intent_kind: input.intent_kind,
            outcome: input.outcome,
            gate_decision_id: input.gate_decision_id,
            channel: input.channel,
            address_or_handle: input.address_or_handle,
            state: input.state,
            fulfillment_mode: input.fulfillment_mode,
            owner_visible_state: input.owner_visible_state,
            outbound_closed: input.outbound_closed,
            identity_retiring: input.identity_retiring,
            quarantine_until: input.quarantine_until,
        };
        self.store
            .append_channel_identity_lifecycle_receipt_in_txn(wtxn, &receipt)?;
        Ok(receipt)
    }
}

pub(crate) fn lifecycle_receipt_ref(receipt_id: ChannelIdentityLifecycleReceiptId) -> String {
    format!("identity_lifecycle:{}", receipt_id.to_hex())
}

#[cfg(test)]
mod tests;
