//! ChannelIdentity lifecycle verbs through the ExternalEffect door (OF-347 CID-2).

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityFulfillment, ChannelIdentityState,
    decode_channel_identity_body, encode_channel_identity_body,
};
use crate::error::{Error, Result};
use crate::gate::{
    self, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles,
};
use crate::store::{ChannelIdentityLifecycleReceiptId, ChannelIdentityLifecycleReceiptRecord};
use crate::types::{ENTITY_TYPE_CHANNEL_IDENTITY, EntityId};

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
mod tests {
    use super::*;
    use rmpv::Value;

    use crate::channel_identity::CHANNEL_IDENTITY_MIN_QUARANTINE_SECS;
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    use crate::store::Store;
    use crate::types::{ENTITY_ID_LEN, ENTITY_TYPE_POLICY_MANIFEST, VaultConfig};

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
        (tmp, vault)
    }

    fn entity(seed: u8) -> EntityId {
        let mut bytes = [seed; ENTITY_ID_LEN];
        bytes[0] = seed.max(1);
        EntityId::from_bytes(bytes).expect("test entity id")
    }

    fn policy_manifest(actor_ref: &str, channel: &str, verbs: &[&str]) -> Vec<u8> {
        let scoped_grants = verbs
            .iter()
            .map(|verb| {
                Value::Map(vec![
                    (Value::from("actor_ref"), Value::from(actor_ref)),
                    (
                        Value::from("effector"),
                        Value::from(format!("external:{verb}")),
                    ),
                    (
                        Value::from("scope"),
                        Value::Map(vec![(Value::from("channel"), Value::from(channel))]),
                    ),
                ])
            })
            .collect::<Vec<_>>();
        let entries = vec![
            (Value::from("schema_version"), Value::from("1.1")),
            (Value::from("pack_id"), Value::from("cid-2-test")),
            (Value::from("pack_version"), Value::from("v1")),
            (
                Value::from("min_engine_version"),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                Value::from("defaults"),
                Value::Map(vec![
                    (Value::from("criticality"), Value::from("normal")),
                    (Value::from("sensitivity"), Value::from("normal")),
                ]),
            ),
            (Value::from("rules"), Value::Array(Vec::new())),
            (
                Value::from("actor_ceilings"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("actor_class"), Value::from("agent")),
                    (Value::from("actor_ref"), Value::from(actor_ref)),
                    (Value::from("ceiling"), Value::from("auto")),
                ])]),
            ),
            (Value::from("scoped_grants"), Value::Array(scoped_grants)),
        ];
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
        out
    }

    fn put_policy_manifest(vault: &Vault, seed: u8, data: &[u8]) -> Result<()> {
        let id = entity(seed);
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(ENTITY_TYPE_POLICY_MANIFEST);
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(data);

        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
    }

    fn requested_identity(agent: EntityId, at: u64) -> ChannelIdentity {
        ChannelIdentity::requested(
            "email",
            format!("agent-{}@example.test", agent.to_hex()),
            crate::channel_identity::ChannelIdentityShape::DedicatedAddress,
            crate::channel_identity::ChannelIdentityBinding::agent(agent),
            at,
        )
    }

    fn request(
        actor: ChannelIdentityLifecycleActor,
        at: u64,
        intent: ChannelIdentityLifecycleIntent,
    ) -> ChannelIdentityLifecycleRequest {
        ChannelIdentityLifecycleRequest {
            actor,
            gate: ChannelIdentityLifecycleGate::allow_when_policy_grants(),
            requested_at: at,
            intent,
        }
    }

    #[test]
    fn lifecycle_verbs_gate_receipt_and_manual_fulfillment() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let agent = entity(0xA1);
        let actor = ChannelIdentityLifecycleActor::agent(agent);
        put_policy_manifest(
            &vault,
            0xD0,
            &policy_manifest(
                actor.actor_ref.as_deref().expect("actor ref"),
                "email",
                &["provision", "bind", "rotate", "release", "route_inbound"],
            ),
        )?;

        let provision_id = entity(0xB1);
        let provision = vault.apply_channel_identity_lifecycle_intent(request(
            actor.clone(),
            1_000,
            ChannelIdentityLifecycleIntent::Provision(ProvisionIntent {
                identity_id: provision_id,
                identity: requested_identity(agent, 1_000),
                fulfillment_mode: ChannelIdentityFulfillment::Manual,
            }),
        ))?;
        assert_eq!(provision.outcome, "pending_fulfillment");
        assert!(provision.gate_receipt_id.is_some());
        assert_eq!(
            provision.identity.as_ref().expect("identity").state,
            ChannelIdentityState::PendingFulfillment
        );

        let fulfilled = vault.fulfill_channel_identity(ChannelIdentityFulfillmentInput {
            actor: actor.clone(),
            identity_id: provision_id,
            fulfilled_at: 1_010,
        })?;
        assert_eq!(fulfilled.outcome, "active");
        assert_eq!(
            fulfilled.identity.as_ref().expect("identity").state,
            ChannelIdentityState::Active
        );

        let bind_id = entity(0xB2);
        vault.create_channel_identity(&bind_id, &requested_identity(entity(0xA2), 1_020))?;
        let bound = vault.apply_channel_identity_lifecycle_intent(request(
            actor.clone(),
            1_030,
            ChannelIdentityLifecycleIntent::Bind(BindIntent {
                identity_id: bind_id,
                fulfillment_mode: ChannelIdentityFulfillment::Manual,
            }),
        ))?;
        assert_eq!(bound.outcome, "pending_fulfillment");
        vault.fulfill_channel_identity(ChannelIdentityFulfillmentInput {
            actor: actor.clone(),
            identity_id: bind_id,
            fulfilled_at: 1_040,
        })?;

        let rotated = vault.apply_channel_identity_lifecycle_intent(request(
            actor.clone(),
            1_050,
            ChannelIdentityLifecycleIntent::Rotate(RotateIntent {
                identity_id: provision_id,
            }),
        ))?;
        assert_eq!(rotated.outcome, "rotating");
        vault.fulfill_channel_identity(ChannelIdentityFulfillmentInput {
            actor: actor.clone(),
            identity_id: provision_id,
            fulfilled_at: 1_060,
        })?;

        let quarantine_until = 1_070 + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS;
        let released = vault.apply_channel_identity_lifecycle_intent(request(
            actor.clone(),
            1_070,
            ChannelIdentityLifecycleIntent::Release(ReleaseIntent {
                identity_id: provision_id,
                quarantine_until,
            }),
        ))?;
        assert_eq!(released.outcome, "quarantine");
        assert!(released.outbound_closed);
        assert!(released.identity_retiring);
        assert_eq!(
            released.identity.as_ref().expect("identity").state,
            ChannelIdentityState::Quarantine
        );

        let inbound = vault.apply_channel_identity_lifecycle_intent(request(
            actor,
            1_080,
            ChannelIdentityLifecycleIntent::RouteInbound(RouteInboundIntent {
                identity_id: provision_id,
            }),
        ))?;
        assert_eq!(inbound.outcome, "routable");
        assert_eq!(inbound.owner_visible_state, "identity_retiring");
        assert!(inbound.outbound_closed);
        assert!(inbound.identity_retiring);

        let identity_receipts = vault.receipts(
            ReceiptQuery::new(20)
                .with_kind(ReceiptKind::IdentityLifecycle)
                .with_actor(agent.to_hex()),
        )?;
        for verb in ["provision", "bind", "rotate", "release", "route_inbound"] {
            assert!(
                identity_receipts.iter().any(|receipt| receipt
                    .fields
                    .get("verb")
                    .is_some_and(|value| value == verb)),
                "missing lifecycle receipt for {verb}"
            );
        }
        assert!(identity_receipts.iter().any(|receipt| {
            receipt.fields.get("fulfillment_mode").map(String::as_str) == Some("manual")
                && receipt.outcome == "pending_fulfillment"
        }));
        assert!(identity_receipts.iter().any(|receipt| {
            receipt
                .fields
                .get("owner_visible_state")
                .map(String::as_str)
                == Some("identity_retiring")
                && receipt.fields.get("outbound_closed").map(String::as_str) == Some("true")
        }));

        let gate_receipts = vault.receipts(
            ReceiptQuery::new(20)
                .with_kind(ReceiptKind::Gate)
                .with_actor(agent.to_hex()),
        )?;
        assert_eq!(
            gate_receipts
                .iter()
                .filter(|receipt| {
                    receipt.fields.get("content_kind").map(String::as_str)
                        == Some("external_effect")
                })
                .count(),
            5
        );
        Ok(())
    }

    #[test]
    fn pending_external_effect_holds_without_mutating_identity() {
        let (_tmp, vault) = temp_vault();
        let agent = entity(0xC1);
        let actor = ChannelIdentityLifecycleActor::agent(agent);
        let identity_id = entity(0xC2);
        let requested = requested_identity(agent, 2_000);

        let held = vault
            .apply_channel_identity_lifecycle_intent(request(
                actor,
                2_000,
                ChannelIdentityLifecycleIntent::Provision(ProvisionIntent {
                    identity_id,
                    identity: requested,
                    fulfillment_mode: ChannelIdentityFulfillment::Manual,
                }),
            ))
            .expect("pending provision should hold and receipt");

        assert_eq!(held.outcome, "held");
        assert_eq!(held.owner_visible_state, "held");
        assert!(
            vault
                .get_channel_identity(&identity_id)
                .expect("read held identity")
                .is_none()
        );
        let receipts = vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::IdentityLifecycle))
            .expect("query held lifecycle receipts");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, "held");
        assert_eq!(
            receipts[0].fields.get("verb").map(String::as_str),
            Some("provision")
        );
    }
}
