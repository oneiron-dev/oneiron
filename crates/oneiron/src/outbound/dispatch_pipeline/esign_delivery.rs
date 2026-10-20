//! E-sign delivery authority (FIX 5238 option 3; an L02 seam that changes no
//! existing body). A signing link is minted when its delivery exports, long
//! after the send's gate decision, and a queued row proves only that a past
//! send crossed the gate, never that a new bearer link may be minted. So the
//! mint writer reads here the send's canonical admitted call, and whether a
//! Grant live under that same writer still covers its effect, through the
//! chokepoint's own grant matching
//! ([`crate::gate::live_grant_covering_effect_in_txn`]). The owner's one-send
//! press the gate spent admitting the send rides its ledger row as a typed
//! proof (FIX 6362); the call carries it, and the ledger validates it against
//! the digest the frozen call recomposes here.

use serde::Deserialize;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::outbound::capability::outbound_verb_contract;
use crate::outbound::outbound_dispatch_attempt_id;
use crate::outbound_intent_ledger::{
    AdmittedApproval, IntentLedgerError, IntentState, read_intent_for_attempt_in_txn,
};

/// One e-sign send's admitted call, as its frozen ledger payload holds it:
/// the gate principal (not the display actor), the act and its target.
pub(crate) struct EsignDeliveryCall {
    pub(crate) actor_class: String,
    pub(crate) actor_entity_ref: Option<EntityId>,
    pub(crate) on_behalf_of: Option<String>,
    pub(crate) verb: String,
    pub(crate) target: String,
    pub(crate) content_ref: Option<String>,
    /// The owner's one-send press the gate spent admitting this call, as
    /// its ledger row records it (FIX 6362); `None` for a send no press
    /// released.
    pub(crate) admitted_approval: Option<AdmittedApproval>,
    actor_ref: Option<String>,
    channel: String,
    job_ref: Option<String>,
    counterparty_ref: Option<String>,
    channel_identity_ref: Option<EntityId>,
    has_opted_in: bool,
    has_permission: bool,
    policy_risk: ExternalEffectPolicyRisk,
    send_ref: String,
}

/// The members of the frozen payload the delivery reads; the rest stay
/// unread.
#[derive(Deserialize)]
struct FrozenCall {
    verb: String,
    channel: String,
    target: String,
    #[serde(default)]
    on_behalf_of: Option<String>,
    #[serde(default)]
    content_ref: Option<String>,
    #[serde(default)]
    job_ref: Option<String>,
    actor_class: String,
    #[serde(default)]
    actor_ref: Option<String>,
    #[serde(default)]
    actor_entity_ref: Option<String>,
    #[serde(default)]
    channel_identity_ref: Option<String>,
    #[serde(default)]
    counterparty_ref: Option<String>,
    has_opted_in: bool,
    has_permission: bool,
    policy_risk: String,
}

/// The completed call `dispatch_ref` admitted: call 0 of its dispatch
/// attempt, the one OF-327 ran the e-sign sink for. `None` while no such call
/// completed, or for one on another channel.
pub(crate) fn esign_delivery_call_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    dispatch_ref: &str,
) -> Result<Option<EsignDeliveryCall>> {
    let attempt_id = outbound_dispatch_attempt_id(dispatch_ref)
        .map_err(|_| Error::InvariantViolation("e-sign dispatch attempt id"))?;
    let record =
        read_intent_for_attempt_in_txn(vault, txn, attempt_id, 0).map_err(|error| match error {
            IntentLedgerError::Engine(error) => error,
            _ => Error::InvariantViolation("e-sign dispatch ledger row"),
        })?;
    let Some(record) = record.filter(|record| record.state == IntentState::Done) else {
        return Ok(None);
    };
    let frozen: FrozenCall = serde_json::from_slice(record.payload())
        .map_err(|_| Error::InvariantViolation("e-sign dispatch frozen payload"))?;
    if frozen.channel != "esign" {
        return Ok(None);
    }
    frozen_call(frozen, dispatch_ref, record.admitted_approval).map(Some)
}

/// The digest an owner's one-send press on the e-sign `tool` call frozen in
/// `payload` approves: the gate's approve-once composer over the call's
/// actor, act, channel and brief, as the gate built them for the send.
/// `None` for a payload that is no frozen e-sign `tool` call.
pub(crate) fn esign_approval_digest_from_frozen_payload(
    payload: &[u8],
    tool: &str,
) -> Option<crate::consent::EffectDigest> {
    let frozen: FrozenCall = serde_json::from_slice(payload).ok()?;
    if frozen.channel != "esign" || frozen.verb != tool {
        return None;
    }
    let call = frozen_call(frozen, "", None).ok()?;
    crate::gate::external_effect_approval_digest(&call_effect(&call).ok()?)
}

fn frozen_call(
    frozen: FrozenCall,
    send_ref: &str,
    admitted_approval: Option<AdmittedApproval>,
) -> Result<EsignDeliveryCall> {
    let entity = |value: Option<String>| -> Result<Option<EntityId>> {
        value.map(|hex| EntityId::from_hex(&hex)).transpose()
    };
    Ok(EsignDeliveryCall {
        actor_class: frozen.actor_class,
        actor_entity_ref: entity(frozen.actor_entity_ref)?,
        on_behalf_of: frozen.on_behalf_of,
        verb: frozen.verb,
        target: frozen.target,
        content_ref: frozen.content_ref,
        admitted_approval,
        actor_ref: frozen.actor_ref,
        channel: frozen.channel,
        job_ref: frozen.job_ref,
        counterparty_ref: frozen.counterparty_ref,
        channel_identity_ref: entity(frozen.channel_identity_ref)?,
        has_opted_in: frozen.has_opted_in,
        has_permission: frozen.has_permission,
        policy_risk: if frozen.policy_risk == ExternalEffectPolicyRisk::Normal.as_str() {
            ExternalEffectPolicyRisk::Normal
        } else {
            ExternalEffectPolicyRisk::HoldToProposal
        },
        send_ref: send_ref.to_owned(),
    })
}

/// The Grant live on THIS writer that covers `call`'s effect, as the gate
/// built it for the send: a standing outbound grant, a policy-scoped grant
/// or a DEC-0006 standing consent grant. `None`: none does any more.
pub(crate) fn esign_delivery_grant_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    call: &EsignDeliveryCall,
) -> Result<Option<String>> {
    let effect = call_effect(call)?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, wtxn)?;
    crate::gate::live_grant_covering_effect_in_txn(&vault.store, wtxn, &effect, &policy)
}

/// The gate effect `call` was admitted as, as the gate built it for the send.
fn call_effect(call: &EsignDeliveryCall) -> Result<ExternalEffectGateInput> {
    let contract = outbound_verb_contract(&call.channel, &call.verb)
        .map_err(|_| Error::InvariantViolation("e-sign dispatch verb"))?;
    Ok(ExternalEffectGateInput {
        actor: GateActor {
            actor_class: call.actor_class.clone(),
            actor_ref: call.actor_ref.clone(),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: call.actor_entity_ref,
            mail_content_ref: call.content_ref.clone(),
            ..GateProvenanceHandles::default()
        },
        verb: contract.kind.clone(),
        channel: call.channel.clone(),
        channel_identity_ref: call.channel_identity_ref,
        counterparty: call
            .counterparty_ref
            .clone()
            .or_else(|| Some(call.target.clone())),
        brief_ref: call.job_ref.clone(),
        send_ref: Some(call.send_ref.clone()),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: call.has_opted_in,
        has_permission: call.has_permission,
        policy_risk: call.policy_risk,
        send_autonomy: None,
    })
}
