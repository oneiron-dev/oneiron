//! The governance-only parked lane: one durable gate transaction, no budget debit.
use super::verdict::DispatchVerdict;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{self, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateOutcome};
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::dispatch_types::{
    OutboundDispatchError, OutboundDispatchOutcome, OutboundDispatchRequest,
};

pub(super) fn gate_input(
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
    policy_risk: ExternalEffectPolicyRisk,
) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: request.actor.gate_actor(),
        provenance: request.actor.provenance(),
        verb: verb_contract.kind.clone(),
        channel: request.intent.channel.clone(),
        channel_identity_ref: request.channel_identity_ref,
        counterparty: request
            .counterparty_ref
            .clone()
            .or_else(|| Some(request.intent.target.clone())),
        brief_ref: request.intent.job_ref.clone(),
        send_ref: Some(request.intent_ref.clone()),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: request.gate.has_opted_in,
        has_permission: request.gate.has_permission,
        policy_risk,
    }
}

impl Vault {
    /// Associate an exact prepared send with a stored scope origin. Only a
    /// vault policy-power holder may attest this association; dispatch rechecks
    /// the stored origin and exact effect identity on its own write transaction.
    pub fn bind_outbound_policy_origin(
        &self,
        holder: &crate::consent::AuthenticatedOwner,
        request: OutboundDispatchRequest,
        origin: EntityId,
        now: u64,
    ) -> Result<(), OutboundDispatchError> {
        let prepared =
            super::request_binding::PreparedOutboundDispatch::prepare(self, request, None)?;
        let effect = gate_input(
            &prepared.request,
            prepared.verb_contract,
            prepared.policy_risk,
        );
        let mut txn = self.store.env.write_txn().map_err(Error::from)?;
        holder.revalidate_in_txn(self, &txn)?;
        self.bind_policy_effect_origin_in_txn(&mut txn, holder.actor(), &effect, origin, now)?;
        txn.commit().map_err(Error::from)?;
        Ok(())
    }
}

pub(super) fn govern_parked(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    effect: &ExternalEffectGateInput,
    verified_actor: Option<(EntityId, EdgeActorClass)>,
    space_posting: Option<&crate::channel_identity_autonomy::FrozenSpacePosting>,
    parked_outcome: OutboundDispatchOutcome,
) -> Result<DispatchVerdict, OutboundDispatchError> {
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    if let Some((actor, actor_class)) = verified_actor {
        let entity_type = vault
            .get_entity_type_in_txn(&wtxn, &actor)?
            .ok_or(OutboundDispatchError::InvalidBoundActor)?;
        crate::provenance::validate_actor_class(entity_type, actor_class)?;
    }
    let mut held_value = serde_json::json!({
        "actor_class": request.actor.actor_class, "channel_identity_ref": request.channel_identity_ref.map(|id| id.to_hex()),
        "target": request.intent.target,
    });
    if let Some(posting) = &space_posting {
        held_value["space_posting"] = serde_json::to_value(posting)
            .map_err(|_| Error::InvariantViolation("posting gate payload"))?;
    }
    let held_bytes = serde_json::to_vec(&held_value)
        .map_err(|_| Error::InvariantViolation("posting gate payload"))?;
    let effect = vault.space_posting_gate_in_txn(&wtxn, &held_bytes, effect)?;
    let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    let (gate_decision_id, gate_decision, _) =
        gate::check_external_effect_policy(&vault.store, &mut wtxn, &effect, &policy, false)?;
    wtxn.commit().map_err(Error::from)?;
    vault.store.notify_attempt_observers();
    let gate_outcome_kind = gate_decision.outcome();
    let outcome = match gate_outcome_kind {
        GateOutcome::Pending => OutboundDispatchOutcome::Held,
        GateOutcome::Deny => OutboundDispatchOutcome::Suppressed,
        GateOutcome::Allow => parked_outcome,
    };
    Ok(DispatchVerdict {
        gate_decision_ref: Some(format!("gate:{}", gate_decision_id.to_hex())),
        gate_outcome: gate_outcome_kind,
        gate_reason_codes: gate_decision
            .reason_codes()
            .iter()
            .map(|reason| reason.as_str().to_owned())
            .collect(),
        gate_receipt_reasons: gate_decision
            .receipt_reasons()
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect(),
        effector_charge: None,
        effect_state: None,
        outcome,
        execution: None,
        suppression_receipt: None,
    })
}
