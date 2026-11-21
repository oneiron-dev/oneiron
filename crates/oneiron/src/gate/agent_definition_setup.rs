//! The setup Gate receipt for one generated agent definition, in its writer.

use oneiron_authority::federation::{Scope, SensitivityCeiling};

use super::ceiling::PolicyCriticality;
use super::constants::POLICY_SCHEMA_VERSION;
use super::decision::GateDecision;
use super::input::{
    ConsentGateContext, GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles,
};
use super::resolve_policy_manifest;
use crate::claim::ClaimSource;
use crate::consent::ComposedEffect;
use crate::error::Result;
use crate::store::{GateDecisionId, PolicyBasis, ReceiptActor};
use crate::{EntityId, Vault, WriteActor};

/// This records a verdict, not authority. The caller checks Allow before it
/// writes the exact candidate bytes; a pending verdict never stores a definition.
pub(crate) fn record_agent_definition_setup_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    target: EntityId,
    body: &[u8],
    position: &Scope,
    effect: &ComposedEffect,
) -> Result<(GateDecision, GateDecisionId)> {
    let policy = resolve_policy_manifest(&vault.store, txn)?;
    let input = GateEvaluatorInput {
        actor: GateActor {
            actor_class: actor.actor_class().gate_actor_class().to_owned(),
            actor_ref: Some(actor.entity_ref().to_hex()),
            delegation_grant_ref: None,
        },
        source: Some(ClaimSource::Generated),
        content_kind: GateContentKind::AgentDefinitionSetup,
        sensitivity_band: match position.sensitivity {
            SensitivityCeiling::AtMost(band) => Some(band as u8),
            SensitivityCeiling::Bottom => None,
        },
        criticality: PolicyCriticality::Normal,
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(actor.entity_ref()),
            run_attempt: actor.run_attempt(),
            ..GateProvenanceHandles::default()
        },
        external_effect: None,
        agent_definition_ceiling: super::agent_definition_ceiling_for_actor(
            &vault.store,
            txn,
            actor,
        ),
        foreign_agent_ceiling: super::foreign_agent::resolve(&vault.store, txn, actor)?,
        consent: Some(ConsentGateContext::evaluate(effect, None, &[])),
    };
    let decision = policy.evaluate_gate(&input);
    vault.store.diagnostics.gate.record_decision(&decision);
    let mut receipt = decision.gate_receipt(
        input.content_kind.as_str(),
        ReceiptActor::Row(actor),
        blake3::hash(body).as_bytes().to_vec(),
        PolicyBasis::frontier(policy.read_frontier_hash()?),
    );
    receipt.receipt_reasons = decision
        .receipt_reasons()
        .iter()
        .map(|reason| (*reason).to_owned())
        .collect();
    receipt.grant_ref = Some(format!("agent_definition:{}", target.to_hex()));
    let record = vault.store.record_gate_receipt_in_txn(txn, receipt)?;
    Ok((decision, record.decision_id))
}
