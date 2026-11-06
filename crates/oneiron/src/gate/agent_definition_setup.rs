//! The setup Gate receipt for one generated agent definition, in its writer.

use oneiron_authority::federation::{Scope, SensitivityCeiling};

use super::ceiling::PolicyCriticality;
use super::constants::POLICY_SCHEMA_VERSION;
use super::decision::{GateDecision, GateOutcome};
use super::input::{
    ConsentGateContext, GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles,
};
use super::{PolicyManifestResolution, resolve_policy_manifest};
use crate::claim::ClaimSource;
use crate::consent::ComposedEffect;
use crate::error::Result;
use crate::store::{GateDecisionId, GateDecisionRecord};
use crate::{EntityId, Vault, WriteActor};

/// Original authority, captured before the native setup can stage any rows.
/// No verdict, clock allocation or receipt exists until the program completes.
pub(crate) struct OriginalAgentSetupGate {
    policy: PolicyManifestResolution,
    input: GateEvaluatorInput,
}

impl OriginalAgentSetupGate {
    pub(crate) fn capture(vault: &Vault, txn: &heed::RoTxn<'_>, actor: WriteActor) -> Result<Self> {
        let policy = resolve_policy_manifest(&vault.store, txn)?;
        let input = GateEvaluatorInput {
            actor: GateActor {
                actor_class: actor.actor_class().gate_actor_class().to_owned(),
                actor_ref: Some(actor.entity_ref().to_hex()),
                delegation_grant_ref: None,
            },
            source: Some(ClaimSource::Generated),
            content_kind: GateContentKind::AgentDefinitionSetup,
            sensitivity_band: None,
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
            consent: None,
        };
        Ok(Self { policy, input })
    }

    /// Consumes the original authority once, using the completed native facts.
    pub(crate) fn evaluate(
        mut self,
        position: &Scope,
        effect: &ComposedEffect,
    ) -> EvaluatedAgentSetupGate {
        self.input.sensitivity_band = match position.sensitivity {
            SensitivityCeiling::AtMost(band) => Some(band as u8),
            SensitivityCeiling::Bottom => None,
        };
        self.input.consent = Some(ConsentGateContext::evaluate(effect, None, &[]));
        let decision = self.policy.evaluate_gate(&self.input);
        EvaluatedAgentSetupGate {
            original: self,
            decision,
        }
    }
}

/// The actual verdict. Recording consumes it, after the child is merged or
/// dropped, in the same ultimate writer as the shape item, journal and run.
pub(crate) struct EvaluatedAgentSetupGate {
    original: OriginalAgentSetupGate,
    decision: GateDecision,
}

impl EvaluatedAgentSetupGate {
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.decision.outcome()
    }

    pub(crate) fn record_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        target: EntityId,
        body: &[u8],
    ) -> Result<(GateDecision, GateDecisionId)> {
        let Self {
            original: self_original,
            decision,
        } = self;
        let OriginalAgentSetupGate { policy, input } = self_original;
        vault.store.diagnostics.gate.record_decision(&decision);
        let mut record = GateDecisionRecord {
            version: crate::store::GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
            created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
            outcome: decision.outcome().as_str().to_owned(),
            reason_codes: decision
                .reason_codes()
                .iter()
                .map(|code| code.as_str().to_owned())
                .collect(),
            receipt_reasons: decision
                .receipt_reasons()
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect(),
            system_notices: Vec::new(),
            actor_class: input.actor.actor_class,
            actor_ref: input.actor.actor_ref,
            content_kind: input.content_kind.as_str().to_owned(),
            policy_manifest_version: input.policy_manifest_version,
            claim_id: None,
            grant_ref: Some(format!("agent_definition:{}", target.to_hex())),
            diff_handle: blake3::hash(body).as_bytes().to_vec(),
            read_frontier_hash: policy.read_frontier_hash()?,
            context: Default::default(),
            redacted_at: None,
        };
        vault
            .store
            .append_fresh_gate_decision_in_txn(txn, &mut record)?;
        Ok((decision, record.decision_id))
    }
}

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
    OriginalAgentSetupGate::capture(vault, txn, actor)?
        .evaluate(position, effect)
        .record_in_txn(vault, txn, target, body)
}
