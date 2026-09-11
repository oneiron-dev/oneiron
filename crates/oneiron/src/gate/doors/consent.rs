//! Consent binding hashes plus the pending lifecycle and enforcement matrix.

use super::peripheral::GateWriteMode;
use crate::claim::{ClaimApprovalStatus, ClaimBody, claim_sensitivity_band};
use crate::entity_id::EntityId;
use crate::error::GateError;
use crate::error::{Error, Result};
use crate::gate::ceiling::PolicyApprovalCeiling;
use crate::gate::constants::POLICY_SCHEMA_VERSION;
use crate::gate::decision::{GateDecision, GateOutcome};
use crate::gate::input::{
    ConsentGateContext, GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles,
};
use crate::gate::resolution::{
    PolicyManifestResolution, hash_bool, hash_bytes, hash_opt_str, hash_str,
    resolve_policy_manifest,
};
use crate::store::{GateDecisionRecord, PendingGateConsentRecord, Store};
use sha2::{Digest, Sha256};

pub(in crate::gate) struct GateConsentBinding {
    pub(in crate::gate) diff_handle: Vec<u8>,
    pub(in crate::gate) read_frontier_hash: [u8; 32],
}

impl GateConsentBinding {
    pub(super) fn for_claim(body: &ClaimBody, policy: &PolicyManifestResolution) -> Result<Self> {
        let mut normalized = body.clone();
        normalized.approval = ClaimApprovalStatus::Proposed;
        let encoded = crate::claim::encode_claim_body(&normalized)?;
        let mut hasher = Sha256::new();
        hasher.update(b"oneiron.gate.claim_diff.v0");
        hasher.update(&encoded);
        Ok(Self {
            diff_handle: hasher.finalize().to_vec(),
            read_frontier_hash: policy.read_frontier_hash()?,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::gate) fn for_external_effect(
        input: &GateEvaluatorInput,
        policy: &PolicyManifestResolution,
    ) -> Result<Self> {
        let mut hasher = Sha256::new();
        hash_bytes(&mut hasher, b"oneiron.gate.external_effect.v0");
        hash_str(&mut hasher, &input.actor.actor_class);
        hash_opt_str(&mut hasher, input.actor.actor_ref.as_deref());
        match input.provenance.actor_entity_ref {
            Some(actor_entity_ref) => {
                hash_bool(&mut hasher, true);
                hash_bytes(&mut hasher, actor_entity_ref.as_bytes());
            }
            None => hash_bool(&mut hasher, false),
        }
        match input.external_effect.as_ref() {
            Some(effect) => {
                hash_bool(&mut hasher, true);
                hash_str(&mut hasher, effect.verb.trim());
                hash_str(&mut hasher, effect.channel.trim());
                hash_opt_str(&mut hasher, effect.brief_ref.as_deref());
                hash_opt_str(&mut hasher, effect.send_ref.as_deref());
                hash_opt_str(&mut hasher, effect.standing_grant_ref.as_deref());
                match effect.scoped_mcp_call.as_ref() {
                    Some(call) => {
                        hash_bool(&mut hasher, true);
                        hash_str(&mut hasher, &call.server);
                        hash_str(&mut hasher, &call.tool);
                        hash_str(&mut hasher, call.payload_data_class.as_str());
                        hash_str(&mut hasher, &call.resolved_endpoint);
                    }
                    None => hash_bool(&mut hasher, false),
                }
                hash_bool(&mut hasher, effect.has_opted_in);
                hash_bool(&mut hasher, effect.has_permission);
                hash_str(&mut hasher, effect.policy_risk.as_str());
            }
            None => hash_bool(&mut hasher, false),
        }
        Ok(Self {
            diff_handle: hasher.finalize().to_vec(),
            read_frontier_hash: policy.read_frontier_hash()?,
        })
    }
}

// The claim-door assembler takes the full axis tuple one call site at a time
// spells out; boxing the tail two `Option` knobs would hide the consent seam
// this lane opened.
#[allow(clippy::too_many_arguments)]
pub(in crate::gate) fn claim_gate_input(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
    actor: GateActor,
    content_kind: GateContentKind,
    provenance: GateProvenanceHandles,
    include_source: bool,
    agent_definition_ceiling: Option<PolicyApprovalCeiling>,
    consent: Option<ConsentGateContext>,
) -> GateEvaluatorInput {
    let (source, sensitivity_band) = if include_source || body.approval == ClaimApprovalStatus::Auto
    {
        (body.source, claim_sensitivity_band(body))
    } else {
        (None, None)
    };

    GateEvaluatorInput {
        actor,
        source,
        content_kind,
        sensitivity_band,
        criticality: policy.criticality_for_predicate(&body.predicate),
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        provenance,
        external_effect: None,
        agent_definition_ceiling,
        consent,
    }
}

pub(in crate::gate) fn enforce_gate_decision(decision: GateDecision) -> Result<()> {
    if decision.outcome() == GateOutcome::Allow {
        return Ok(());
    }

    reject_gate_decision(decision)
}

pub(in crate::gate) fn gate_decision_matches_pending_candidate(
    record: &GateDecisionRecord,
    expected: &GateDecisionRecord,
) -> bool {
    record.version == expected.version
        && record.redacted_at == expected.redacted_at
        && record.outcome == expected.outcome
        && record.reason_codes == expected.reason_codes
        && record.receipt_reasons == expected.receipt_reasons
        && record.system_notices == expected.system_notices
        && record.actor_class == expected.actor_class
        && record.actor_ref == expected.actor_ref
        && record.content_kind == expected.content_kind
        && record.policy_manifest_version == expected.policy_manifest_version
        && record.claim_id == expected.claim_id
        && record.grant_ref == expected.grant_ref
        && record.diff_handle == expected.diff_handle
        && record.read_frontier_hash == expected.read_frontier_hash
}

pub(super) fn enforce_claim_gate_decision_with_consent(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    decision: &GateDecision,
    approval: ClaimApprovalStatus,
    binding: &GateConsentBinding,
    mode: GateWriteMode,
) -> Result<()> {
    match (decision.outcome(), approval) {
        (GateOutcome::Allow, _) => {
            if mode.resolve_pending {
                resolve_pending_gate_consent_if_bound(store, wtxn, id, binding)?;
            }
            Ok(())
        }
        (GateOutcome::Pending, ClaimApprovalStatus::Proposed) => Ok(()),
        (GateOutcome::Pending, ClaimApprovalStatus::Approved) => {
            if !mode.can_resolve_pending_consent {
                return reject_gate_decision(decision.clone());
            }
            let Some(pending) = store.pending_gate_consent_in_txn(wtxn, id)? else {
                return reject_gate_decision(decision.clone());
            };
            require_pending_gate_consent_binding(id, &pending, binding)?;
            if mode.resolve_pending {
                store.delete_pending_gate_consent_in_txn(wtxn, id)?;
            }
            Ok(())
        }
        _ => reject_gate_decision(decision.clone()),
    }
}

fn resolve_pending_gate_consent_if_bound(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    binding: &GateConsentBinding,
) -> Result<()> {
    let Some(pending) = store.pending_gate_consent_in_txn(wtxn, id)? else {
        return Ok(());
    };
    require_pending_gate_consent_binding(id, &pending, binding)?;
    store.delete_pending_gate_consent_in_txn(wtxn, id)
}

fn require_pending_gate_consent_binding(
    id: &EntityId,
    pending: &PendingGateConsentRecord,
    binding: &GateConsentBinding,
) -> Result<()> {
    if pending.diff_handle != binding.diff_handle
        || pending.read_frontier_hash != binding.read_frontier_hash
    {
        return Err(Error::Gate(GateError::GateConsentStale { claim_id: *id }));
    }
    Ok(())
}

pub(super) fn reject_gate_decision(decision: GateDecision) -> Result<()> {
    Err(Error::Gate(GateError::GateWriteRejected {
        outcome: decision.outcome().as_str(),
        reason_codes: decision
            .reason_codes()
            .iter()
            .map(|code| code.as_str())
            .collect(),
    }))
}

/// Computes the content-addressed consent binding parts for a claim body
/// against the currently-resolved policy manifest. The OF-234 inbox uses
/// this to verify a pending proposal has not drifted (content or policy
/// floor) before redeeming bundle consent on it.
pub(crate) fn claim_consent_binding_parts(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<(Vec<u8>, [u8; 32])> {
    let policy = resolve_policy_manifest(store, txn)?;
    let binding = GateConsentBinding::for_claim(body, &policy)?;
    Ok((binding.diff_handle, binding.read_frontier_hash))
}
