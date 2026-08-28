use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, claim_sensitivity_band};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store};
use crate::write_envelope::{WriteActor, WriteEnvelope};

use super::ceiling::PolicyApprovalCeiling;
use super::confirm::{
    GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED, GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED,
    critical_claim_can_land_auto_with_confirm,
};
use super::constants::{
    DREAMER_PROVENANCE_RUN_ID_KEY, DREAMER_PROVENANCE_RUN_KEY, DREAMER_PROVENANCE_RUNNER_KEY,
    DREAMER_PROVENANCE_SURFACE_KEY, LOCAL_WRITE_ACTOR_CLASS, LOCAL_WRITE_ACTOR_ENTITY_REF,
    POLICY_SCHEMA_VERSION,
};
use super::decision::{GateDecision, GateOutcome, record_gate_decision_metrics};
// Reason codes are minted here only by the federated-admission door, which is
// sync-gated; the base doors build their decisions from other constructors.
#[cfg(feature = "sync")]
use super::decision::GateReasonCode;
use super::definition_ceiling::agent_definition_ceiling_for_actor;
use super::input::{
    ConsentGateContext, GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles,
};
use super::resolution::{
    PolicyManifestResolution, check_claim_source_trust, hash_bool, hash_bytes, hash_opt_str,
    hash_str, resolve_policy_manifest,
};

pub(crate) fn check_claim_policy_for_write(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    envelope: Option<&WriteEnvelope>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
) -> Result<()> {
    let mut recorded_decision = None;
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        ClaimGateWrite {
            body,
            envelope,
            defer_metrics_until_commit: false,
        },
        policy,
        mode,
        &mut recorded_decision,
        None,
    )
}

// The pending-bind seam threads the preflight receipt identity one parameter
// further than the record seam; bundling the axis tuple would hide the
// preflight decision binding this lane opened.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_claim_policy_for_write_with_preflight_decision(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    envelope: Option<&WriteEnvelope>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    preflight_decision_id: Option<GateDecisionId>,
) -> Result<()> {
    let mut recorded_decision = None;
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        ClaimGateWrite {
            body,
            envelope,
            defer_metrics_until_commit: false,
        },
        policy,
        mode,
        &mut recorded_decision,
        preflight_decision_id,
    )
}

pub(crate) fn check_claim_policy_for_write_with_record(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
) -> Result<()> {
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        recorded_decision,
        None,
    )
}

// The inner executor carries the outer record seam's axis tuple plus the
// preflight identity exactly once; a parameter struct would only rename the
// same boundary.
#[allow(clippy::too_many_arguments)]
fn check_claim_policy_for_write_with_record_inner(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
    preflight_decision_id: Option<GateDecisionId>,
) -> Result<()> {
    let ClaimGateWrite {
        body,
        envelope,
        defer_metrics_until_commit,
    } = write;
    *recorded_decision = None;
    if let Some(envelope) = envelope {
        validate_write_envelope(envelope)?;
    }

    if policy.enforces_write_gate() {
        let (actor, provenance, agent_definition_ceiling) = if let Some(envelope) = envelope {
            let actor = envelope.actor();
            let dreamer_run_id = dreamer_run_id_from_write_envelope(envelope);
            let agent_definition_ceiling = agent_definition_ceiling_for_actor(store, &*wtxn, actor);
            (
                GateActor {
                    actor_class: edge_actor_class_str(actor.actor_class()).to_owned(),
                    actor_ref: Some(actor.entity_ref().to_hex()),
                    delegation_grant_ref: None,
                },
                GateProvenanceHandles {
                    actor_entity_ref: Some(actor.entity_ref()),
                    dreamer_run_id,
                    ..GateProvenanceHandles::default()
                },
                agent_definition_ceiling,
            )
        } else {
            (
                GateActor {
                    actor_class: LOCAL_WRITE_ACTOR_CLASS.to_owned(),
                    actor_ref: None,
                    delegation_grant_ref: None,
                },
                GateProvenanceHandles {
                    actor_entity_ref: Some(local_write_actor_entity_ref()),
                    ..GateProvenanceHandles::default()
                },
                None,
            )
        };
        let input = claim_gate_input(
            body,
            policy,
            actor,
            GateContentKind::Claim,
            provenance,
            mode.include_source_in_gate_input,
            agent_definition_ceiling,
            // Claim bodies carry no effect-fact axes the consent evaluator
            // could classify honestly; this door keeps its pre-DEC-0006
            // criticality behaviour (the `None` arm of `evaluate_gate`)
            // rather than guess at defaults that would silently auto-run.
            None,
        );
        let mut decision = policy.evaluate_gate(&input);
        let attach_critical_confirm = body.approval == ClaimApprovalStatus::Auto
            && critical_claim_can_land_auto_with_confirm(
                &input,
                decision.reason_codes(),
                &body.predicate,
            );
        if attach_critical_confirm {
            decision = GateDecision::allow()
                .with_receipt_reasons([GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED]);
        }
        let binding = GateConsentBinding::for_claim(body, policy)?;
        let decision_id = GateDecisionId::now();
        let created_at = crate::unix_seconds_now();
        let mut decision_record = GateDecisionRecord {
            version: 0,
            decision_id,
            created_at,
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
            actor_class: input.actor.actor_class.clone(),
            actor_ref: input.actor.actor_ref.clone(),
            content_kind: input.content_kind.as_str().to_owned(),
            policy_manifest_version: input.policy_manifest_version,
            claim_id: Some(*id.as_bytes()),
            grant_ref: None,
            diff_handle: binding.diff_handle.clone(),
            read_frontier_hash: binding.read_frontier_hash,
            redacted_at: None,
        };

        if mode.record_decision {
            if attach_critical_confirm {
                store.append_fresh_gate_decision_in_txn(wtxn, &mut decision_record)?;
            } else {
                store.append_gate_decision_in_txn(wtxn, &decision_record)?;
            }
            let recorded = RecordedClaimGateDecision {
                record: decision_record.clone(),
                decision: decision.clone(),
            };
            if !defer_metrics_until_commit {
                recorded.record_metrics();
            }
            *recorded_decision = Some(recorded);
        }

        if mode.persist_pending_consent
            && ((decision.outcome() == GateOutcome::Pending
                && body.approval == ClaimApprovalStatus::Proposed)
                || (attach_critical_confirm && body.approval == ClaimApprovalStatus::Auto))
        {
            let pending_decision = if mode.record_decision {
                decision_record.clone()
            } else if let Some(decision_id) = preflight_decision_id {
                let record = store.gate_decision_in_txn(&*wtxn, decision_id)?.ok_or(
                    Error::InvariantViolation(
                        "preflight gate decision missing during pending bind",
                    ),
                )?;
                if !gate_decision_matches_pending_candidate(&record, &decision_record) {
                    return Err(Error::InvariantViolation(
                        "preflight gate decision does not match pending candidate",
                    ));
                }
                record
            } else {
                // Caller-owned transactions have no same-transaction preflight
                // identity, so they always mint a new attachment receipt.
                store.append_fresh_gate_decision_in_txn(wtxn, &mut decision_record)?;
                record_gate_decision_metrics(&decision);
                decision_record.clone()
            };
            let pending = PendingGateConsentRecord {
                version: crate::store::PENDING_GATE_CONSENT_VERSION,
                claim_id: *id.as_bytes(),
                decision_id: pending_decision.decision_id,
                created_at: pending_decision.created_at,
                diff_handle: pending_decision.diff_handle,
                read_frontier_hash: pending_decision.read_frontier_hash,
                reason_codes: if attach_critical_confirm {
                    vec![GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED.to_owned()]
                } else {
                    pending_decision.reason_codes
                },
                dreamer_run_id: pending_consent_dreamer_run_id(envelope, body),
            };
            store.put_pending_gate_consent_in_txn(wtxn, &pending)?;
            // This is the sole reopening transition: a successful local
            // critical-confirm attachment replaces the invalidated ceremony in
            // this transaction. Pending ordinary work and replicated input do
            // not clear the claim-scoped marker.
            if attach_critical_confirm {
                store.delete_critical_confirm_invalidation_in_txn(wtxn, id)?;
            }
        }

        enforce_claim_gate_decision_with_consent(
            store,
            wtxn,
            id,
            &decision,
            body.approval,
            &binding,
            GateWriteMode {
                resolve_pending: mode.resolve_pending && !attach_critical_confirm,
                ..mode
            },
        )?;
    }

    check_claim_source_trust(body, policy)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateWriteMode {
    pub(crate) record_decision: bool,
    pub(crate) persist_pending_consent: bool,
    pub(crate) resolve_pending: bool,
    pub(crate) can_resolve_pending_consent: bool,
    pub(crate) include_source_in_gate_input: bool,
}

pub(crate) struct ClaimGateWrite<'a> {
    pub(crate) body: &'a ClaimBody,
    pub(crate) envelope: Option<&'a WriteEnvelope>,
    pub(crate) defer_metrics_until_commit: bool,
}

pub(crate) struct RecordedClaimGateDecision {
    record: GateDecisionRecord,
    decision: GateDecision,
}

impl RecordedClaimGateDecision {
    pub(crate) fn decision_id(&self) -> GateDecisionId {
        self.record.decision_id
    }

    pub(crate) fn outcome(&self) -> &str {
        &self.record.outcome
    }

    pub(crate) fn record_metrics(&self) {
        record_gate_decision_metrics(&self.decision);
    }

    pub(crate) fn into_record(self) -> GateDecisionRecord {
        self.record
    }
}

pub(crate) fn check_reserved_claim_policy(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    check_claim_source_trust(body, policy)
}

#[cfg(feature = "sync")]
pub(crate) fn check_federated_claim_admission(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    let decision = federated_claim_admission_decision(body, policy);
    record_gate_decision_metrics(&decision);
    enforce_gate_decision(decision)
}

#[cfg(feature = "sync")]
fn federated_claim_admission_decision(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> GateDecision {
    if policy.enforces_write_gate() && policy.is_fail_closed() {
        return GateDecision::deny(GateReasonCode::DenyPolicyFailClosed);
    }

    if !policy.source_trust_allows_auto(body.source, claim_sensitivity_band(body)) {
        return GateDecision::pending(vec![GateReasonCode::PendingSourceTrust]);
    }

    GateDecision::allow()
}

pub(crate) fn validate_write_envelope(envelope: &WriteEnvelope) -> Result<()> {
    if matches!(envelope.provenance().value(), &Value::Nil) {
        return Err(Error::InvalidClaimBody("write envelope missing provenance"));
    }

    Ok(())
}

fn pending_consent_dreamer_run_id(
    envelope: Option<&WriteEnvelope>,
    body: &ClaimBody,
) -> Option<String> {
    if body.approval != ClaimApprovalStatus::Proposed || body.source != Some(ClaimSource::Generated)
    {
        return None;
    }

    let envelope = envelope?;
    dreamer_run_id_from_write_envelope(envelope)
}

fn dreamer_run_id_from_write_envelope(envelope: &WriteEnvelope) -> Option<String> {
    if envelope.source() != ClaimSource::Generated
        || envelope.actor().actor_class() != EdgeActorClass::Agent
    {
        return None;
    }
    dreamer_run_id_from_provenance(envelope.provenance().value())
}

fn dreamer_run_id_from_provenance(value: &Value) -> Option<String> {
    let Value::Map(entries) = value else {
        return None;
    };
    if !entries.iter().any(|(key, value)| {
        key.as_str().is_some_and(|key| {
            key == DREAMER_PROVENANCE_RUNNER_KEY || key == DREAMER_PROVENANCE_SURFACE_KEY
        }) && value.as_str() == Some(DREAMER_RUNNER_ATTEMPT_KIND)
    }) {
        return None;
    }

    [DREAMER_PROVENANCE_RUN_ID_KEY, DREAMER_PROVENANCE_RUN_KEY]
        .into_iter()
        .find_map(|run_key| {
            entries.iter().find_map(|(key, value)| {
                if key.as_str() != Some(run_key) {
                    return None;
                }
                let run_id = value.as_str()?.trim();
                (!run_id.is_empty()).then(|| run_id.to_owned())
            })
        })
}

pub(crate) fn check_edge_provenance_claim_policy(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
    record: &crate::provenance::EdgeProvenanceClaimBody,
    actor_class: EdgeActorClass,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    if policy.enforces_write_gate() {
        let agent_definition_ceiling = agent_definition_ceiling_for_actor(
            store,
            txn,
            WriteActor::new(record.actor_entity_ref, actor_class),
        );
        let input = claim_gate_input(
            body,
            policy,
            GateActor {
                actor_class: edge_actor_class_str(actor_class).to_owned(),
                actor_ref: Some(record.actor_entity_ref.to_hex()),
                delegation_grant_ref: None,
            },
            GateContentKind::EdgeProvenanceClaim,
            GateProvenanceHandles {
                actor_entity_ref: Some(record.actor_entity_ref),
                substrate_ref: record.substrate_ref,
                source_revision_ref: record.source_revision_ref,
                body_snapshot_ref: record.body_snapshot_ref,
                ..GateProvenanceHandles::default()
            },
            false,
            agent_definition_ceiling,
            // Edge-provenance claims, like ordinary claims, carry no effect-fact
            // axes; the door keeps its pre-DEC-0006 behaviour (None arm).
            None,
        );
        let decision = policy.evaluate_gate(&input);
        record_gate_decision_metrics(&decision);
        enforce_gate_decision(decision)?;
    }

    check_claim_source_trust(body, policy)
}

// The claim-door assembler takes the full axis tuple one call site at a time
// spells out; boxing the tail two `Option` knobs would hide the consent seam
// this lane opened.
#[allow(clippy::too_many_arguments)]
pub(super) fn claim_gate_input(
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

pub(super) fn enforce_gate_decision(decision: GateDecision) -> Result<()> {
    if decision.outcome() == GateOutcome::Allow {
        return Ok(());
    }

    reject_gate_decision(decision)
}

pub(super) struct GateConsentBinding {
    pub(super) diff_handle: Vec<u8>,
    pub(super) read_frontier_hash: [u8; 32],
}

impl GateConsentBinding {
    fn for_claim(body: &ClaimBody, policy: &PolicyManifestResolution) -> Result<Self> {
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
    pub(super) fn for_external_effect(
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

pub(crate) fn standing_outbound_grant_binding_parts(
    intent: &GrantMintIntent,
    policy: &PolicyManifestResolution,
) -> Result<(Vec<u8>, [u8; 32])> {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"oneiron.gate.standing_outbound_grant.v0");
    hash_str(&mut hasher, intent.principal_ref.trim());
    hash_str(&mut hasher, intent.origin_component_id.trim());
    hash_str(&mut hasher, intent.origin_action_id.trim());
    hash_opt_str(&mut hasher, intent.origin_receipt_ref.as_deref());
    match &intent.scope {
        GrantMintIntentScope::JustOnce { .. } => {
            return Err(Error::InvalidOutboundGrantBody(
                "non-standing grant scope is not supported",
            ));
        }
        GrantMintIntentScope::Contact { contact_ref } => {
            hash_str(&mut hasher, "contact");
            hash_str(&mut hasher, contact_ref.trim());
        }
        GrantMintIntentScope::VerbClass { verb_class } => {
            hash_str(&mut hasher, "verb_class");
            hash_str(&mut hasher, verb_class.trim());
        }
        GrantMintIntentScope::Channel { channel } => {
            hash_str(&mut hasher, "channel");
            hash_str(&mut hasher, channel.trim());
        }
        GrantMintIntentScope::BundleExactSends { .. } => {
            return Err(Error::InvalidOutboundGrantBody(
                "non-standing grant scope is not supported",
            ));
        }
        GrantMintIntentScope::BriefVerbClass {
            brief_ref,
            verb_class,
        } => {
            hash_str(&mut hasher, "brief_verb_class");
            hash_str(&mut hasher, brief_ref.trim());
            hash_str(&mut hasher, verb_class.trim());
        }
        GrantMintIntentScope::Calendar { .. } => {
            return Err(Error::InvalidOutboundGrantBody(
                "calendar disclosure scope is a read grant, not an outbound grant scope",
            ));
        }
    }
    Ok((hasher.finalize().to_vec(), policy.read_frontier_hash()?))
}

fn gate_decision_matches_pending_candidate(
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

fn enforce_claim_gate_decision_with_consent(
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
        return Err(Error::GateConsentStale { claim_id: *id });
    }
    Ok(())
}

fn reject_gate_decision(decision: GateDecision) -> Result<()> {
    Err(Error::GateWriteRejected {
        outcome: decision.outcome().as_str(),
        reason_codes: decision
            .reason_codes()
            .iter()
            .map(|code| code.as_str())
            .collect(),
    })
}

fn local_write_actor_entity_ref() -> EntityId {
    EntityId::from_bytes(LOCAL_WRITE_ACTOR_ENTITY_REF)
        .expect("local Gate actor entity ref is non-reserved")
}

pub(super) const fn edge_actor_class_str(actor_class: EdgeActorClass) -> &'static str {
    actor_class.gate_actor_class()
}
