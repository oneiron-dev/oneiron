use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, DreamerIsolationClass, claim_sensitivity_band,
    dreamer_isolation_class,
};
use crate::compaction::turn_session_membership_in_txn;
use crate::dreamer_consolidation::decode_consolidation_evidence;
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::{WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY, WriteActor, WriteEnvelope};

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
use super::decision::{GateDecision, GateOutcome, GateReasonCode, record_gate_decision_metrics};
use super::definition_ceiling::agent_definition_ceiling_for_actor;
use super::dreamer_precommit::{DreamerPrecommitInput, validate_dreamer_precommit};
use super::input::{
    ConsentGateContext, GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles,
};
use super::resolution::{
    PolicyManifestResolution, check_claim_source_trust, hash_bool, hash_bytes, hash_opt_str,
    hash_str, resolve_policy_manifest,
};

/// The claim write door.
///
/// `operation_effect_body` is the HOST-CONSTRUCTED synthetic-operation mode
/// the GATE-12 block below describes: it is spelled at the call site, never
/// derived from the body, envelope, provenance, predicate, value, approval or
/// actor, and every persisted-candidate caller passes `false`. The seam is an
/// explicit parameter rather than a `GateWriteMode` field so that a caller
/// cannot inherit it by copying a mode value around: a door that means it has
/// to say so, here, in its own call.
// The synthetic-operation mode is spelled beside the axis tuple rather than
// folded into it, for the reason the doc comment gives.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_claim_policy_for_write(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    envelope: Option<&WriteEnvelope>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    operation_effect_body: bool,
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
        operation_effect_body,
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
        // The batch/replay claim door only ever carries PERSISTED candidates,
        // so it never opens the synthetic-operation mode.
        false,
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
        // Every caller of the record seam writes a persisted candidate.
        false,
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
    operation_effect_body: bool,
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

    // ONE-1314: the write's OWN history, read once here and consulted by both
    // auto-permit decisions this door makes (the evaluator's source-trust
    // pend below, and the ceiling check at the end). An envelope-less local
    // write has no history to read and keeps its exact prior verdict.
    let lineage_requires_auto_permit = envelope_lineage_requires_auto_permit(envelope);

    // GATE-12: Dreamer authorship is detected exactly once, here, and the
    // provenance handle carries it into the evaluator input below. Pre-commit
    // validation asks whether the CLAIM IS VALID, not whether the author is
    // authorized, so it is computed OUTSIDE the `enforces_write_gate` arm: a
    // vault with no policy manifest loaded still refuses a degenerate,
    // malformed or evidence-free Dreamer candidate instead of letting the
    // bootstrap path commit it unchecked.
    //
    // `operation_effect_body` is the ONE exception, and it is not an exemption
    // from the floor: a host-typed synthetic memory-verb effect body is GATE
    // MATERIAL, never a persisted claim (the verb's traps persist a lifecycle
    // Put plus an Edge, never the body they gate), so asking a claim-candidate
    // question of it is a category error rather than a check it evades. The
    // mode is HOST-CONSTRUCTED at the three synthetic call sites in
    // `claim/put.rs` and is never read off the body, envelope, provenance,
    // predicate, value, approval or actor. It skips pre-commit validation and
    // NOTHING else: detection above, the provenance handles below, policy
    // authority, pending/source-trust behaviour and decision recording all run
    // unchanged — and every persisted Dreamer claim candidate, on every
    // candidate door, still clears the full evidence floor.
    let dreamer_run_id = envelope.and_then(dreamer_run_id_from_write_envelope);
    let dreamer_candidate = dreamer_run_id.is_some() && !operation_effect_body;
    let precommit_denial = if dreamer_candidate {
        dreamer_precommit_denial(store, &*wtxn, body)
    } else {
        None
    };

    if policy.enforces_write_gate() {
        let (actor, provenance, agent_definition_ceiling) = if let Some(envelope) = envelope {
            let actor = envelope.actor();
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
        // A pre-commit failure REPLACES the policy verdict: the recording,
        // pending and enforcement paths below then run unchanged, and the
        // Deny aborts the caller's batch op before any claim-side write lands.
        let mut decision = match precommit_denial {
            Some(reason_code) => GateDecision::deny(reason_code),
            None => policy.evaluate_gate_with_lineage(&input, lineage_requires_auto_permit),
        };
        // GATE-13: persona-core and mirroring-prone predicates are isolated
        // for the DREAMER path only, and only AFTER the validity pass above.
        // Authorship reuses the one detection computed at the top of this
        // door, so there is no second notion of "is this a Dreamer write";
        // owner/human writes never enter, and replicated replay never reaches
        // this module at all.
        //
        // The guard is deny-first in both directions. A denial already
        // returned — a GATE-12 validity refusal or a fail-closed policy
        // verdict — is stricter than anything isolation would say, so it
        // stands; isolation may only refuse or park a write that would
        // otherwise have been allowed. It also runs BEFORE the
        // critical-confirm attachment below, whose exact single-code match on
        // `[PendingCriticalityFloor]` an isolation pend can therefore never
        // satisfy: a persona-core write has no confirm-attached Auto path.
        if dreamer_candidate
            && decision.outcome() != GateOutcome::Deny
            && let Some(isolation_class) = dreamer_isolation_class(&body.predicate)
        {
            decision = dreamer_isolation_decision(store, &*wtxn, body, isolation_class);
        }
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
    } else if let Some(reason_code) = precommit_denial {
        // No manifest is loaded, so there is no policy verdict for the denial
        // to replace and no gate-decision row this bootstrap path would have
        // written anyway. The refusal itself is not optional: the same Deny
        // reaches the caller and aborts the batch op before any claim-side
        // write lands, so an absent manifest cannot be used to smuggle an
        // invalid Dreamer claim past the pre-commit floor.
        return reject_gate_decision(GateDecision::deny(reason_code));
    }

    let actor_ref = write_envelope_actor_ref(envelope);
    check_claim_source_trust(
        body,
        actor_ref.as_deref(),
        policy,
        lineage_requires_auto_permit,
    )
}

/// The hex actor ref an envelope attributes a write to, for source-trust row
/// selection. An envelope-less local write stays unattributed (`None`) and so
/// never rides an actor-bound permit.
fn write_envelope_actor_ref(envelope: Option<&WriteEnvelope>) -> Option<String> {
    envelope.map(|envelope| envelope.actor().entity_ref().to_hex())
}

/// ONE-1314: whether the write's observed lineage requires an explicit auto
/// permit. An envelope-less write declares no history, so it answers `false`
/// and keeps the pre-lineage verdict exactly.
fn envelope_lineage_requires_auto_permit(envelope: Option<&WriteEnvelope>) -> bool {
    envelope.is_some_and(WriteEnvelope::effective_requires_explicit_auto_permit)
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
    envelope: Option<&WriteEnvelope>,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    let actor_ref = write_envelope_actor_ref(envelope);
    // Envelope-bearing local write path (the batch reserved-predicate door),
    // so it reads the same two axes the main write door reads.
    check_claim_source_trust(
        body,
        actor_ref.as_deref(),
        policy,
        envelope_lineage_requires_auto_permit(envelope),
    )
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

    // Replicated input carries no local write actor, so it is unattributed for
    // row selection and can never ride an actor-bound permit.
    if !policy.source_trust_allows_auto(body.source, claim_sensitivity_band(body), None) {
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

/// Runs the GATE-12 pre-commit checks for one Dreamer-authored candidate,
/// returning the pinned denial reason when a check refuses it.
///
/// The existence resolver answers "does this ref resolve to a LIVE entity",
/// through the PASSED transaction and nothing else. An absent key, an
/// unparseable header, a read or deletion-metadata error, and an ARCH-0038
/// soft-delete shell (a header-only row whose tombstone is pending or
/// published) are all "does not resolve" rather than an abort — the floor is
/// looking for one ref that DOES resolve, and every unreadable or erased
/// state is fail-closed non-evidence. Reading through the caller's
/// transaction is what keeps a ref written earlier in the SAME write
/// transaction resolvable, so the miner's write-then-gate order still holds;
/// a live zero-byte payload, which carries no deletion metadata, also still
/// resolves. Liveness is the whole question here: the floor stays
/// type-agnostic.
fn dreamer_precommit_denial(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Option<GateReasonCode> {
    let resolves =
        |id: &EntityId| -> Result<bool> { Ok(live_entity_row_in_txn(store, txn, id)?.is_live()) };

    validate_dreamer_precommit(
        &DreamerPrecommitInput {
            predicate: &body.predicate,
            value: &body.value,
            confidence: body.confidence,
            // `ClaimBody::subject` is a total `ClaimSubject`, so a body that
            // reaches this door always carries one; the validator keeps the
            // axis explicit for the shape contract it pins.
            subject_present: true,
            evidence: body.evidence.as_ref(),
        },
        &resolves,
    )
    .err()
}

/// How many distinct SESSION entities a persona-core Dreamer write must cite
/// before it may be parked for owner review (GATE-13).
///
/// Two is the smallest number that cannot be one conversation. A persona head
/// moves on DELIBERATE transformation — something the owner returned to across
/// sittings — so a single cycle, however emphatic inside itself, is refused
/// rather than queued.
const PERSONA_CORE_MIN_DISTINCT_SESSIONS: usize = 2;

/// The isolation verdict for one Dreamer-authored candidate whose predicate
/// carries an isolation class.
///
/// Both classes force the ceiling to Proposed and both carry the EXISTING
/// criticality marker beside their own code, so the inbox projection keeps
/// classifying them `ManifestCritical` through the equality it already has —
/// no new inbox variant, and no dial that can waive the row.
fn dreamer_isolation_decision(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
    isolation_class: DreamerIsolationClass,
) -> GateDecision {
    match isolation_class {
        DreamerIsolationClass::PersonaCore => {
            let sessions = distinct_evidence_session_count(store, txn, body);
            if sessions < PERSONA_CORE_MIN_DISTINCT_SESSIONS {
                GateDecision::deny(GateReasonCode::DenyPersonaSingleCycle)
            } else {
                GateDecision::pending(vec![
                    GateReasonCode::PendingPersonaIsolation,
                    GateReasonCode::PendingCriticalityFloor,
                ])
            }
        }
        DreamerIsolationClass::MirroringProne => GateDecision::pending(vec![
            GateReasonCode::PendingMirroringIsolation,
            GateReasonCode::PendingCriticalityFloor,
        ]),
    }
}

/// Counts the DISTINCT sittings the candidate's own evidence reaches.
///
/// Read from the candidate's `candidate_evidence` payload through the same
/// codec the GATE-12 floor uses, and resolved through the CALLER's
/// transaction so a turn written earlier in this write transaction still
/// answers. Every unreadable state is non-evidence rather than an abort: a
/// legacy payload shape, a structurally broken envelope, a ref that does not
/// resolve, a ref that resolves to something other than a TURN, a turn with
/// no recorded sitting, and a recorded sitting that does not resolve to a
/// live SESSION all fail closed and simply do not count.
fn distinct_evidence_session_count(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> usize {
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return 0;
    };
    let Some(candidate_evidence) = entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)).then_some(value)
    }) else {
        return 0;
    };
    let Ok(Some(evidence)) = decode_consolidation_evidence(candidate_evidence) else {
        return 0;
    };

    let mut sessions: Vec<EntityId> = Vec::new();
    for entity_ref in &evidence.refs {
        let Some(session) = evidence_ref_session(store, txn, entity_ref) else {
            continue;
        };
        if !sessions.contains(&session) {
            sessions.push(session);
        }
    }
    sessions.len()
}

/// The sitting one evidence ref speaks from: the ref must resolve to a live
/// TURN, that turn must carry a RECORDED session membership, and the
/// membership must itself resolve to a live SESSION.
///
/// Membership is the engine-written fact recorded beside the turn at witness
/// time, never a caller-authored field on the turn body — a body a writer
/// controls could otherwise name any sitting it liked and manufacture the
/// second cycle this floor exists to require.
fn evidence_ref_session(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity_ref: &EntityId,
) -> Option<EntityId> {
    if !live_entity_row_has_type(store, txn, entity_ref, ENTITY_TYPE_TURN) {
        return None;
    }
    let session = turn_session_membership_in_txn(store, txn, entity_ref)
        .ok()
        .flatten()?;
    live_entity_row_has_type(store, txn, &session, ENTITY_TYPE_SESSION).then_some(session)
}

/// Whether `id` reads back as a LIVE row of exactly `entity_type`. A read
/// error, an absent row and an erased shell are all `false`.
fn live_entity_row_has_type(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> bool {
    matches!(
        live_entity_row_in_txn(store, txn, id),
        Ok(LiveEntityRow::Live { entity_type: found, .. }) if found == entity_type
    )
}

/// The Dreamer run this write is authored by, if any.
///
/// Authorship is a property of the WRITE, read off provenance and
/// SOURCE-AGNOSTIC: `Agent` actor class, the Dreamer run surface/runner
/// marker, and a non-empty run id. `envelope.source()` is the computed
/// evidence meet — epistemic taint derived FROM the candidate's evidence —
/// so a truthful `ToolOutput` or `Observed` meet says how well the claim is
/// known, never who wrote it, and must not disable the deny-first GATE-12
/// floor. Source narrowing answers the other question, owner-review
/// grouping, and lives solely in `pending_consent_dreamer_run_id`.
pub(super) fn dreamer_run_id_from_write_envelope(envelope: &WriteEnvelope) -> Option<String> {
    if envelope.actor().actor_class() != EdgeActorClass::Agent {
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

    let actor_ref = record.actor_entity_ref.to_hex();
    // Edge-provenance claims arrive with no write envelope, so there is no
    // observed lineage to read: declared-source only, exactly as before.
    check_claim_source_trust(body, Some(actor_ref.as_str()), policy, false)
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
