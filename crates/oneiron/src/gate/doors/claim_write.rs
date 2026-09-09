//! Claim write entry seams plus the phase-ordered inner executor.

use super::breaker_staging::{self, GateBreakerAccounting, RecordedClaimGateDecision};
use super::consent::{
    GateConsentBinding, claim_gate_input, enforce_claim_gate_decision_with_consent,
    gate_decision_matches_pending_candidate, reject_gate_decision,
};
use super::dreamer_run::{
    dreamer_isolation_decision, dreamer_precommit_denial, dreamer_run_id_from_write_envelope,
    pending_consent_dreamer_run_id,
};
use super::peripheral::{
    ClaimGateWrite, GateWriteMode, auto_check_value_preview, edge_actor_class_str,
    local_write_actor_entity_ref, validate_write_envelope, write_envelope_actor_ref,
};
use crate::claim::{ClaimApprovalStatus, claim_sensitivity_band, dreamer_isolation_class};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::confirm::{
    GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED, GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED,
    critical_claim_can_land_auto_with_confirm,
};
use crate::gate::constants::LOCAL_WRITE_ACTOR_CLASS;
use crate::gate::decision::{
    GateDecision, GateOutcome, GateReasonCode, record_gate_decision_metrics,
};
use crate::gate::definition_ceiling::agent_definition_ceiling_for_actor;
use crate::gate::input::{GateActor, GateContentKind, GateProvenanceHandles};
use crate::gate::resolution::{PolicyManifestResolution, check_claim_source_trust};
use crate::llm::{AutoCheckCandidate, AutoCheckOutcome, AutoChecker};
use crate::store::{
    GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store,
    checker_hold_receipt_reason,
};
use crate::write_envelope::{SourceLineage, WriteEnvelope};

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
pub(crate) fn check_claim_policy_for_write(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    operation_effect_body: bool,
) -> Result<()> {
    let mut recorded_decision = None;
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        &mut recorded_decision,
        None,
        operation_effect_body,
        // A pre-check door DISCARDS its receipt, so it cannot carry a
        // breaker demotion into the write that materializes the body. The
        // ordinary batch preflight books that event instead; counting it here
        // too would debit one write twice.
        GateBreakerAccounting::Exempt,
    )
}

// The pending-bind seam threads the preflight receipt identity one parameter
// further than the record seam; bundling the axis tuple would hide the
// preflight decision binding this lane opened.
pub(crate) fn check_claim_policy_for_write_with_preflight_decision(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    preflight_decision_id: Option<GateDecisionId>,
) -> Result<()> {
    let mut recorded_decision = None;
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        &mut recorded_decision,
        preflight_decision_id,
        // The batch/replay claim door only ever carries PERSISTED candidates,
        // so it never opens the synthetic-operation mode.
        false,
        // Phase-2 materialization replays an identity the preflight already
        // booked. Re-counting it would debit the breaker twice for one write.
        GateBreakerAccounting::Exempt,
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
        // Exempt by default. A door earns breaker accounting by being able to
        // CARRY the demotion into the body it materializes, and this seam's
        // callers — claim lifecycle transitions, the session-bundle merge, the
        // commitment gap-decay preflight — materialize through paths that
        // consume no staged verdict.
        GateBreakerAccounting::Exempt,
    )
}

// The inner executor carries the outer record seam's axis tuple plus the
// preflight identity exactly once; a parameter struct would only rename the
// same boundary.
#[allow(clippy::too_many_arguments)]
pub(super) fn check_claim_policy_for_write_with_record_inner(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
    preflight_decision_id: Option<GateDecisionId>,
    operation_effect_body: bool,
    breaker_accounting: GateBreakerAccounting,
) -> Result<()> {
    let ClaimGateWrite {
        body,
        envelope,
        auto_checker,
        defer_metrics_until_commit,
    } = write;
    *recorded_decision = None;
    if let Some(envelope) = envelope {
        validate_write_envelope(envelope)?;
    }

    // Preserve the write's member identities for both source-trust checks:
    // the evaluator below and the final Auto ceiling check. No member's
    // permit can answer for a different member of the observed history.
    let lineage = envelope.map(WriteEnvelope::lineage);

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
    // ONE-1453 keys its rows on the SAME run id the pending-consent path
    // carries. The detection above already restricts it to an `Agent` actor
    // on a Dreamer run surface, so an owner-interactive write is outside the
    // breaker even when a caller supplies run-shaped metadata.
    let breaker_run_id = dreamer_run_id.clone();
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
            // Restricted lineage also needs the declared source's normal
            // check and candidate sensitivity, even for non-Auto public writes.
            // This boolean controls input shape, not permit authorization.
            mode.include_source_in_gate_input
                || envelope.is_some_and(WriteEnvelope::effective_requires_explicit_auto_permit),
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
            None => policy.evaluate_gate_with_lineage(&input, lineage),
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

        // ONE-1296: the host's auto checker is the LAST word on an ORDINARY
        // Auto verdict, and only that. It runs after everything the engine
        // decides for itself — pre-commit validity, the policy verdict,
        // GATE-13 isolation, the critical-confirm attachment — so a write
        // already refused or already parked is never consulted about, and the
        // checker can only NARROW a verdict, never widen one.
        //
        // The consult is EXACTLY: a manifest names a checker, a checker is
        // injected for this write, the ordinary decision is Auto, the write is
        // an agent-class Dreamer write, and its source is one that requires an
        // explicit auto permit. Human and owner writes therefore never reach a
        // checker at all, and neither does any door that passes `None`.
        //
        // A confirm-attached Auto is excluded because it is not the ordinary
        // verdict: the ordinary verdict there was a criticality-floor PEND,
        // and what replaced it is an owner ceremony bound to this exact claim.
        // A host hedge must not overrule a confirmation the owner just gave,
        // and rewriting that decision would also drop the criticality marker
        // the inbox classifies on.
        //
        // ONE-1314 widens this source check to source OR lineage.
        // This only selects a checker consult; authorization still checks
        // each restricted lineage member's own permit above and below.
        let mut checker_receipt_reasons: Vec<String> = Vec::new();
        if decision.outcome() == GateOutcome::Allow
            && !attach_critical_confirm
            && dreamer_candidate
            && policy.auto_checker().is_some()
            && let Some(checker) = auto_checker
            && let Some(source) = body.source.filter(|source| {
                source.requires_explicit_auto_permit()
                    || lineage.is_some_and(SourceLineage::requires_explicit_auto_permit)
            })
        {
            let value_preview = auto_check_value_preview(&body.value);
            let candidate = AutoCheckCandidate {
                predicate: &body.predicate,
                value_preview: &value_preview,
                source,
                lineage,
                actor_class: &input.actor.actor_class,
                sensitivity_band: claim_sensitivity_band(body),
            };
            // The concrete wrapper is required at every injection boundary:
            // one capacity-bounded consult, with panic and timeout isolation.
            match checker.check(&candidate) {
                AutoCheckOutcome::Allow => {}
                AutoCheckOutcome::Hold { reasons } => {
                    // A host names its reasons in prose; the decision ledger's
                    // receipt field is a closed token vocabulary vetted on the
                    // append AND decode paths. Rendering them here is what
                    // keeps a hold RECORDABLE: the raw text would fail the vet
                    // and cost the whole decision row, so the write the
                    // checker meant to park would fail with a corrupt-ledger
                    // error instead of parking.
                    checker_receipt_reasons = reasons
                        .iter()
                        .filter_map(|reason| checker_hold_receipt_reason(reason.as_str()))
                        .collect();
                    // Same rule `AutoCheckOutcome::normalized` already applies
                    // one step earlier: a hold left naming no reason is a
                    // malformed verdict, not a quiet hold, and an unexplained
                    // refusal on the receipt is the one thing this seam must
                    // not produce. Both verdicts park the write, so nothing
                    // widens either way.
                    decision = if checker_receipt_reasons.is_empty() {
                        GateDecision::pending(vec![GateReasonCode::PendingCheckerUnavailable])
                    } else {
                        GateDecision::pending(vec![GateReasonCode::PendingChecker])
                    };
                }
                AutoCheckOutcome::Unavailable => {
                    decision =
                        GateDecision::pending(vec![GateReasonCode::PendingCheckerUnavailable]);
                }
            }
        }

        let binding = GateConsentBinding::for_claim(body, policy)?;
        let decision_id = GateDecisionId::now();
        let created_at = crate::unix_seconds_now();

        let breaker = breaker_staging::OriginalBreakerEvent {
            accounting: breaker_accounting,
            record_decision: mode.record_decision,
            run_id: breaker_run_id.as_deref(),
            input: &input,
            policy,
            binding: &binding,
            body,
            attach_critical_confirm,
            created_at,
        }
        .apply(store, wtxn, &mut decision)?;
        let breaker_demoted = breaker
            .as_ref()
            .is_some_and(|applied| applied.breaker_demoted);
        let effective_approval = if breaker_demoted {
            ClaimApprovalStatus::Proposed
        } else {
            body.approval
        };

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
                // The checker's own reasons append to the receipt, rendered
                // above into the ledger's token vocabulary: an owner reviewing
                // a held write reads WHY the host held it, not just that
                // something did.
                .chain(checker_receipt_reasons)
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
                breaker_demoted,
                breaker_undo: breaker
                    .as_ref()
                    .and_then(|applied| applied.breaker_undo.clone()),
            };
            if !defer_metrics_until_commit {
                recorded.record_metrics();
            }
            *recorded_decision = Some(recorded);
        }

        if mode.persist_pending_consent
            && ((decision.outcome() == GateOutcome::Pending
                && effective_approval == ClaimApprovalStatus::Proposed)
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
                dreamer_run_id: if breaker_demoted {
                    // Breaker accounting already required and validated a
                    // nonempty run id for this write, so failing to recover it
                    // here is an invariant error rather than `None`. The
                    // landed derivation cannot be reused: it narrows on the
                    // body's own `Proposed` stamp, and a demoted body still
                    // reads `Auto` until `batch` re-encodes it.
                    Some(
                        envelope
                            .and_then(dreamer_run_id_from_write_envelope)
                            .ok_or(Error::InvariantViolation(
                                "breaker-demoted pending consent lost its dreamer run id",
                            ))?,
                    )
                } else {
                    pending_consent_dreamer_run_id(envelope, body)
                },
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
            effective_approval,
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
    check_claim_source_trust(body, actor_ref.as_deref(), policy, lineage)
}
