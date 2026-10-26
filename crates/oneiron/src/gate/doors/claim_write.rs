//! Claim write entry seams plus the phase-ordered inner executor.

mod decision_context;
mod reference_read;

use super::burst_inputs::claim_burst_inputs;
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
use super::recorded::RecordedClaimGateDecision;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, VerifiedClaimTransition};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, DreamerIsolationClass,
    claim_sensitivity_band, decode_claim_body, dreamer_isolation_class, encode_claim_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::confirm::{
    GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED, GATE_REASON_ALLOW_CRITICAL_OWNER_AUTHORED,
    GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED, critical_claim_can_land_auto_with_confirm,
    pending_row_holds_critical_confirm,
};
use crate::gate::constants::LOCAL_WRITE_ACTOR_CLASS;
use crate::gate::decision::{GateDecision, GateOutcome, GateReasonCode};
use crate::gate::definition_ceiling::agent_definition_ceiling_for_actor;
use crate::gate::input::{GateActor, GateContentKind, GateProvenanceHandles};
use crate::gate::resolution::{PolicyManifestResolution, check_claim_source_trust};
use crate::llm::{AutoCheckCandidate, AutoCheckOutcome};
use crate::ports::EntityStoreRead;
use crate::store::{
    GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store, TrayRemoval,
    checker_hold_receipt_reason,
};
use crate::write_envelope::{SourceLineage, WriteEnvelope};

/// The receipt reason of a write held because its value does not fit the auto
/// checker's preview, so no checker could review all of it.
const CHECKER_PARTIAL_VIEW_RECEIPT_REASON: &str = "checker_partial_view";

/// Whether this write only closes the stored row: the row's own value, now
/// closed, under a verified in-place transition. It admits nothing new, so no
/// checker is consulted and none is required, whatever the value's length: a
/// restriction always lands.
fn closes_stored_value(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    transition: Option<&VerifiedClaimTransition>,
) -> bool {
    closes_in_place(store, txn, id, body, transition)
        && stored_claim_body(store, txn, id).is_some_and(|stored| stored.value == body.value)
}

/// Whether this write is the stored row's own close and nothing more: the
/// stored Active body with only its lifecycle and `valid_to` changed, as the
/// canonical lifecycle validator admits it. An edit that also moves approval
/// or any other field is not one.
fn closes_stored_row_only(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    transition: Option<&VerifiedClaimTransition>,
) -> bool {
    closes_in_place(store, txn, id, body, transition)
        && stored_claim_body(store, txn, id).is_some_and(|mut stored| {
            if stored.lifecycle != ClaimLifecycleStatus::Active {
                return false;
            }
            stored.lifecycle = body.lifecycle;
            stored.valid_to = body.valid_to;
            match (encode_claim_body(&stored), encode_claim_body(body)) {
                (Ok(closed), Ok(written)) => closed == written,
                _ => false,
            }
        })
}

/// A non-Active body under a verified in-place transition of the same row.
fn closes_in_place(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    transition: Option<&VerifiedClaimTransition>,
) -> bool {
    body.lifecycle != ClaimLifecycleStatus::Active
        && transition.is_some_and(|proof| {
            proof.predecessor().is_none()
                && proof.matches_body(store, txn, id, body).unwrap_or(false)
        })
}

/// The stored row's claim body, when it decodes.
fn stored_claim_body(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Option<ClaimBody> {
    let raw = store.port_entity_record(txn, id).ok().flatten()?.encode();
    decode_claim_body(raw.get(ENTITY_METADATA_HEADER_LEN..)?, true).ok()
}

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
        None,
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
        None,
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
        None,
    )
}

/// [`check_claim_policy_for_write_with_record`] for a writer whose own scoped
/// read the caller holds (OF-063, FIX 1218): every typed record ref the body
/// names must resolve under `reader` in this final write's snapshot. One that
/// does not is the door's verdict, a hard Deny
/// (`gate.deny.unresolved_record_reference`) recorded on the ordinary path,
/// that no isolation, confirmation, checker, source trust or Proposed lane
/// overrides. Missing and unreadable are the same refusal. Everything else is
/// the record seam's, unchanged; a trusted caller with no reader keeps that
/// seam.
#[expect(
    clippy::too_many_arguments,
    reason = "the record seam's arguments plus the writer's own scoped read"
)]
pub(crate) fn check_claim_policy_for_write_with_record_with_reader(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
    reader: &crate::claim::ScopedRead<'_>,
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
        false,
        Some(reader),
    )
}

/// The isolation class of a Dreamer candidate's predicate: a prefix a trusted
/// pack declares persona-core (`persona_core_prefixes`, H393) first, so the
/// host names its own protected namespace and the engine names none; else the
/// built-in tables.
fn isolation_class(
    policy: &PolicyManifestResolution,
    predicate: &str,
) -> Option<DreamerIsolationClass> {
    if policy
        .persona_core_prefixes
        .iter()
        .any(|prefix| predicate.starts_with(prefix.as_str()))
    {
        return Some(DreamerIsolationClass::PersonaCore);
    }
    dreamer_isolation_class(predicate)
}

// The inner executor carries the outer record seam's axis tuple plus the
// preflight identity exactly once; a parameter struct would only rename the
// same boundary.
#[expect(
    clippy::too_many_arguments,
    reason = "the record seam carries the preflight receipt identity and explicit write mode"
)]
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
    reader: Option<&crate::claim::ScopedRead<'_>>,
) -> Result<()> {
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    let ClaimGateWrite {
        body,
        envelope,
        auto_checker,
        defer_metrics_until_commit,
        transition,
        owner_authored,
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
    let dreamer_candidate = dreamer_run_id.is_some() && !operation_effect_body;
    let precommit_denial = if dreamer_candidate {
        dreamer_precommit_denial(store, &*wtxn, body)
    } else {
        None
    };
    // OF-063 (FIX 1218): with the writer's own read, a record the body names
    // that does not resolve for it here, in this final snapshot, is a hard
    // deny in the same slot as a validity refusal, after it. A synthetic
    // operation body is not a persisted claim and is not judged.
    let mut reference_denial = None;
    if let Some(reader) = reader.filter(|_| !operation_effect_body)
        && let Some(field) = reference_read::unresolved_claim_reference(reader, &*wtxn, body)?
    {
        tracing::info!(%field, "a claim names a record its writer cannot read; denied");
        reference_denial = Some(GateReasonCode::DenyUnresolvedRecordReference);
    }
    let hard_denial = precommit_denial.or(reference_denial);

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
        let mut input = claim_gate_input(
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
        input.foreign_agent_ceiling = envelope
            .map(|envelope| crate::gate::foreign_agent::resolve(store, &*wtxn, envelope.actor()))
            .transpose()?
            .flatten();
        let mut decision = match hard_denial {
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
            && let Some(isolation_class) = isolation_class(policy, &body.predicate)
        {
            decision = dreamer_isolation_decision(store, &*wtxn, body, isolation_class);
        }
        // The subtype confidence floor is a Gate decision, not merely a
        // writer convention. A generic candidate can neither turn a held
        // proposal into Auto nor bypass the stricter care threshold.
        if decision.outcome() == GateOutcome::Allow
            && let Some(kind) =
                crate::write_envelope::carry_forward::CarryForwardKind::from_predicate(
                    &body.predicate,
                )
            && body.confidence
                < policy.carry_forward_floor(
                    kind,
                    envelope.map(|envelope| envelope.actor().entity_ref()),
                )
            && (body.approval == ClaimApprovalStatus::Proposed
                || body.approval == ClaimApprovalStatus::Auto
                    && !transition.is_some_and(|proof| {
                        proof.matches_body(store, &*wtxn, id, body).unwrap_or(false)
                    }))
        {
            decision = GateDecision::pending(vec![GateReasonCode::PendingCarryForwardConfidence]);
        }
        let critical_floor_only = body.approval == ClaimApprovalStatus::Auto
            && critical_claim_can_land_auto_with_confirm(
                &input,
                decision.reason_codes(),
                &body.predicate,
            );
        // Owner-authored writes carry their own confirmation: the vault's
        // owner, revalidated in this transaction, wrote this claim in person,
        // so it lands Auto with nothing to confirm. The proof rides the
        // write's options from the door that authenticated the owner; the
        // envelope only has to name the same actor.
        let owner_write = owner_authored.filter(|write| {
            envelope.is_some_and(|envelope| {
                envelope.actor().entity_ref() == write.actor()
                    && envelope.actor().actor_class() == crate::edge::EdgeActorClass::Human
            })
        });
        let owner_authored = critical_floor_only && owner_write.is_some();
        let attach_critical_confirm = critical_floor_only && !owner_authored;
        if owner_authored {
            decision = GateDecision::allow()
                .with_receipt_reasons([GATE_REASON_ALLOW_CRITICAL_OWNER_AUTHORED]);
        } else if attach_critical_confirm {
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
        // The consult is EXACTLY: a manifest names a checker, the ordinary
        // decision is Auto, the write is an agent-class Dreamer write, and its
        // source is one that requires an explicit auto permit. Human and owner
        // writes therefore never reach a checker at all. A door that injects
        // no checker for a write the manifest wants checked gets no verdict,
        // so the write pends as checker-unavailable rather than landing
        // unreviewed.
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
        let model_manifest = crate::llm::manifest::read_manifest(store, &*wtxn)?;
        let verdict_binding = model_manifest.as_ref().and_then(|m| m.verdict.as_ref());
        let mut checker_receipt_reasons: Vec<String> = Vec::new();
        if decision.outcome() == GateOutcome::Allow
            && !attach_critical_confirm
            && dreamer_candidate
            && (policy.auto_checker().is_some() || verdict_binding.is_some())
            && preflight_decision_id.is_none()
            && let Some(source) = body.source.filter(|source| {
                source.requires_explicit_auto_permit()
                    || lineage.is_some_and(SourceLineage::requires_explicit_auto_permit)
            })
            && !closes_stored_value(store, &*wtxn, id, body, transition)
        {
            // A value the preview cannot hold whole is never sent: the
            // checker would answer for a prefix while the write stores the
            // rest. With no checker to ask, the write is held below.
            let value_preview = auto_check_value_preview(&body.value);
            if value_preview.is_none() {
                checker_receipt_reasons.push(CHECKER_PARTIAL_VIEW_RECEIPT_REASON.to_owned());
            }
            let auto_checker = auto_checker.filter(|_| value_preview.is_some());
            let value_preview = value_preview.unwrap_or_default();
            let candidate = AutoCheckCandidate {
                signals: crate::gate::auto_signals::auto_check_signals(
                    store,
                    &*wtxn,
                    input.actor.actor_ref.as_deref(),
                    crate::unix_seconds_now(),
                )?,
                predicate: &body.predicate,
                value_preview: &value_preview,
                source,
                lineage,
                actor_class: &input.actor.actor_class,
                sensitivity_band: claim_sensitivity_band(body),
                burst: input
                    .provenance
                    .actor_entity_ref
                    .map(|actor| {
                        claim_burst_inputs(
                            store,
                            &*wtxn,
                            &actor,
                            &input.actor.actor_class,
                            crate::unix_seconds_now(),
                        )
                    })
                    .transpose()?,
            };
            // The concrete wrapper is required at every injection boundary:
            // one capacity-bounded consult, with panic and timeout isolation.
            let outcome = auto_checker.map_or(AutoCheckOutcome::Unavailable, |checker| {
                checker.check(&candidate)
            });
            let (outcome, verdict_note) =
                crate::llm::manifest::apply_verdict_floor(verdict_binding, outcome);
            if let Some(note) = verdict_note.and_then(checker_hold_receipt_reason) {
                checker_receipt_reasons.push(note);
            }
            match outcome {
                AutoCheckOutcome::Allow => {}
                AutoCheckOutcome::Verdict(_) => unreachable!("floor consumes calibrated outcomes"),
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
        let decision_id = crate::store::GateDecisionId::from_bytes(store.clock.ulid()?);
        let created_at = mutation_recorded_at;

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
                .chain(
                    decision
                        .policy_row_ref()
                        .map(|row| format!("policy_row_{row}")),
                )
                .chain(decision.precedence_row_ref().map(|row| match row {
                    Some(row) => format!("policy_precedence_row_{row}"),
                    None => "policy_precedence_shipped_default".to_owned(),
                }))
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
            context: decision_context::claim_decision_context(
                id,
                body,
                input.provenance.dreamer_run_id.as_deref(),
            ),
            redacted_at: None,
        };

        if matches!(input.actor.actor_class.as_str(), "agent" | "system")
            && policy.criticality_for_predicate(&body.predicate)
                == crate::gate::PolicyCriticality::Normal
        {
            decision_record.receipt_reasons.push(
                crate::self_heal::tripwires::normal_baseline_token(&body.predicate),
            );
        }
        if mode.record_decision {
            // A structural streak follows durable append order, including
            // ordinary receipts created within the same clock millisecond.
            store.append_fresh_gate_decision_in_txn(wtxn, &mut decision_record)?;
            store.stamp_claim_gate_retention_context_in_txn(
                wtxn,
                decision_record.decision_id,
                id,
                crate::gate::GateRetentionContext {
                    world: Some(body.world.unwrap_or_else(crate::claim::base_world_id)),
                    project: Some(body.scope_project),
                    sub_project: None,
                    thread: None,
                },
            )?;
            let recorded = RecordedClaimGateDecision {
                record: decision_record.clone(),
                decision: decision.clone(),
            };
            if !defer_metrics_until_commit {
                recorded.record_metrics(&store.diagnostics.gate);
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
                store.diagnostics.gate.record_decision(&decision);
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
            // A fresh local confirm on this revision is the item the claim's
            // owner answers now, and the only one that ends the demotion of
            // peer revisions. Ordinary pending work and replicated input
            // never end it.
            if attach_critical_confirm {
                crate::gate::owner_answer::rebind_owner_answer_obligation_in_txn(
                    store, wtxn, id, &pending,
                )?;
            }
        }
        // A revision its owner wrote in person answers whatever the claim's
        // owner had not.
        if owner_authored
            && mode.persist_pending_consent
            && let Some(write) = owner_write
        {
            crate::gate::owner_answer::close_owner_answer_obligation_by_owner_revision_in_txn(
                store, wtxn, id, write,
            )?;
        }

        let resolve_pending = mode.resolve_pending && !attach_critical_confirm;
        // A held claim's own close (a supersession or retraction that changes
        // only its lifecycle) narrows it and is not the owner's answer: its
        // tray row goes silently, as a retraction's does, and the obligation
        // stays open. Redeeming the confirm instead would fail on a binding to
        // the body it closes.
        if resolve_pending
            && decision.outcome() == GateOutcome::Allow
            && closes_stored_row_only(store, &*wtxn, id, body, transition)
            && store
                .pending_gate_consent_in_txn(&*wtxn, id)?
                .is_some_and(|row| pending_row_holds_critical_confirm(&row))
        {
            store.remove_pending_gate_consent_in_txn(wtxn, id, TrayRemoval::Silent)?;
        }
        enforce_claim_gate_decision_with_consent(
            store,
            wtxn,
            id,
            &decision,
            body.approval,
            &binding,
            GateWriteMode {
                resolve_pending,
                ..mode
            },
            owner_write,
        )?;
    } else if let Some(reason_code) = hard_denial {
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

/// Whether the source-trust step this door ends on would let `body` land
/// `Auto` from `envelope` under `policy`. A writer asks before it requests
/// `Auto`, so a source the policy does not trust stays where it landed
/// instead of failing the write.
pub(crate) fn claim_source_trust_admits_auto(
    body: &ClaimBody,
    envelope: &WriteEnvelope,
    policy: &PolicyManifestResolution,
) -> bool {
    let mut auto = body.clone();
    auto.approval = ClaimApprovalStatus::Auto;
    let actor_ref = write_envelope_actor_ref(Some(envelope));
    check_claim_source_trust(
        &auto,
        actor_ref.as_deref(),
        policy,
        Some(envelope.lineage()),
    )
    .is_ok()
}
