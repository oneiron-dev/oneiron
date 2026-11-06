//! Claim-gate preflight loop including CommitmentGapDecay arms.

use super::super::base_apply::pending_prompt_for;
use super::super::*;
use super::BatchOp;

use std::collections::{HashMap, VecDeque};

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::llm::BoundedAutoChecker;
use crate::store::Store;
use oneiron_contracts::claim::ClaimApprovalStatus;

/// The first native Pending-Auto refusal and its exact probe occurrences.
/// The committing terminal either settles a staged reference denial or keeps
/// this first receipt; neither outcome commits the probe's rows.
pub(super) struct DeferredPreflight {
    pub(super) err: Error,
    pub(super) first_decision: crate::store::GateDecisionId,
    pub(super) probes:
        HashMap<crate::store::GateDecisionId, super::super::gate_mode::PendingAutoProbe>,
}

/// Evaluates local claim gates and appends their decisions to `wtxn`.
///
/// The caller owns committing or aborting the transaction.
pub(super) fn preflight_gate_decisions_in_txn(
    store: &Store,
    ops: &[BatchOp],
    wtxn: &mut RwTxn<'_>,
    staged_decisions: &mut Vec<crate::gate::RecordedClaimGateDecision>,
    preflight_gate_decision_ids: &mut HashMap<
        EntityId,
        VecDeque<Option<crate::store::GateDecisionId>>,
    >,
    checker: Option<&BoundedAutoChecker>,
    origin: BaseWriteOrigin<'_>,
    caller_envelopes: &HashMap<EntityId, crate::WriteEnvelope>,
    births: &[(EntityId, crate::provenance::birth::RowBirth)],
    defer_pending_auto: bool,
) -> Result<Option<DeferredPreflight>> {
    if !contains_local_claim_put(ops) {
        return Ok(None);
    }
    let mut deferred: Option<DeferredPreflight> = None;

    // #493 now owns this caller-provided transaction: gate receipts remain
    // atomic with phase-2 apply and metrics are emitted only after commit.
    // Run the entity write door's verdict in that SAME transaction before any
    // gate receipt is appended, so a write `apply_put` will reject cannot leave
    // a decision behind for a turn that never materializes.
    // CMT-4 (ONE-1541): the lapse op's post-transition bodies are derived HERE,
    // before any gate receipt is appended, for the same reason the overlay door
    // below runs first — a set the apply arm will refuse outright must not
    // leave a decision behind for a transition that never materializes. One
    // queue entry per op, consumed in order by the gating loop.
    let mut gap_decay_lapses = VecDeque::new();
    for op in ops {
        match op {
            BatchOp::Put { id, .. } | BatchOp::ClaimCandidate { id, .. } => {
                // The batch's own origin, the one its apply judges the same
                // ids under. Only the committing terminal runs this preflight,
                // and a promotion replay carries no claim put and never
                // commits, so in practice it is `Ordinary`.
                reject_overlay_member_base_write(store, id, origin)?;
            }
            BatchOp::CommitmentGapDecay { ids, .. } => {
                for id in ids {
                    reject_overlay_member_base_write(store, id, origin)?;
                }
                gap_decay_lapses.push_back(crate::commitment::pending_commitment_lapses_in_txn(
                    store, &*wtxn, ids,
                )?);
            }
            _ => continue,
        }
    }
    let policy = crate::gate::resolve_policy_manifest(store, &*wtxn)?;
    let default_facet = crate::claim::default_facet_in(store, &*wtxn)?;
    for op in ops {
        // The gap-decay op gates ONE decision per selected instance rather
        // than one per op, so it runs its own loop and never collapses the
        // selected set into a single receipt.
        if let BatchOp::CommitmentGapDecay { envelope, .. } = op {
            let lapses = gap_decay_lapses
                .pop_front()
                .ok_or(Error::InvariantViolation(
                    "commitment gap decay preflight lost its derived bodies",
                ))?;
            for lapse in lapses {
                let mut recorded_decision = None;
                let lapse_id = lapse.id;
                let body = lapse.candidate.into_claim_body(envelope, default_facet)?;
                let result = crate::gate::check_claim_policy_for_write_with_record(
                    store,
                    wtxn,
                    &lapse_id,
                    crate::gate::ClaimGateWrite {
                        body: &body,
                        envelope: Some(envelope),
                        // Ordinary batch preflight: no checker is injected on
                        // this door, so an Auto verdict here is the engine's
                        // own and nothing consults a host.
                        auto_checker: None,
                        defer_metrics_until_commit: true,
                        transition: None,
                        owner_authored: None,
                        // Derived lapse rows carry no pending birth on this
                        // door; do not infer one from a stored revision.
                        pending_prompt: None,
                    },
                    &policy,
                    crate::store::GateWriteMode {
                        record_decision: true,
                        persist_pending_consent: false,
                        resolve_pending: false,
                        can_resolve_pending_consent: true,
                        include_source_in_gate_input: false,
                    },
                    &mut recorded_decision,
                );
                stage_preflight_decision(
                    store,
                    wtxn,
                    &lapse_id,
                    recorded_decision,
                    result,
                    staged_decisions,
                    preflight_gate_decision_ids,
                )?;
            }
            continue;
        }
        let mut recorded_decision = None;
        let eligible = match op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                allow_reserved_predicate,
                ..
            } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && !*allow_reserved_predicate =>
            {
                let mut auto = false;
                let result =
                    crate::claim::validate_claim_body_and_decode_in_txn(store, wtxn, data, false)
                        .and_then(|body| {
                            auto = body.approval == ClaimApprovalStatus::Auto;
                            let pending_prompt = pending_prompt_for(births, id);
                            crate::gate::check_claim_policy_for_write_with_record(
                                store,
                                wtxn,
                                id,
                                crate::gate::ClaimGateWrite {
                                    body: &body,
                                    // A bound caller's verified envelope
                                    // (FIX 8118), else the unbound host's; no
                                    // Dreamer authorship to consult about.
                                    envelope: caller_envelopes.get(id),
                                    auto_checker: None,
                                    defer_metrics_until_commit: true,
                                    transition: None,
                                    owner_authored: None,
                                    pending_prompt: pending_prompt.as_deref(),
                                },
                                &policy,
                                crate::store::GateWriteMode {
                                    record_decision: true,
                                    persist_pending_consent: false,
                                    resolve_pending: false,
                                    can_resolve_pending_consent: true,
                                    include_source_in_gate_input: false,
                                },
                                &mut recorded_decision,
                            )
                        });
                Some((id, auto, result))
            }
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                internal_lexical_query_hint,
                ..
            } if !*internal_lexical_query_hint => {
                let body = (**candidate)
                    .clone()
                    .into_claim_body(envelope, default_facet)?;
                let pending_prompt = pending_prompt_for(births, id);
                let result = crate::gate::check_claim_policy_for_write_with_record(
                    store,
                    wtxn,
                    id,
                    crate::gate::ClaimGateWrite {
                        body: &body,
                        envelope: Some(envelope),
                        // Only promotion injects here, and only an Auto
                        // request needs a second opinion. The gate still owns
                        // the knob + Dreamer + source + ordinary-Allow test.
                        // Phase-2 apply always passes None: no double consult.
                        auto_checker: checker
                            .filter(|_| body.approval == ClaimApprovalStatus::Auto),
                        defer_metrics_until_commit: true,
                        transition: None,
                        owner_authored: None,
                        pending_prompt: pending_prompt.as_deref(),
                    },
                    &policy,
                    crate::store::GateWriteMode {
                        record_decision: true,
                        persist_pending_consent: false,
                        resolve_pending: false,
                        can_resolve_pending_consent: true,
                        include_source_in_gate_input: false,
                    },
                    &mut recorded_decision,
                );
                Some((id, body.approval == ClaimApprovalStatus::Auto, result))
            }
            _ => None,
        };
        let Some((eligible_id, auto, result)) = eligible else {
            continue;
        };
        match (result, recorded_decision) {
            (Err(err), Some(decision))
                if defer_pending_auto
                    && auto
                    && decision.outcome() == "pending"
                    && matches!(
                        &err,
                        Error::Gate(GateError::GateWriteRejected {
                            outcome: "pending",
                            ..
                        })
                    ) =>
            {
                let decision_id = decision.decision_id();
                stage_preflight_decision(
                    store,
                    wtxn,
                    eligible_id,
                    Some(decision),
                    Ok(()),
                    staged_decisions,
                    preflight_gate_decision_ids,
                )?;
                let probe = super::super::gate_mode::PendingAutoProbe {
                    claim: *eligible_id,
                    decision: decision_id,
                };
                if let Some(deferred) = deferred.as_mut() {
                    deferred.probes.insert(decision_id, probe);
                } else {
                    deferred = Some(DeferredPreflight {
                        err,
                        first_decision: decision_id,
                        probes: HashMap::from([(decision_id, probe)]),
                    });
                }
            }
            (result, decision) => stage_preflight_decision(
                store,
                wtxn,
                eligible_id,
                decision,
                result,
                staged_decisions,
                preflight_gate_decision_ids,
            )?,
        }
    }

    Ok(deferred)
}
