//! Claim-gate preflight loop including CommitmentGapDecay arms.

use super::super::*;
use super::BatchOp;

use std::collections::{HashMap, VecDeque};

use heed::RwTxn;

use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::BoundedAutoChecker;
use crate::store::Store;

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
) -> Result<()> {
    if !contains_local_claim_put(ops) {
        return Ok(());
    }

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
                // Gate preflight is an ordinary-write path; a promotion replay
                // carries no claim put and never reaches it.
                reject_overlay_member_base_write(store, id, BaseWriteOrigin::Ordinary)?;
            }
            BatchOp::CommitmentGapDecay { ids, .. } => {
                for id in ids {
                    reject_overlay_member_base_write(store, id, BaseWriteOrigin::Ordinary)?;
                }
                gap_decay_lapses.push_back(crate::commitment::pending_commitment_lapses_in_txn(
                    store, &*wtxn, ids,
                )?);
            }
            _ => continue,
        }
    }
    let policy = crate::gate::resolve_policy_manifest(store, &*wtxn)?;
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
                let body = lapse.candidate.into_claim_body(envelope);
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
                    },
                    &policy,
                    crate::gate::GateWriteMode {
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
                let result =
                    crate::claim::validate_claim_body_and_decode(data, false).and_then(|body| {
                        crate::gate::check_claim_policy_for_write_as_original_event(
                            store,
                            wtxn,
                            id,
                            crate::gate::ClaimGateWrite {
                                body: &body,
                                envelope: None,
                                // Envelope-less local claim put: no Dreamer
                                // authorship to consult about.
                                auto_checker: None,
                                defer_metrics_until_commit: true,
                            },
                            &policy,
                            crate::gate::GateWriteMode {
                                record_decision: true,
                                persist_pending_consent: false,
                                resolve_pending: false,
                                can_resolve_pending_consent: true,
                                include_source_in_gate_input: false,
                            },
                            &mut recorded_decision,
                        )
                    });
                Some((id, result))
            }
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                internal_lexical_query_hint,
                ..
            } if !*internal_lexical_query_hint => {
                let body = (**candidate).clone().into_claim_body(envelope);
                let result = crate::gate::check_claim_policy_for_write_as_original_event(
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
                    },
                    &policy,
                    crate::gate::GateWriteMode {
                        record_decision: true,
                        persist_pending_consent: false,
                        resolve_pending: false,
                        can_resolve_pending_consent: true,
                        include_source_in_gate_input: false,
                    },
                    &mut recorded_decision,
                );
                Some((id, result))
            }
            _ => None,
        };
        let Some((eligible_id, result)) = eligible else {
            continue;
        };
        stage_preflight_decision(
            store,
            wtxn,
            eligible_id,
            recorded_decision,
            result,
            staged_decisions,
            preflight_gate_decision_ids,
        )?;
    }

    Ok(())
}
