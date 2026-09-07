use super::*;

use crate::batch::StagedClaimGateOutcome;
use crate::gate::breaker::{GateBreakerCandidate, GateBreakerUndo, apply_gate_breaker_in_txn};

/// The record seam at the ONE site the ONE-1453 burst breaker books: the batch
/// gate preflight for a local claim Put or ClaimCandidate.
///
/// That site is singular for a reason. It appends the event's ordinary
/// decision, hands the decision back, and its caller carries the resulting
/// staged verdict into phase-2 materialization — so a demotion computed here
/// reaches the body that actually lands, and no other door re-books the same
/// write.
pub(crate) fn check_claim_policy_for_write_as_original_event(
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
        false,
        GateBreakerAccounting::OriginalEvent,
    )
}

/// The record seam, marked as an owner-authenticated ONE-1452 bundle replay.
///
/// This is the private internal exemption the ONE-1453 breaker needs: an
/// owner who resolves a bundle is authorizing exactly these writes, so
/// replaying them must not count against — or be demoted by — the run's burst
/// budget. It is a distinct FUNCTION rather than a field on
/// [`GateWriteMode`], so no caller can inherit the exemption by copying a mode
/// value around, and no public argument exposes it.
pub(in crate::gate) fn check_claim_policy_for_write_with_owner_bundle_replay(
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
        false,
        GateBreakerAccounting::Exempt,
    )
}

/// Materializes ONE local claim under the verdict this same transaction's gate
/// preflight already recorded (ONE-1453).
///
/// It ENFORCES and nothing else. There is no second policy evaluation, no
/// second ordinary decision append, and no second breaker debit — which is the
/// point: breaker accounting is booked exactly once per original event, and a
/// phase-2 re-evaluation would either double-count the event or throw away the
/// demotion the preflight computed. Every fact it acts on was produced by that
/// preflight over the SAME body bytes and the SAME policy snapshot.
///
/// Claims absent from the staged map never reach here and keep the landed
/// `apply_put` gate path unchanged.
#[expect(
    clippy::too_many_arguments,
    reason = "the staged seam mirrors the landed claim door's explicit axis tuple"
)]
pub(crate) fn apply_staged_claim_gate_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    envelope: Option<&WriteEnvelope>,
    policy: &PolicyManifestResolution,
    staged: &StagedClaimGateOutcome,
    mode: GateWriteMode,
) -> Result<()> {
    let decision = match staged.outcome {
        GateOutcome::Allow => GateDecision::allow(),
        GateOutcome::Pending => GateDecision::pending(staged.reason_codes.clone()),
        // A preflight denial returns to `BatchBuilder::commit`, which commits
        // exactly that denial receipt and aborts the batch, so no denied claim
        // can reach materialization. Refuse rather than assume.
        GateOutcome::Deny => {
            return Err(Error::InvariantViolation(
                "staged gate denial reached materialization",
            ));
        }
    };
    let effective_approval = if staged.breaker_demoted {
        ClaimApprovalStatus::Proposed
    } else {
        body.approval
    };
    // The preflight computed this binding from the same body and the same
    // resolved manifest; `GateConsentBinding::for_claim` normalizes approval
    // before hashing, so a breaker demotion cannot move it.
    let binding = GateConsentBinding {
        diff_handle: staged.diff_handle.clone(),
        read_frontier_hash: staged.read_frontier_hash,
    };

    if mode.persist_pending_consent
        && staged.outcome == GateOutcome::Pending
        && effective_approval == ClaimApprovalStatus::Proposed
    {
        let pending = PendingGateConsentRecord {
            version: crate::store::PENDING_GATE_CONSENT_VERSION,
            claim_id: *id.as_bytes(),
            decision_id: staged.decision_id,
            created_at: staged.created_at,
            diff_handle: staged.diff_handle.clone(),
            read_frontier_hash: staged.read_frontier_hash,
            reason_codes: staged
                .reason_codes
                .iter()
                .map(|code| code.as_str().to_owned())
                .collect(),
            dreamer_run_id: if staged.breaker_demoted {
                // Breaker accounting already required and validated a nonempty
                // run id, so this is an invariant error rather than `None`.
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
    }

    enforce_claim_gate_decision_with_consent(
        store,
        wtxn,
        id,
        &decision,
        effective_approval,
        &binding,
        mode,
    )?;

    let actor_ref = write_envelope_actor_ref(envelope);
    check_claim_source_trust(
        body,
        actor_ref.as_deref(),
        policy,
        envelope_lineage_requires_auto_permit(envelope),
    )
}

/// Whether this door invocation is the ONE original gate event the ONE-1453
/// per-actor burst breaker accounts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GateBreakerAccounting {
    /// The record seam: it appends this event's ordinary decision AND hands
    /// that decision to its caller, so a demotion it computes can reach the
    /// body that materializes.
    OriginalEvent,
    /// A receipt-discarding pre-check, a phase-2 replay of an already-booked
    /// preflight identity, or an owner-authenticated bundle replay. None of
    /// them is an original event.
    Exempt,
}

pub(super) struct OriginalBreakerEvent<'a> {
    pub(super) accounting: GateBreakerAccounting,
    pub(super) record_decision: bool,
    pub(super) run_id: Option<&'a str>,
    pub(super) input: &'a GateEvaluatorInput,
    pub(super) policy: &'a PolicyManifestResolution,
    pub(super) binding: &'a GateConsentBinding,
    pub(super) body: &'a ClaimBody,
    pub(super) attach_critical_confirm: bool,
    pub(super) created_at: u64,
}

impl OriginalBreakerEvent<'_> {
    pub(super) fn apply(
        self,
        store: &Store,
        wtxn: &mut heed::RwTxn<'_>,
        decision: &mut GateDecision,
    ) -> Result<Option<crate::gate::breaker::GateBreakerApplied>> {
        // ONE-1453: the per-actor burst breaker, booked AFTER the ordinary
        // policy result is known and BEFORE any decision, pending or claim row
        // is committed. It converts velocity into review; it never denies and
        // never discards agent output. Every entry condition is checked here
        // and nowhere else:
        //
        //  * an ORIGINAL event on the record seam — not a pre-check that
        //    discards its receipt, not a phase-2 replay, not the synthetic
        //    trip receipt, and not an owner-authenticated bundle replay;
        //  * `mode.record_decision`, so the demotion rides a receipt;
        //  * a nonempty Dreamer run id, which already implies an agent
        //    (non-owner) actor on a run surface;
        //  * a resolved and bound provenance actor entity reference — a
        //    missing or invalid actor stays governed by the existing authority
        //    failure and never lands under an invented `unknown` row;
        //  * an ordinary result of would-be-`Auto` or already-`Proposed`.
        //
        // A critical-confirm attachment is deliberately NOT a candidate: that
        // ceremony already parks its write for the owner under its own
        // reason, and rewriting its outcome here would break the attachment's
        // reopening transition.
        let breaker_candidate = if decision.outcome() == GateOutcome::Allow
            && self.body.approval == ClaimApprovalStatus::Auto
            && !self.attach_critical_confirm
        {
            Some(GateBreakerCandidate::Auto)
        } else if decision.outcome() == GateOutcome::Pending
            && self.body.approval == ClaimApprovalStatus::Proposed
        {
            Some(GateBreakerCandidate::Proposed)
        } else {
            None
        };
        let breaker = match (
            self.accounting,
            self.record_decision,
            self.run_id,
            self.input.provenance.actor_entity_ref,
            breaker_candidate,
        ) {
            (
                GateBreakerAccounting::OriginalEvent,
                true,
                Some(run_id),
                Some(actor_entity_ref),
                Some(candidate),
            ) if !run_id.is_empty() => Some(apply_gate_breaker_in_txn(
                store,
                wtxn,
                run_id,
                &actor_entity_ref,
                &self.input.actor.actor_class,
                candidate,
                // The ALREADY-RESOLVED snapshot that produced the verdict
                // above: the manifest is never reopened between policy
                // evaluation, this accounting, the ordinary receipt and the
                // trip receipt.
                self.policy,
                &self.input.policy_manifest_version,
                self.binding.read_frontier_hash,
                self.created_at,
            )?),
            _ => None,
        };
        if let Some(applied) = breaker.as_ref()
            && applied.decision_is_proposed
            && applied.add_pending_reason
        {
            let receipt_reasons = decision.receipt_reasons().to_vec();
            *decision = GateDecision::pending(vec![GateReasonCode::PendingActorBurstBreaker])
                .with_receipt_reasons(receipt_reasons);
        }
        Ok(breaker)
    }
}

pub(crate) struct RecordedClaimGateDecision {
    pub(super) record: GateDecisionRecord,
    pub(super) decision: GateDecision,
    /// ONE-1453: the breaker converted this event's would-be-`Auto` outcome.
    pub(super) breaker_demoted: bool,
    /// ONE-1453 rollback metadata for the preflight selective-error path.
    pub(super) breaker_undo: Option<GateBreakerUndo>,
}

impl RecordedClaimGateDecision {
    pub(crate) fn decision_id(&self) -> GateDecisionId {
        self.record.decision_id
    }

    pub(crate) fn outcome(&self) -> &str {
        &self.record.outcome
    }

    pub(crate) fn record(&self) -> &GateDecisionRecord {
        &self.record
    }

    pub(crate) fn decision(&self) -> &GateDecision {
        &self.decision
    }

    pub(crate) fn breaker_demoted(&self) -> bool {
        self.breaker_demoted
    }

    pub(crate) fn breaker_undo(&self) -> Option<&GateBreakerUndo> {
        self.breaker_undo.as_ref()
    }

    pub(crate) fn record_metrics(&self) {
        record_gate_decision_metrics(&self.decision);
    }

    pub(crate) fn into_record(self) -> GateDecisionRecord {
        self.record
    }
}
