//! Recording external-effect governance: record, check and held; `effect` re-exports them.

use super::*;

pub(crate) fn record_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    governance: ExternalEffectGovernance,
) -> Result<(GateDecisionId, GateDecision)> {
    let ExternalEffectGovernance {
        decision_id,
        decision,
        created_at,
        input,
        binding,
        grant_ref,
        approve_once,
        approval_context,
        matched_grant,
        envelope_reservation,
        envelope_wait,
        budget_target: _,
        scoped_capability: _,
    } = governance;
    // FIX 7948: an Allow that stands on a place in a full window's line
    // admits nothing; only the chokepoint keeps that place, and it records no
    // admission for it.
    if envelope_wait.is_some()
        && decision.outcome() == GateOutcome::Allow
        && approval_context != ApprovalContext::Observe
    {
        return Err(crate::error::Error::InvariantViolation(
            "channel identity window wait recorded as an admission",
        ));
    }
    if decision.outcome() == GateOutcome::Allow
        && (approval_context != ApprovalContext::Observe
            || !input
                .external_effect
                .as_ref()
                .is_some_and(|effect| effect.mail_approve_once))
        && let Some(authorization) = approve_once.as_ref()
    {
        crate::consent::spend_approve_once_in_txn(store, wtxn, authorization)?;
    }
    let candidate = GateDecisionRecord {
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
            .chain(
                decision
                    .policy_row_ref()
                    .map(|row| format!("policy_row_{row}")),
            )
            .chain(decision.precedence_row_ref().map(|row| match row {
                Some(row) => format!("policy_precedence_row_{row}"),
                None => "policy_precedence_shipped_default".to_owned(),
            }))
            .collect(),
        system_notices: Vec::new(),
        actor_class: input.actor.actor_class.clone(),
        actor_ref: input.actor.actor_ref.clone(),
        content_kind: input.content_kind.as_str().to_owned(),
        policy_manifest_version: input.policy_manifest_version,
        claim_id: None,
        grant_ref,
        diff_handle: binding.diff_handle,
        read_frontier_hash: binding.read_frontier_hash,
        context: Default::default(),
        redacted_at: None,
    };
    if decision.outcome() == GateOutcome::Pending {
        // Read the caller's txn so retries also see its uncommitted appends.
        // Stop at the first match; the cursor is dropped before any write.
        let existing_id = store.find_gate_decision_id_in_txn(&*wtxn, |record| {
            gate_decision_matches_pending_candidate(record, &candidate)
        })?;
        if let Some(existing_id) = existing_id {
            store.diagnostics.gate.record_decision(&decision);
            return Ok((existing_id, decision));
        }
    }
    crate::off_record::FloorWrites::new(store).append_egress_gate_decision(wtxn, &candidate)?;
    if decision.outcome() == GateOutcome::Allow
        && let Some((grant_id, grant)) = matched_grant
    {
        touch_standing_outbound_grant_in_txn(store, wtxn, &grant_id, grant, created_at)?;
    }
    if decision.outcome() == GateOutcome::Allow
        && approval_context != ApprovalContext::Observe
        && let Some(reservation) = envelope_reservation
    {
        reservation.commit_in_txn(store, wtxn, created_at)?;
    }
    store.diagnostics.gate.record_decision(&decision);

    Ok((decision_id, decision))
}

/// Governance surface for external-effect callers that finalize the decision in
/// their own transaction. When `admit_for_execution` is set the caller applies
/// the effect immediately in this same txn (e.g. an identity lifecycle intent),
/// so the governing connector key is debited exactly once here and an exhausted
/// key flips the recorded decision to a budget-exhausted denial before the
/// effect is applied — one durable accounting event per genuinely-new effect
/// (design.out §2/§3). Governance-only callers pass `false` and never debit.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn check_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    admit_for_execution: bool,
) -> Result<(GateDecisionId, GateDecision, Option<EffectorBudgetCharge>)> {
    let context = if admit_for_execution {
        ApprovalContext::FirstAdmission
    } else {
        ApprovalContext::Observe
    };
    let mut governance =
        evaluate_external_effect_policy(store, wtxn, effect, policy, None, None, context)?;
    let mut effector_charge = None;
    if admit_for_execution && governance.outcome() == GateOutcome::Allow {
        let (charge, exhausted) = charge_admitted_external_effect(
            store,
            wtxn,
            &mut governance,
            effect.send_ref.is_some(),
            true,
        )?;
        if exhausted {
            governance.deny_budget_exhausted();
        }
        effector_charge = charge;
    }
    let (decision_id, decision) = record_external_effect_policy(store, wtxn, governance)?;
    Ok((decision_id, decision, effector_charge))
}

/// Records governance for an effect held BEFORE admission, such as a count
/// ceiling reached under the admission writer lock. The decision stays as
/// evidence, but nothing was admitted: no approve-once authorization or
/// envelope slot is spent and no standing grant is touched as used, so the
/// held effect can still run on its approval once the ceiling clears.
pub(crate) fn record_held_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
) -> Result<(GateDecisionId, GateDecision)> {
    let mut governance = evaluate_external_effect_policy(
        store,
        wtxn,
        effect,
        policy,
        None,
        None,
        ApprovalContext::Observe,
    )?;
    governance.approve_once = None;
    governance.matched_grant = None;
    governance.envelope_reservation = None;
    governance.envelope_wait = None;
    record_external_effect_policy(store, wtxn, governance)
}

impl ExternalEffectGovernance {
    /// FIX 7948: keeps this send's place in its envelope's line in the
    /// caller's writer and returns the wait, when the Gate allowed the send
    /// on an envelope whose window is full. Nothing is admitted, recorded or
    /// charged: the caller commits the place and brings the send back at the
    /// wait's `next_eligible_at`, before its `deadline`.
    pub(crate) fn retain_envelope_wait_in_txn(
        &mut self,
        store: &Store,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<Option<crate::outbound_grant::ChannelIdentityWindowWait>> {
        if self.decision.outcome() != GateOutcome::Allow {
            return Ok(None);
        }
        self.envelope_wait
            .take()
            .map(|place| place.retain_in_txn(store, wtxn))
            .transpose()
    }
}
