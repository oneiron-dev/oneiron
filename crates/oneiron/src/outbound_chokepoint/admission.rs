//! New-effect admission path: actor/booking/calendar checks, gate eval, one-shot budget debit, Pending insert.

use super::dedupe;
use super::replay::{
    effect_result, gate_rejection, replay_record, send_pending, suppression_result,
};
#[cfg(any(test, feature = "test-hooks"))]
use super::types::BEFORE_NEW_ADMISSION;
use super::types::{
    OutboundEffectCommand, OutboundEffectError, OutboundEffectResult, OutboundTransport,
    PreparedAuthorization, PreparedEffect,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::connector_key::{
    self, ConnectorKeyStatus, EffectorBudgetCharge, EffectorBudgetChargeOutcome,
    EffectorBudgetOnExhaust,
};
use crate::error::Error;
use crate::gate::{self, GateOutcome};
use crate::outbound_consent::OutboundBindingAuthority;
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, IntentEscalationReason, IntentLedgerError, IntentState,
    OutboundCallRequest, RecordedOutboundOutcome, force_sync, insert_pending_in_txn,
    insert_suppressed_in_txn, read_intent_for_attempt_in_txn, read_intent_record_in_txn,
};
use crate::ports::TombstoneStore;

/// The governance-only gate for a parked, already-admitted operation, as for a
/// fresh park: no debit. Only a Deny is recorded and returned; any other verdict
/// rolls back, so the parked row keeps its admission untouched.
fn parked_refusal(
    vault: &Vault,
    intent_id: crate::outbound_intent_ledger::IntentId,
    prepared: &PreparedEffect,
) -> Result<Option<OutboundEffectResult>, OutboundEffectError> {
    let mut wtxn = vault.store.env.write_txn()?;
    calendar_admission_in_txn(vault, &wtxn, prepared)?;
    let effect = vault.space_posting_gate_in_txn(&wtxn, &prepared.payload, &prepared.gate)?;
    let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    let (decision_id, decision, _) =
        gate::check_external_effect_policy(&vault.store, &mut wtxn, &effect, &policy, false)?;
    if decision.outcome() != GateOutcome::Deny {
        return Ok(None);
    }
    wtxn.commit().map_err(Error::from)?;
    vault.store.notify_attempt_observers();
    Ok(Some(gate_rejection(intent_id, decision_id, decision)))
}

/// Executes every outbound effect in ledger-read → replay → gate → debit →
/// durable-Pending → transport order.
/// Holds a send its admission ceiling stops: the decision is recorded and
/// nothing is admitted. Held before admission, so the owner's approval stays
/// unspent. A live denial is not the ceiling's to hold: it comes back as the
/// denial it is, with no ceiling count, as on every other path.
fn ceiling_hold(
    vault: &Vault,
    mut wtxn: heed::RwTxn<'_>,
    intent_id: crate::outbound_intent_ledger::IntentId,
    prepared: &PreparedEffect,
    count: u32,
) -> Result<OutboundEffectResult, OutboundEffectError> {
    let effect = vault.space_posting_gate_in_txn(&wtxn, &prepared.payload, &prepared.gate)?;
    let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    let (decision_id, decision) =
        gate::record_held_external_effect_policy(&vault.store, &mut wtxn, &effect, &policy)?;
    wtxn.commit().map_err(Error::from)?;
    vault.store.notify_attempt_observers();
    let denied = decision.outcome() == GateOutcome::Deny;
    let mut result = gate_rejection(intent_id, decision_id, decision);
    result.ceiling_count = (!denied).then_some(count);
    Ok(result)
}

/// An exact retry keeps its paid admission while the ceiling's window still
/// counts it. A Pending retry whose admission aged out of that window is a
/// send in today's window, so once governance has let it out, under the same
/// writer lock, it meets the ceiling: held at a full ceiling, keeping its
/// Pending row, and otherwise renewed before transport, so a concurrent send
/// counts it. Governance answers first, so the ceiling only ever adds a hold
/// to a send that would go out; a send governance stops gets the same answer
/// at a full ceiling as below it. Returns the hold, or `None` with the
/// transaction settled.
pub(super) fn aged_admission_ceiling(
    vault: &Vault,
    mut wtxn: heed::RwTxn<'_>,
    prepared: &PreparedEffect,
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
    now_ms: u64,
) -> Result<Option<OutboundEffectResult>, OutboundEffectError> {
    let Some(ceiling) = prepared.admission_ceiling else {
        return Ok(None);
    };
    // The row as it stands under this lock, not the snapshot the replay
    // began from: a renewal rewrites it.
    let Some(stored) = read_intent_record_in_txn(vault, &wtxn, &record.id)? else {
        return Ok(None);
    };
    if stored.state != IntentState::Pending
        || stored.created_ms.max(stored.updated_ms) >= ceiling.since_ms
    {
        return Ok(None);
    }
    let admitted = crate::outbound_intent_ledger::admitted_calls_since_in_txn(
        vault,
        &wtxn,
        &prepared.server,
        &prepared.tool,
        ceiling.since_ms,
        Some(stored.attempt_id),
    )?;
    let count = ceiling.prior.max(admitted);
    if count >= ceiling.cap {
        let mut held = ceiling_hold(vault, wtxn, stored.id, prepared, count)?;
        if held.ceiling_count.is_some() {
            let pending = effect_result(&stored, None, true, None);
            held.resolution = pending.resolution;
            held.dispatch = pending.dispatch;
        }
        return Ok(Some(held));
    }
    crate::outbound_intent_ledger::renew_admission_in_txn(vault, &mut wtxn, &stored, now_ms)?;
    wtxn.commit().map_err(Error::from)?;
    Ok(None)
}

pub(crate) fn execute_outbound_effect<T: OutboundTransport>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    command: OutboundEffectCommand,
    now_ms: u64,
    transport: &mut T,
) -> Result<OutboundEffectResult, OutboundEffectError> {
    let intent_id = match &command {
        OutboundEffectCommand::New(prepared) | OutboundEffectCommand::Park(prepared) => {
            prepared.intent_id()?
        }
        OutboundEffectCommand::Resume(intent_id) => *intent_id,
    };

    #[cfg(any(test, feature = "test-hooks"))]
    if matches!(&command, OutboundEffectCommand::New(_)) {
        BEFORE_NEW_ADMISSION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
    }
    let mut wtxn = vault.store.env.write_txn()?;
    if let OutboundEffectCommand::New(prepared) | OutboundEffectCommand::Park(prepared) = &command {
        if let Some(owner) = &prepared.owner_proof {
            owner.revalidate_in_txn(vault, &wtxn)?;
        }
        if let Some((actor, actor_class)) = prepared.verified_actor {
            if vault.port_tombstone_is_deleted(&wtxn, &actor)? {
                return Err(IntentLedgerError::InvalidBoundActor);
            }
            let entity_type = vault
                .get_entity_type_in_txn(&wtxn, &actor)?
                .ok_or(IntentLedgerError::InvalidBoundActor)?;
            crate::provenance::validate_actor_class(entity_type, actor_class)?;
            if prepared.gate.provenance.actor_entity_ref != Some(actor)
                || prepared.gate.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
                || prepared.gate.actor.actor_class != actor_class.gate_actor_class()
            {
                return Err(IntentLedgerError::InvalidBoundActor);
            }
        }
        verify_booking_effect(vault, &wtxn, prepared.attempt_id, &prepared.payload)?;
    }
    // Payload-derived ids alone are not unique logical calls. Resolve the
    // attempt under the SAME writer lock as the gate, debit, and Pending insert.
    let record = match &command {
        OutboundEffectCommand::New(prepared) | OutboundEffectCommand::Park(prepared) => {
            read_intent_for_attempt_in_txn(vault, &wtxn, prepared.attempt_id, prepared.call_seq)?
        }
        OutboundEffectCommand::Resume(_) => read_intent_record_in_txn(vault, &wtxn, &intent_id)?,
    };
    if let Some(record) = record {
        if let OutboundEffectCommand::New(prepared) | OutboundEffectCommand::Park(prepared) =
            &command
        {
            validate_new_replay(&record, prepared)?;
        }
        drop(wtxn);
        force_sync(vault)?;
        if let OutboundEffectCommand::Park(prepared) = &command
            && record.state == IntentState::Pending
        {
            // Today's window parks this already-admitted operation. Its
            // paid admission and typed approval remain on the same ledger row.
            // A refusal still ends the attempt, so the ledger can settle the
            // logical send instead of re-arming a send the gate now denies.
            if let Some(refusal) = parked_refusal(vault, intent_id, prepared)? {
                return Ok(refusal);
            }
            return Ok(effect_result(&record, None, true, None));
        }
        let prepared = match &command {
            OutboundEffectCommand::New(prepared) | OutboundEffectCommand::Park(prepared) => {
                Some(prepared)
            }
            OutboundEffectCommand::Resume(_) => None,
        };
        return replay_record(vault, authority, record, prepared, now_ms, transport);
    }

    let invite_admission = match &command {
        OutboundEffectCommand::New(prepared) | OutboundEffectCommand::Park(prepared) => {
            calendar_admission_in_txn(vault, &wtxn, prepared)?
        }
        OutboundEffectCommand::Resume(_) => None,
    };
    let mut prepared = match command {
        OutboundEffectCommand::New(prepared) => prepared,
        OutboundEffectCommand::Park(prepared) => {
            let effect =
                vault.space_posting_gate_in_txn(&wtxn, &prepared.payload, &prepared.gate)?;
            let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
            let (decision_id, decision, _) = gate::check_external_effect_policy(
                &vault.store,
                &mut wtxn,
                &effect,
                &policy,
                false,
            )?;
            wtxn.commit().map_err(Error::from)?;
            vault.store.notify_attempt_observers();
            return Ok(gate_rejection(intent_id, decision_id, decision));
        }
        OutboundEffectCommand::Resume(_) => {
            return Err(IntentLedgerError::InvalidRecord(
                "outbound resume target is missing",
            ));
        }
    };

    let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    enforce_step_failure_policy(
        vault,
        &wtxn,
        &policy,
        &prepared.payload,
        prepared.gate.provenance.actor_entity_ref,
    )?;
    let required_grant_id = invite_admission
        .as_ref()
        .and_then(crate::calendar::CalendarInviteAdmission::page_grant)
        .or_else(|| required_grant_id(&prepared.authorization));
    let posting_gate = vault.space_posting_gate_in_txn(&wtxn, &prepared.payload, &prepared.gate)?;
    let mut governance = gate::evaluate_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &posting_gate,
        &policy,
        required_grant_id,
        match &prepared.authorization {
            PreparedAuthorization::ScopedMcp { prepared, .. } => Some(prepared),
            PreparedAuthorization::None => None,
        },
        gate::ApprovalContext::FirstAdmission,
    )?;
    if governance.outcome() != GateOutcome::Allow {
        let (decision_id, decision) =
            gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
        wtxn.commit().map_err(Error::from)?;
        return Ok(gate_rejection(intent_id, decision_id, decision));
    }
    // OF-427: the co-actor's own governance under this same writer. A
    // refusal records only its decision: the primary's Allow admitted
    // nothing, so it spends no approve-once marker.
    let mut co_governance = match prepared.co_actor.take() {
        Some(co_actor) => {
            let effect = (co_actor.bind)(vault, &mut wtxn)?;
            let co = gate::evaluate_external_effect_policy(
                &vault.store,
                &mut wtxn,
                &effect,
                &policy,
                None,
                None,
                gate::ApprovalContext::FirstAdmission,
            )?;
            if co.outcome() != GateOutcome::Allow {
                let (decision_id, decision) =
                    gate::record_external_effect_policy(&vault.store, &mut wtxn, co)?;
                wtxn.commit().map_err(Error::from)?;
                return Ok(gate_rejection(intent_id, decision_id, decision));
            }
            Some(co)
        }
        None => None,
    };

    let dedupe_key = dedupe::dedupe_key(&prepared)?;
    // `now_ms` is supplied by the dispatch caller; semantic suppression must
    // use the vault's own clock, not a caller-selected future timestamp.
    let dedupe_now = vault.store.clock.now_recorded_at();
    if let Some(key) = dedupe_key.as_deref()
        && dedupe::blocked(vault, &wtxn, key, dedupe_now)?
    {
        // An Allow was evaluated, but recording it here would spend an
        // approve-once marker without admitting a send. Instead commit the
        // replayable terminal attempt and its synced receipt in ONE txn.
        let mut receipt =
            prepared
                .suppression_receipt
                .clone()
                .ok_or(IntentLedgerError::InvalidInput(
                    "dedupe dispatch lacks receipt",
                ))?;
        receipt.occurred_at = dedupe_now;
        receipt.receipt_id = crate::receipt::suppression_receipt_id(&intent_id);
        let request = OutboundCallRequest::new(
            prepared.attempt_id,
            prepared.call_seq,
            prepared.server.clone(),
            prepared.tool.clone(),
            prepared.payload.clone(),
            now_ms,
        );
        let mut suppressed = crate::outbound_intent_ledger::IntentLedgerRecord::pending(
            request,
            prepared.idempotency_supported,
            BudgetChargeMarker {
                key_ref: None,
                budget_class: prepared.budget_class,
                matched_rows: Vec::new(),
                sends_debit: 0,
                accounted_at_ms: now_ms,
            },
        )?;
        if suppressed.id != intent_id {
            return Err(IntentLedgerError::InvalidRecord(
                "suppressed outbound identity changed",
            ));
        }
        suppressed.state = IntentState::Abandoned;
        suppressed.recorded_outcome = Some(RecordedOutboundOutcome::Abandoned(
            IntentEscalationReason::DedupeSuppressed,
        ));
        insert_suppressed_in_txn(vault, &mut wtxn, &suppressed)?;
        crate::receipt::put_suppression_in_txn(vault, &mut wtxn, &intent_id, &receipt, dedupe_now)?;
        wtxn.commit().map_err(Error::from)?;
        force_sync(vault)?;
        return suppression_result(vault, &suppressed, false);
    }

    // A count bound reads the ledger under THIS writer lock, after an exact
    // retry has replayed and a semantic duplicate has been suppressed above,
    // so only a new send meets it: the call is held like a parked send, with
    // its decision recorded and nothing admitted.
    if let Some(ceiling) = prepared.admission_ceiling {
        let admitted = crate::outbound_intent_ledger::admitted_calls_since_in_txn(
            vault,
            &wtxn,
            &prepared.server,
            &prepared.tool,
            ceiling.since_ms,
            None,
        )?;
        let count = ceiling.prior.max(admitted);
        if count >= ceiling.cap {
            return ceiling_hold(vault, wtxn, intent_id, &prepared, count);
        }
    }

    // OF-427: a co-actor key that is not the primary's is preflighted
    // before either is charged, so its exhaustion never spends the
    // primary's allowance; the same key is charged once.
    let primary_key = governance.budget_target_mut().map(|target| target.key_id);
    let co_key_distinct = co_governance.as_mut().is_some_and(|co| {
        co.budget_target_mut()
            .is_some_and(|target| Some(target.key_id) != primary_key)
    });
    // Two per-grant keys of one catalog share its pool: the co-actor key
    // meets only its own rows, so the effect debits the pool once (ONE-1794).
    let co_pool = match (
        governance.budget_target_mut(),
        co_governance.as_mut().and_then(|co| co.budget_target_mut()),
    ) {
        (Some(primary), Some(co)) if co_key_distinct => {
            !connector_key::shares_budget_pool(&vault.store, &wtxn, &primary.key, &co.key)?
        }
        _ => true,
    };
    let co_exhausted = match co_governance.as_mut() {
        Some(co) if co_key_distinct => {
            co_actor_exhausted(vault, &mut wtxn, co, prepared.budget_class, now_ms, co_pool)?
        }
        _ => false,
    };
    if co_exhausted && let Some(co) = co_governance.take() {
        let (decision_id, decision) =
            gate::record_external_effect_policy(&vault.store, &mut wtxn, co)?;
        wtxn.commit().map_err(Error::from)?;
        return Ok(gate_rejection(intent_id, decision_id, decision));
    }
    let (budget_accounting, budget_charge, exhausted) = charge_once(
        vault,
        &mut wtxn,
        &mut governance,
        prepared.budget_class,
        now_ms,
        true,
    )?;
    if exhausted {
        governance.deny_budget_exhausted();
        let (decision_id, decision) =
            gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
        wtxn.commit().map_err(Error::from)?;
        let mut result = gate_rejection(intent_id, decision_id, decision);
        result.budget_charge = budget_charge;
        return Ok(result);
    }
    if co_key_distinct && let Some(co) = co_governance.as_mut() {
        let (_, _, exhausted) =
            charge_once(vault, &mut wtxn, co, prepared.budget_class, now_ms, co_pool)?;
        if exhausted {
            // Preflighted above under this writer: fail the transaction
            // rather than persist the primary's debit alone.
            return Err(Error::InvariantViolation(
                "co-actor budget changed inside admission transaction",
            )
            .into());
        }
    }

    // The gate's VERIFIED per-grant capability identity. It is the only
    // capability authority this admission may carry forward (ONE-1885).
    let gate_capability = governance.scoped_capability().cloned();
    let (authorization_binding, capability_provenance) = match &prepared.authorization {
        PreparedAuthorization::None => {
            if prepared.resolved_endpoint.is_some() || prepared.gate.scoped_mcp_call.is_some() {
                return Err(IntentLedgerError::InvalidInput(
                    "endpoint effect requires scoped authorization",
                ));
            }
            // An ordinary authorization path never carries capability
            // provenance, whatever its connector string happens to spell.
            (None, None)
        }
        PreparedAuthorization::ScopedMcp {
            grant_id,
            principal_ref,
            prepared: tool_call,
        } => {
            if tool_call.frozen_bytes() != prepared.payload.as_slice()
                || tool_call.call().server != prepared.server
                || tool_call.call().tool != prepared.tool
                || Some(tool_call.call().resolved_endpoint.as_str())
                    != prepared.resolved_endpoint.as_deref()
                || tool_call.idempotency_supported() != prepared.idempotency_supported
                || prepared.gate.scoped_mcp_call.as_ref() != Some(tool_call.call())
            {
                return Err(IntentLedgerError::InvalidInput(
                    "scoped preparation mismatch",
                ));
            }
            let minted = authority.mint_scoped_binding_in_txn(
                vault,
                &wtxn,
                *grant_id,
                principal_ref,
                &intent_id,
                tool_call,
            )?;
            // Both readers of this admission — the gate's grant match and the
            // binding mint's own re-verification on this same write snapshot —
            // must have produced the SAME typed identity, or the authorization
            // is not one this engine can vouch for.
            match minted {
                Some((binding, capability)) if gate_capability.as_ref() == Some(&capability) => {
                    (Some(binding), Some(capability))
                }
                _ => {
                    return Err(IntentLedgerError::InvalidInput(
                        "scoped authorization changed during admission",
                    ));
                }
            }
        }
    };

    let mut request = OutboundCallRequest::new(
        prepared.attempt_id,
        prepared.call_seq,
        prepared.server,
        prepared.tool,
        prepared.payload,
        now_ms,
    );
    request.authorization_binding = authorization_binding;
    request.resolved_endpoint = prepared.resolved_endpoint;
    if let Some(capability) = capability_provenance {
        request = request.with_capability_provenance(capability);
    }
    let mut pending = crate::outbound_intent_ledger::IntentLedgerRecord::pending(
        request,
        prepared.idempotency_supported,
        budget_accounting,
    )?;
    // The proof is the Gate's ACTUAL selected tap under this writer lock,
    // not an availability observation from dispatch preparation. Spend,
    // decision, typed proof, budget marker and Pending insert commit together.
    pending.admitted_approval = governance.admitted_mail_approval(pending.id);
    if pending.id != intent_id {
        return Err(IntentLedgerError::InvalidRecord(
            "prepared outbound identity changed",
        ));
    }
    let (decision_id, decision) =
        gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
    if let Some(co) = co_governance {
        gate::record_external_effect_policy(&vault.store, &mut wtxn, co)?;
    }
    insert_pending_in_txn(vault, &mut wtxn, &pending)?;
    if let Some(admission) = invite_admission {
        admission
            .commit_in_txn(vault, &mut wtxn, dedupe_now)
            .map_err(|_| IntentLedgerError::InvalidInput("calendar.invite publication failed"))?;
    }
    if let Some(key) = dedupe_key.as_deref() {
        dedupe::reserve(vault, &mut wtxn, key, &pending.id, dedupe_now)?;
    }
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;

    let mut result = send_pending(vault, authority, pending, now_ms, false, transport)?;
    result.gate_decision_id = Some(format!("gate:{}", decision_id.to_hex()));
    result.gate_outcome = Some(decision.outcome().as_str().to_owned());
    result.gate_reason_codes = decision
        .reason_codes()
        .iter()
        .map(|reason| reason.as_str().to_owned())
        .collect();
    result.gate_receipt_reasons = decision
        .receipt_reasons()
        .iter()
        .map(|reason| (*reason).to_owned())
        .collect();
    result.budget_charge = budget_charge;
    Ok(result)
}

/// Reads all calendar state under the same writer that publishes Pending.
/// An exact ledger replay never calls commit_in_txn again.
pub(super) fn calendar_admission_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prepared: &PreparedEffect,
) -> Result<Option<crate::calendar::CalendarInviteAdmission>, IntentLedgerError> {
    crate::calendar::invite::admit_frozen_calendar_invite_in_txn(
        vault,
        txn,
        &prepared.tool,
        prepared.gate.provenance.actor_entity_ref,
        &prepared.payload,
        vault.store.clock.now_recorded_at(),
    )
    .map_err(|_| IntentLedgerError::InvalidInput("calendar.invite failed calendar admission"))
}

/// An absent binding means an ordinary non-step effect. A present binding is
/// verified against the durable step and the resident policy in the SAME
/// transaction the caller uses for ordinary effect governance.
pub(super) fn enforce_step_failure_policy(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &gate::PolicyManifestResolution,
    payload: &[u8],
    actor: Option<crate::entity_id::EntityId>,
) -> Result<(), IntentLedgerError> {
    let Some(binding) = crate::llm::StepEffectBinding::from_frozen_payload(payload)? else {
        return Ok(());
    };
    let actor = actor.ok_or(IntentLedgerError::InvalidBoundActor)?;
    if !crate::llm::verified_step_effector_eligible_in_txn(vault, txn, policy, binding, actor)? {
        return Err(IntentLedgerError::FailureResultIneligible);
    }
    Ok(())
}

/// OF-427: whether a co-actor's own (distinct) connector key is exhausted.
/// An exhausted key goes through the regular charger, which applies its
/// suspend-on-exhaust without debiting it, and the co-actor's decision turns
/// into a budget-exhausted denial. Nothing else has been charged yet.
fn co_actor_exhausted(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    co: &mut gate::ExternalEffectGovernance,
    budget_class: BudgetClass,
    now_ms: u64,
    pool: bool,
) -> Result<bool, IntentLedgerError> {
    let Some(target) = co.budget_target_mut() else {
        return Ok(false);
    };
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    if connector_key::preflight_effector_budgets_pooled(
        &vault.store,
        wtxn,
        &target.key_id,
        &target.key,
        &target.governing_connector,
        budget_class.is_send(),
        now,
        pool,
    )?
    .is_none()
    {
        return Ok(false);
    }
    let (_, _, exhausted) = charge_once(vault, wtxn, co, budget_class, now_ms, pool)?;
    if !exhausted {
        return Err(Error::InvariantViolation("co-actor budget preflight diverged").into());
    }
    co.deny_budget_exhausted();
    Ok(true)
}

fn charge_once(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    governance: &mut gate::ExternalEffectGovernance,
    budget_class: BudgetClass,
    now_ms: u64,
    pool: bool,
) -> Result<(BudgetChargeMarker, Option<EffectorBudgetCharge>, bool), IntentLedgerError> {
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let Some(target) = governance.budget_target_mut() else {
        return Ok((
            BudgetChargeMarker {
                key_ref: None,
                budget_class,
                matched_rows: Vec::new(),
                sends_debit: 0,
                accounted_at_ms: now_ms,
            },
            None,
            false,
        ));
    };
    // Budget windows are enforcement state, so they advance on the engine's
    // trusted clock rather than a caller-supplied occurrence timestamp. This
    // also keeps the post-charge echo aligned with `effector_budget_read`.
    let budget_now = mutation_recorded_at;
    let outcome = connector_key::charge_effector_budgets_pooled(
        &vault.store,
        wtxn,
        &target.key_id,
        &mut target.key,
        &target.governing_connector,
        budget_class.is_send(),
        budget_now,
        pool,
    )?;
    let (mut charge, exhausted) = match outcome {
        EffectorBudgetChargeOutcome::NoRows(charge)
        | EffectorBudgetChargeOutcome::Charged(charge) => (charge, false),
        EffectorBudgetChargeOutcome::Exhausted {
            row_index,
            on_exhaust,
            mut charge,
        } => {
            if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                connector_key::suspend_connector_key_in_txn(
                    &vault.store,
                    wtxn,
                    &target.key_id,
                    &target.key,
                    connector_key::budget_exhausted_reason(row_index),
                    now_ms,
                )?;
                charge.read.status = ConnectorKeyStatus::Suspended;
            }
            (charge, true)
        }
    };
    charge.matched_rows.sort_unstable();
    charge.matched_rows.dedup();
    let marker = BudgetChargeMarker {
        key_ref: Some(charge.key_ref),
        budget_class,
        matched_rows: charge.matched_rows.clone(),
        sends_debit: charge.sends_debit,
        accounted_at_ms: now_ms,
    };
    Ok((marker, Some(charge), exhausted))
}

pub(super) fn verify_booking_effect(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    bytes: &[u8],
) -> Result<(), IntentLedgerError> {
    crate::booking::emergency_reschedule::verify_frozen_effect_in(vault, txn, attempt, bytes)
        .map_err(|error| {
            let error = crate::memory::booking_error(error);
            if let Some(denial) = error.gate_denial_error() {
                return IntentLedgerError::Engine(denial);
            }
            // Both authority codes land here: `OWNER_BINDING_REQUIRED` is the
            // owner-binding half of the same refusal family FORBIDDEN carries,
            // and classifying it as stale input would tell a caller to refresh
            // state when the actor is simply no longer authorized.
            if error.code == crate::memory::MEMORY_CODE_FORBIDDEN
                || error.code == crate::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED
            {
                IntentLedgerError::InvalidBoundActor
            } else {
                IntentLedgerError::InvalidInput(
                    "emergency effect authority or revision is no longer current",
                )
            }
        })
}

fn validate_new_replay(
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
    prepared: &PreparedEffect,
) -> Result<(), IntentLedgerError> {
    if record.id != prepared.intent_id()?
        || record.attempt_id != prepared.attempt_id
        || record.call_seq != prepared.call_seq
        || record.idempotency_supported != prepared.idempotency_supported
        || record.budget_accounting.budget_class != prepared.budget_class
        || record.server != prepared.server
        || record.tool != prepared.tool
        || record.payload_hash != prepared.payload_hash()
        || record.payload() != prepared.payload.as_slice()
        || record.resolved_endpoint != prepared.resolved_endpoint
    {
        return Err(IntentLedgerError::InvalidRecord(
            "new outbound replay does not match persisted intent",
        ));
    }
    Ok(())
}

/// Scoped MCP authority prepared outside the writer. Calendar page grants
/// instead come from calendar admission on this transaction's snapshot.
pub(super) fn required_grant_id(
    authorization: &PreparedAuthorization,
) -> Option<crate::entity_id::EntityId> {
    match authorization {
        PreparedAuthorization::None => None,
        PreparedAuthorization::ScopedMcp { grant_id, .. } => Some(*grant_id),
    }
}
