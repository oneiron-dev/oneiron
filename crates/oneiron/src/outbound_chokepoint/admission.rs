//! New-effect admission path: actor/booking/calendar checks, gate eval, one-shot budget debit, Pending insert.

use super::budget::{
    charge_once, co_actor_exhausted, envelope_window_result, rate_paced, rate_window_result,
    spend_price_in_txn, spend_reserve,
};
use super::dedupe;
use super::replay::{
    accounting_replay_in_txn, effect_result, gate_rejection, replay_record, send_admitted,
    suppression_result,
};
#[cfg(any(test, feature = "test-hooks"))]
use super::types::BEFORE_NEW_ADMISSION;
use super::types::{
    OutboundEffectCommand, OutboundEffectError, OutboundEffectResult, OutboundTransport,
    PreparedAuthorization, PreparedEffect,
};
use crate::Vault;
use crate::agent_dispatch::{AgentRunEffectAdmission, AgentRunEffectCall, AgentRunEffectStop};
use crate::attempt_queue::AttemptId;
use crate::connector_key;
use crate::error::Error;
use crate::gate::{self, GateOutcome};
use crate::outbound::validate_publisher_signature_in_txn;
use crate::outbound_consent::{OutboundBindingAuthority, SLATE_ALWAYS_ASK_REASON};
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, IntentEscalationReason, IntentLedgerError, IntentState,
    LedgerPayloadContext, OutboundCallRequest, RecordedOutboundOutcome, force_sync,
    insert_pending_in_txn, insert_suppressed_in_txn, payload_recipient_in_txn,
    payload_recipients_in_txn, read_intent_for_attempt_in_txn, read_intent_record_in_txn,
    reserve_budget_in_txn, stored_admission_in_txn,
};
use crate::ports::TombstoneStore;

/// Joins the gate receipt `decision` to the change journal of the code run
/// `run_ref` names (ARCH-0040 #revert-run), in `wtxn`, the receipt's own
/// write. An effect no code run asks records nothing.
fn journal_effect_receipt_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    run_ref: Option<&str>,
    decision: crate::store::GateDecisionId,
) -> Result<(), OutboundEffectError> {
    if let Some(run) = run_ref {
        crate::memory::run_review::record_run_effect_in_txn(&vault.store, wtxn, run, decision)?;
    }
    Ok(())
}

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
    journal_effect_receipt_in_txn(vault, &mut wtxn, prepared.run_ref.as_deref(), decision_id)?;
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
    journal_effect_receipt_in_txn(vault, &mut wtxn, prepared.run_ref.as_deref(), decision_id)?;
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
    // An exact retry's window is anchored as before (FIX 5992).
    let since = now_ms.saturating_sub(ceiling.window_secs);
    // The row as it stands under this lock, not the snapshot the replay
    // began from: a renewal rewrites it.
    let Some(stored) = read_intent_record_in_txn(vault, &wtxn, &record.id)? else {
        return Ok(None);
    };
    if stored.state != IntentState::Pending || stored.created_ms.max(stored.updated_ms) >= since {
        return Ok(None);
    }
    let admitted = crate::outbound_intent_ledger::admitted_calls_since_in_txn(
        vault,
        &wtxn,
        &prepared.server,
        &prepared.tool,
        since,
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

/// Whether the sibling route `sibling` still holds its send: its call 0 is
/// admitted and not stopped definitely unsent. A pending call may go on a
/// later attempt, and a remote task that failed after its provider accepted
/// it may have done its work; only one route of a send is ever admitted
/// while the other can still go.
fn sibling_route_holds_send_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sibling: crate::attempt_queue::AttemptId,
) -> Result<bool, IntentLedgerError> {
    use crate::outbound_intent_ledger::{
        IntentEscalationReason, IntentResolution, UnconfirmedDelivery,
    };
    let Some(record) = read_intent_for_attempt_in_txn(vault, txn, sibling, 0)? else {
        return Ok(false);
    };
    Ok(!matches!(
        IntentResolution::from_record(&record)?,
        IntentResolution::Stopped {
            delivery: UnconfirmedDelivery::DefiniteNonDelivery,
            reason,
        } if reason != IntentEscalationReason::RemoteTaskFailed
    ))
}

/// What a `New` or `Park` command proves on `txn` before its ledger read:
/// the owner its proof names, revalidated, its verified actor's binding, and
/// its booking effect. Returns that owner, which the Pending row keeps
/// (FIX 11591). Reads only.
fn admit_prepared_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prepared: &PreparedEffect,
) -> Result<Option<crate::entity_id::EntityId>, IntentLedgerError> {
    let mut authorizing_owner = None;
    if let Some(owner) = &prepared.owner_proof {
        authorizing_owner = Some(owner.revalidate_in_txn(vault, txn)?);
    }
    if let Some((actor, actor_class)) = prepared.verified_actor {
        if vault.port_tombstone_is_deleted(txn, &actor)? {
            return Err(IntentLedgerError::InvalidBoundActor);
        }
        let entity_type = vault
            .get_entity_type_in_txn(txn, &actor)?
            .ok_or(IntentLedgerError::InvalidBoundActor)?;
        crate::provenance::validate_actor_class(entity_type, actor_class)?;
        if prepared.gate.provenance.actor_entity_ref != Some(actor)
            || prepared.gate.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
            || prepared.gate.actor.actor_class != actor_class.gate_actor_class()
        {
            return Err(IntentLedgerError::InvalidBoundActor);
        }
    }
    verify_booking_effect(vault, txn, prepared.attempt_id, &prepared.payload)?;
    Ok(authorizing_owner)
}

/// What a fresh `New` admission settles on its snapshot before its
/// external-effect judgment: the resident policy, the grant the effect must
/// run under, the effect as its space posting check frames it, and the code
/// consent wait that owns it, if one does.
struct FreshAdmission {
    policy: gate::PolicyManifestResolution,
    required_grant_id: Option<crate::entity_id::EntityId>,
    posting_gate: gate::ExternalEffectGateInput,
    code_wait: Option<(crate::entity_id::EntityId, [u8; 32])>,
}

impl FreshAdmission {
    /// The phase the judgment runs in: the answer of the code consent wait
    /// that owns the effect, else a first admission.
    fn approval_context(&self) -> gate::ApprovalContext {
        self.code_wait.map_or(
            gate::ApprovalContext::FirstAdmission,
            |(_, binding_digest)| gate::ApprovalContext::CodeWait(binding_digest),
        )
    }
}

/// The checks a fresh `New` admission of `prepared` runs on `txn` between its
/// calendar admission and its external-effect judgment, in their order: the
/// campaign leg, the policy, the step-failure policy, the required grant
/// (`invite_admission`'s page grant, else the scoped one), the space posting
/// check and the code consent wait. Reads only.
fn fresh_admission_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prepared: &PreparedEffect,
    invite_admission: Option<&crate::calendar::CalendarInviteAdmission>,
) -> Result<FreshAdmission, IntentLedgerError> {
    // P1-2 #4499: a prepared campaign leg re-proves its lifecycle under
    // this writer before any decision is recorded; other effects pass through.
    crate::campaign::enrollment::admit_campaign_leg_in_txn(vault, txn, &prepared.gate)?;

    let policy = gate::resolve_policy_manifest(&vault.store, txn)?;
    enforce_step_failure_policy(
        vault,
        txn,
        &policy,
        &prepared.payload,
        prepared.gate.provenance.actor_entity_ref,
    )?;
    let required_grant_id = invite_admission
        .and_then(crate::calendar::CalendarInviteAdmission::page_grant)
        .or_else(|| required_grant_id(&prepared.authorization));
    let posting_gate = vault.space_posting_gate_in_txn(txn, &prepared.payload, &prepared.gate)?;
    // DOOR-079 1a: a held connector call a code consent wait owns is
    // admitted under that wait's answer, proved from the rows under this
    // writer: its code-bound approval, its bound bytes, its original
    // caller's own credential. Any other effect admits as before.
    let code_wait = crate::outbound_consent::code_wait_admission_in_txn(vault, txn, prepared)?;
    Ok(FreshAdmission {
        policy,
        required_grant_id,
        posting_gate,
        code_wait,
    })
}

/// The prepared tool call a scoped effect's judgment reads; `None` for any
/// other authorization.
fn prepared_tool_call(
    authorization: &PreparedAuthorization,
) -> Option<&crate::outbound_consent::tool_call::PreparedToolCall> {
    match authorization {
        PreparedAuthorization::ScopedMcp { prepared, .. } => Some(prepared),
        PreparedAuthorization::None | PreparedAuthorization::PublisherSignature(_) => None,
    }
}

/// The judgment a fresh `New` admission of `prepared` would make on `txn`,
/// dated `at`, read-only (FIX 22102): its owner-proof, actor and booking
/// checks, its sibling-route hold, its calendar admission, the fresh
/// admission's checks, then the external-effect judgment. A fresh call has no
/// intent row, so no replay is read. `transport.admit_in` belongs to a
/// sending transport, and a preflight has none (the scoped transport's is a
/// no-op). Nothing is recorded, debited or committed.
pub(crate) fn judge_new_effect_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prepared: &PreparedEffect,
    at: u64,
) -> Result<gate::ExternalEffectJudgment, IntentLedgerError> {
    admit_prepared_in_txn(vault, txn, prepared)?;
    if let Some(sibling) = prepared.exclusive_route
        && sibling_route_holds_send_in_txn(vault, txn, sibling)?
    {
        return Err(IntentLedgerError::InvalidInput(
            "a sibling route of this send holds it",
        ));
    }
    let invite_admission = calendar_admission_at_in_txn(vault, txn, prepared, at)?;
    let fresh = fresh_admission_in_txn(vault, txn, prepared, invite_admission.as_ref())?;
    Ok(gate::judge_external_effect_in_txn(
        &vault.store,
        txn,
        &fresh.posting_gate,
        &fresh.policy,
        fresh.required_grant_id,
        prepared_tool_call(&prepared.authorization),
        fresh.approval_context(),
        at,
        Some(at),
    )?)
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
    // The owner the proof names, revalidated under this writer: the Pending
    // row keeps it, and every later send of the row rechecks it (FIX 11591).
    let mut authorizing_owner = None;
    if let OutboundEffectCommand::New(prepared) | OutboundEffectCommand::Park(prepared) = &command {
        authorizing_owner = admit_prepared_in_txn(vault, &wtxn, prepared)?;
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
    // KS7-5 (FIX 12117): a call a restore kept only the accounting of
    // replays as the owner's erase left it, never gated, asked or sent again.
    if let Some(result) = accounting_replay_in_txn(vault, &wtxn, &command, intent_id)? {
        drop(wtxn);
        return Ok(result);
    }
    // FIX 11029: a send is not admitted, nor parked, while its sibling
    // route (an interrupt and its ambient alternative) holds the send, under
    // this writer: at most one route of a send is ever live.
    if let OutboundEffectCommand::New(prepared) | OutboundEffectCommand::Park(prepared) = &command
        && let Some(sibling) = prepared.exclusive_route
        && sibling_route_holds_send_in_txn(vault, &wtxn, sibling)?
    {
        return Err(IntentLedgerError::InvalidInput(
            "a sibling route of this send holds it",
        ));
    }
    // FIX 6404: the transport's own target judges the new call again under
    // this writer; a refusal records no decision.
    transport.admit_in(&wtxn)?;
    // FIX 4747 slice 7: an agent run's new effect meets its run TASK's
    // marks under this writer, before any decision is recorded or budget
    // charged: it goes only while this machine holds the run, and one an
    // earlier executor of the run marked goes as its mark and the owner's
    // answer rule. The Pending insert below marks it in this same writer.
    let run_effect = match &command {
        OutboundEffectCommand::New(prepared) => match agent_run_effect_call(prepared) {
            Some(call) => match crate::agent_dispatch::admit_agent_run_effect_in_txn(
                vault,
                &mut wtxn,
                call,
                &intent_id,
                &prepared.server,
                &prepared.tool,
            )? {
                AgentRunEffectAdmission::Unmarked => None,
                AgentRunEffectAdmission::Marked(holding) => Some(holding),
                AgentRunEffectAdmission::Stopped { stop, commit } => {
                    if commit {
                        wtxn.commit().map_err(Error::from)?;
                    }
                    return Ok(agent_run_effect_stopped(intent_id, stop));
                }
            },
            None => None,
        },
        OutboundEffectCommand::Park(_) | OutboundEffectCommand::Resume(_) => None,
    };

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
            // A parked send admits nothing, so its decision stays evidence
            // only: its one-shot approval, standing grant and envelope slot
            // are kept for the send that is admitted later (FIX 8754).
            let (decision_id, decision) = gate::record_held_external_effect_policy(
                &vault.store,
                &mut wtxn,
                &effect,
                &policy,
            )?;
            journal_effect_receipt_in_txn(
                vault,
                &mut wtxn,
                prepared.run_ref.as_deref(),
                decision_id,
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

    // The code run that asks the effect: each receipt below joins its
    // change journal in the receipt's own write (ARCH-0040 #revert-run).
    let run_ref = prepared.run_ref.clone();
    let fresh = fresh_admission_in_txn(vault, &wtxn, &prepared, invite_admission.as_ref())?;
    let approval_context = fresh.approval_context();
    let FreshAdmission {
        policy,
        required_grant_id,
        posting_gate,
        code_wait,
    } = fresh;
    let mut governance = gate::evaluate_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &posting_gate,
        &policy,
        required_grant_id,
        prepared_tool_call(&prepared.authorization),
        approval_context,
    )?;
    if governance.outcome() != GateOutcome::Allow {
        let ask_consent = governance.ask_consent().cloned();
        let (decision_id, decision) =
            gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
        journal_effect_receipt_in_txn(vault, &mut wtxn, run_ref.as_deref(), decision_id)?;
        wtxn.commit().map_err(Error::from)?;
        let mut result = gate_rejection(intent_id, decision_id, decision)
            .held_by_outside_code_wait(&posting_gate, code_wait.is_some());
        if result.approval_digest.is_some() {
            result.ask_consent = ask_consent;
        }
        return Ok(result);
    }
    // OF-427: the co-actor's own governance under this same writer. A
    // refusal records only its decision: the primary's Allow admitted
    // nothing, so it spends no approve-once marker. FIX 6424 part 2a: it
    // reuses the press its own earlier admission kept, and names its digest.
    let mut co_keep = None;
    let mut co_governance = match prepared.co_actor.take() {
        Some(co_actor) => {
            let bound = (co_actor.bind)(vault, &mut wtxn)?;
            co_keep = Some(bound.keep_press);
            let co = gate::evaluate_external_effect_policy(
                &vault.store,
                &mut wtxn,
                &bound.effect,
                &policy,
                None,
                None,
                bound.kept_press.map_or(
                    gate::ApprovalContext::FirstAdmission,
                    gate::ApprovalContext::Retry,
                ),
            )?;
            if co.outcome() != GateOutcome::Allow {
                let (decision_id, decision) =
                    gate::record_external_effect_policy(&vault.store, &mut wtxn, co)?;
                journal_effect_receipt_in_txn(vault, &mut wtxn, run_ref.as_deref(), decision_id)?;
                wtxn.commit().map_err(Error::from)?;
                return Ok(gate_rejection(intent_id, decision_id, decision).held_by(&bound.effect));
            }
            Some(co)
        }
        None => None,
    };

    // FIX 9283, 9372: the actor the Gate verified and whether the caller keeps
    // no record, kept with the row's payload; never read from the request.
    // FIX 10953: and the persons the engine's own frozen send names as its
    // recipients (its counterparty, and each recipient of one message to
    // several, fix list row 17645), as the comm index resolves them now.
    let payload_context = LedgerPayloadContext {
        actor: prepared.gate.provenance.actor_entity_ref,
        off_record: matches!(
            &prepared.authorization,
            PreparedAuthorization::ScopedMcp { prepared, .. } if prepared.keeps_no_record()
        ),
        recipients: payload_recipients_in_txn(vault, &wtxn, &prepared.payload),
    };
    // FIX 11030 keeps the party of a counterparty that resolved to no
    // PERSON, whatever the send's other recipients resolved to.
    let counterparty = payload_recipient_in_txn(vault, &wtxn, &prepared.payload);
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
        let stored = stored_admission_in_txn(vault, &mut wtxn, &suppressed, &payload_context)?;
        insert_suppressed_in_txn(vault, &mut wtxn, &stored)?;
        // FIX 11030: a party with no PERSON yet is kept for a later erase.
        crate::outbound_intent_ledger::record_unresolved_party_in_txn(
            vault,
            &mut wtxn,
            &suppressed.id,
            suppressed.payload(),
            counterparty,
        )?;
        crate::receipt::put_suppression_in_txn(vault, &mut wtxn, &intent_id, &receipt, dedupe_now)?;
        wtxn.commit().map_err(Error::from)?;
        force_sync(vault)?;
        return suppression_result(vault, &suppressed, false);
    }

    // FIX 5992: from here a capped send's clock is the one vault reading
    // above, not the caller's: it anchors the window, and it stamps the new
    // ledger row's creation, budget accounting and settlement.
    let now_ms = match prepared.admission_ceiling {
        Some(_) if super::types::SEAT_CAP_USES_VAULT_CLOCK => dedupe_now,
        _ => now_ms,
    };
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
            now_ms.saturating_sub(ceiling.window_secs),
            None,
        )?;
        let count = ceiling.prior.max(admitted);
        if count >= ceiling.cap {
            return ceiling_hold(vault, wtxn, intent_id, &prepared, count);
        }
    }
    // FIX 7948: a send its sender's envelope allowed, met by a full window,
    // keeps its place in the envelope's line under this writer and comes back
    // when the window opens: nothing is recorded or charged, and no one is
    // asked for a press.
    if let Some(wait) = governance.retain_envelope_wait_in_txn(&vault.store, &mut wtxn)? {
        wtxn.commit().map_err(Error::from)?;
        return Ok(envelope_window_result(intent_id, &wait));
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
    // FIX 8788, FIX 8686: a Linear mutation, a scoped connector call, or a
    // send whose caller holds a paced result (the dispatch pipeline's), whose
    // only full rows are count-bound windows that refuse waits for them:
    // dropping the writer leaves nothing recorded, bound or charged.
    let scoped_call = matches!(
        prepared.authorization,
        PreparedAuthorization::ScopedMcp { .. }
    );
    if co_governance.is_some() || scoped_call || transport.waits_for_paced_window() {
        let co = co_governance.as_mut().filter(|_| co_key_distinct);
        if let Some(next_eligible_at) = rate_paced(
            vault,
            &mut wtxn,
            &mut governance,
            co,
            prepared.budget_class,
            co_pool,
        )? {
            drop(wtxn);
            return Ok(rate_window_result(intent_id, next_eligible_at));
        }
    }
    let co_exhausted = match co_governance.as_mut() {
        Some(co) if co_key_distinct => {
            co_actor_exhausted(vault, &mut wtxn, co, prepared.budget_class, now_ms, co_pool)?
        }
        _ => false,
    };
    if co_exhausted && let Some(co) = co_governance.take() {
        let (decision_id, decision) =
            gate::record_external_effect_policy(&vault.store, &mut wtxn, co)?;
        journal_effect_receipt_in_txn(vault, &mut wtxn, run_ref.as_deref(), decision_id)?;
        wtxn.commit().map_err(Error::from)?;
        return Ok(gate_rejection(intent_id, decision_id, decision));
    }
    // FIX 8689: a Spend row whose owner preauthorizes money reads the verb's
    // declared price first; one with no room denies before anything debits.
    let spend_price = scoped_call
        .then(|| spend_price_in_txn(vault, &wtxn, &mut governance, &prepared.tool))
        .transpose()?
        .flatten();
    if spend_reserve(
        vault,
        &mut wtxn,
        &mut governance,
        spend_price.as_ref(),
        false,
    )?
    .is_none()
    {
        governance.deny_budget_exhausted();
        let (decision_id, decision) =
            gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
        journal_effect_receipt_in_txn(vault, &mut wtxn, run_ref.as_deref(), decision_id)?;
        wtxn.commit().map_err(Error::from)?;
        return Ok(gate_rejection(intent_id, decision_id, decision));
    }
    let (budget_accounting, mut budget_charge, exhausted) = charge_once(
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
        journal_effect_receipt_in_txn(vault, &mut wtxn, run_ref.as_deref(), decision_id)?;
        wtxn.commit().map_err(Error::from)?;
        let mut result = gate_rejection(intent_id, decision_id, decision);
        result.budget_charge = budget_charge;
        return Ok(result);
    }
    // FIX 7964: the charge is the send's reservation, every participant's
    // usage entries kept beside its row until the send settles.
    let mut reserved = budget_charge
        .as_ref()
        .map_or_else(Vec::new, |charge| charge.debits.clone());
    let spend = spend_reserve(
        vault,
        &mut wtxn,
        &mut governance,
        spend_price.as_ref(),
        true,
    )?
    .ok_or(Error::InvariantViolation(
        "preauthorized spend changed inside admission transaction",
    ))?;
    let spend_basis = spend.map(|(debits, basis, rows)| {
        reserved.extend(debits);
        (basis, rows)
    });
    if co_key_distinct && let Some(co) = co_governance.as_mut() {
        let (_, co_charge, exhausted) =
            charge_once(vault, &mut wtxn, co, prepared.budget_class, now_ms, co_pool)?;
        reserved.extend(co_charge.into_iter().flat_map(|charge| charge.debits));
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
        PreparedAuthorization::PublisherSignature(signature) => {
            validate_publisher_signature_in_txn(vault, &wtxn, signature, &prepared)?;
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
    request = request.with_authorizing_owner(authorizing_owner);
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
    pending.admitted_approval = governance.admitted_send_approval(pending.id);
    pending.pinned_approval = governance.pinned_send_approval(pending.id);
    let spent = governance.spent_press_digest();
    if pending.id != intent_id {
        return Err(IntentLedgerError::InvalidRecord(
            "prepared outbound identity changed",
        ));
    }
    let (decision_id, decision) =
        gate::record_external_effect_policy(&vault.store, &mut wtxn, governance)?;
    journal_effect_receipt_in_txn(vault, &mut wtxn, run_ref.as_deref(), decision_id)?;
    let mut co_spent = None;
    if let Some(co) = co_governance {
        co_spent = co.spent_press_digest().zip(co_keep);
        gate::record_external_effect_policy(&vault.store, &mut wtxn, co)?;
    }
    let stored = stored_admission_in_txn(vault, &mut wtxn, &pending, &payload_context)?;
    insert_pending_in_txn(vault, &mut wtxn, &stored)?;
    // FIX 11030: a party with no PERSON yet is kept for a later erase.
    crate::outbound_intent_ledger::record_unresolved_party_in_txn(
        vault,
        &mut wtxn,
        &pending.id,
        pending.payload(),
        counterparty,
    )?;
    // FIX 4747 slice 7: an agent run's effect is marked on its run TASK by
    // its intent id in the writer that commits its Pending row, at the
    // generation the admission read, before its transport can start.
    if let Some(holding) = run_effect {
        crate::agent_dispatch::record_agent_run_effect_mark_in_txn(
            vault,
            &mut wtxn,
            holding,
            &pending.id,
        )?;
    }
    reserve_budget_in_txn(vault, &mut wtxn, &pending.id, reserved, spend_basis)?;
    if let Some(charge) = budget_charge.as_mut() {
        charge.refresh_read_in_txn(&vault.store, &wtxn, vault.store.clock.now_recorded_at())?;
    }
    // The wait's admission commits with the spend, the decision and the
    // Pending row, or not at all.
    if let Some((wait_id, _)) = code_wait {
        crate::code_run::record_code_consent_admission_in_txn(
            vault,
            &mut wtxn,
            wait_id,
            pending.id,
            decision_id,
        )?;
    }
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
    // The primary proof committed in Pending. The co-actor keeps its existing
    // best-effort post-commit writer and first-send failure policy.
    super::types::keep_spent_presses(vault, pending.id, co_spent)?;

    let mut result = send_admitted(vault, authority, pending, spent, now_ms, transport)?;
    result.gate_decision_id = Some(format!("gate:{}", decision_id.to_hex()));
    // FIX 9228: a send-time AlwaysAsk hold keeps its slate outcome/reasons;
    // stamping the admission Allow here would surface gate.allow instead.
    let slate_held = result
        .gate_receipt_reasons
        .iter()
        .any(|reason| reason == SLATE_ALWAYS_ASK_REASON);
    if !slate_held {
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
    }
    result.budget_charge = budget_charge;
    Ok(result)
}

/// The agent run call a new effect is, when its scoped preparation names the
/// run try whose step makes it (FIX 4747 slice 7): its read-only class and
/// whether its frozen idempotency key reaches the provider. `None` for every
/// other effect, which no run's marks govern.
fn agent_run_effect_call(prepared: &PreparedEffect) -> Option<AgentRunEffectCall> {
    let PreparedAuthorization::ScopedMcp {
        prepared: tool_call,
        ..
    } = &prepared.authorization
    else {
        return None;
    };
    Some(AgentRunEffectCall {
        run: tool_call.agent_run()?,
        read_only: tool_call.is_read_only(),
        idempotent: prepared.idempotency_supported,
    })
}

/// An agent run's effect that did not go at its admission, for `stop` (FIX 4747 slice 7):
/// nothing was decided, charged, settled, written to the ledger or sent.
fn agent_run_effect_stopped(
    intent_id: crate::outbound_intent_ledger::IntentId,
    stop: AgentRunEffectStop,
) -> OutboundEffectResult {
    OutboundEffectResult {
        resolution: None,
        dispatch: crate::outbound_intent_ledger::IntentDispatchResult {
            class: crate::outbound_intent_ledger::OutboundCallClass::Effectful,
            intent_id: Some(intent_id),
            state: None,
            send_outcome: None,
            replayed: false,
            escalation: None,
        },
        gate_decision_id: None,
        gate_outcome: None,
        gate_reason_codes: Vec::new(),
        gate_receipt_reasons: Vec::new(),
        budget_charge: None,
        budget_settlement_events: Vec::new(),
        dedupe_suppressed: false,
        suppression_receipt: None,
        ceiling_count: None,
        approval_digest: None,
        ask_consent: None,
        approval_actor: None,
        paced_until: None,
        agent_run_effect: Some(stop),
    }
}

/// Reads all calendar state under the same writer that publishes Pending.
/// An exact ledger replay never calls commit_in_txn again.
pub(super) fn calendar_admission_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prepared: &PreparedEffect,
) -> Result<Option<crate::calendar::CalendarInviteAdmission>, IntentLedgerError> {
    calendar_admission_at_in_txn(vault, txn, prepared, vault.store.clock.now_recorded_at())
}

/// [`calendar_admission_in_txn`] judged at `now`, recording-time seconds: the
/// writer passes the store clock's reading, a preflight the recording time
/// its judgment is dated by.
fn calendar_admission_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prepared: &PreparedEffect,
    now: u64,
) -> Result<Option<crate::calendar::CalendarInviteAdmission>, IntentLedgerError> {
    crate::calendar::invite::admit_frozen_calendar_invite_in_txn(
        vault,
        txn,
        &prepared.tool,
        prepared.gate.provenance.actor_entity_ref,
        &prepared.payload,
        now,
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
    let Some(binding) = crate::model_step_effect::StepEffectBinding::from_frozen_payload(payload)?
    else {
        return Ok(());
    };
    let actor = actor.ok_or(IntentLedgerError::InvalidBoundActor)?;
    if !crate::llm::verified_step_effector_eligible_in_txn(vault, txn, policy, binding, actor)? {
        return Err(IntentLedgerError::FailureResultIneligible);
    }
    Ok(())
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
            if error.code == oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN
                || error.code == oneiron_contracts::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED
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
        PreparedAuthorization::None | PreparedAuthorization::PublisherSignature(_) => None,
        PreparedAuthorization::ScopedMcp { grant_id, .. } => Some(*grant_id),
    }
}
