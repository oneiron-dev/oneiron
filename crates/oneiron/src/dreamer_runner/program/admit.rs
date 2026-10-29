//! DOOR-141 admission: one writer judges a wake against the live vault and,
//! in one commit, records its Gate decision and admission, queues the program
//! attempt as the root of its run tree under the waking actor's stamp, ready
//! for the program runtime, and consumes the wake.

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DREAMER_TURN_PROGRAM_ATTEMPT_KIND, DreamerAttemptPayload, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TURN;
use crate::store::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionContext, GateDecisionId, GateDecisionReadContext,
    GateDecisionRecord, GateLoopLink, GateLoopSource,
};
use crate::{EntityId, Vault};

use super::authority::Standing;
use super::types::{
    ProgramRecipePin, TurnProgramAdmissionOutcome, TurnProgramAdmissionReceipt,
    TurnProgramAdmissionRecord, TurnProgramWake, run_id,
};
use super::{ADMISSION, ARM, WAKE};

const NOT_ARMED: &str = "the program is no longer armed";
const NOT_TRIGGERED: &str = "the landed turn does not match the program's trigger";
const AUTHORITY_LAPSED: &str = "the waking actor's authority no longer stands";
const PIN_MOVED: &str = "the pinned program changed since it was armed";

impl Vault {
    /// Admits one wake a landed turn owed an armed program (DOOR-141 §4).
    ///
    /// Inside one writer: an identical wake already admitted answers its
    /// first receipt (one that differs is a conflict); otherwise the program
    /// must still be armed at the woken revision, the turn must be the live
    /// TURN of the trigger's conversation, landed at or after arming by the
    /// armed actor, the waking actor's authority must still stand (an
    /// attested owner's as the vault's live owner, FIX 11090), and the
    /// pinned SKILL must still be the program pinned. The decision, allowed
    /// or refused, is a Gate receipt; an allowed one queues one Dreamer
    /// program attempt, stamped as the waking actor, the root of its run
    /// tree, ready for the program runtime: no placeholder park holds it
    /// (DOOR-141 PR2). The wake is consumed in the same commit, so a crash
    /// before it re-admits nothing.
    pub(super) fn admit_turn_program(
        &self,
        wake: &TurnProgramWake,
        now: u64,
    ) -> Result<TurnProgramAdmissionReceipt> {
        let receipt = self.with_write_txn_grouped(|txn| admit_in_txn(self, txn, wake, now))?;
        if receipt.first && matches!(receipt.outcome, TurnProgramAdmissionOutcome::Queued { .. }) {
            self.store.notify_attempt_observers();
            // The deadline lane arms the queued program at once.
            self.store.notify_proactivity_changes();
        }
        Ok(receipt)
    }
}

fn admit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wake: &TurnProgramWake,
    now: u64,
) -> Result<TurnProgramAdmissionReceipt> {
    let admission = wake.admission_id();
    let wake = &erased_actor_form_in_txn(vault, &*txn, wake)?;
    if let Some(existing) = ADMISSION.get(vault, &*txn, &admission)? {
        if existing.wake != *wake {
            return Err(Error::ConcurrentWrite(
                "a turn program wake differs from the one its turn already admitted",
            ));
        }
        WAKE.delete(vault, txn, &wake.key())?;
        return Ok(existing.receipt(false));
    }
    let judged = judge_in_txn(vault, &*txn, wake)?;
    let refused = judged.as_ref().err().copied();
    let receipt_id = gate_decision_in_txn(vault, txn, wake, &admission, refused, now)?;
    let mut record = TurnProgramAdmissionRecord {
        admission,
        wake: wake.clone(),
        definition: judged.ok(),
        receipt_id,
        attempt: None,
        refused: refused.map(str::to_owned),
        decided_at: now,
    };
    // The stamp the queue row takes reads this row, so it lands first.
    ADMISSION.put(vault, txn, &admission, &record)?;
    if refused.is_none() {
        let attempt = queue_in_txn(vault, txn, &admission, now)?;
        record.attempt = Some(attempt);
        ADMISSION.put(vault, txn, &admission, &record)?;
    }
    WAKE.delete(vault, txn, &wake.key())?;
    Ok(record.receipt(true))
}

/// `wake` as an erase of its waking actor leaves it (FIX 10668): without
/// its slip's instrument once the actor bears the local hard-delete marker.
/// The drain reads a wake before its admission's writer opens, so an erase
/// that commits between them, whose sweep found no admission yet, leaves
/// no instrument in the one written after it, and an admission it already
/// scrubbed still matches its wake on replay.
fn erased_actor_form_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wake: &TurnProgramWake,
) -> Result<TurnProgramWake> {
    let mut wake = wake.clone();
    let actor = wake.authority.actor();
    if vault.local_hard_delete_marker_exists_in_txn(txn, &actor)? {
        wake.authority.scrub_instrument_of(&actor);
    }
    Ok(wake)
}

/// The live vault's judgment of `wake`: the pinned definition it admits,
/// or why it refuses it.
fn judge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wake: &TurnProgramWake,
) -> Result<std::result::Result<ProgramRecipePin, &'static str>> {
    let actor = wake.authority.actor();
    let Some(arming) = ARM.get(vault, txn, &(actor, wake.registration))? else {
        return Ok(Err(NOT_ARMED));
    };
    if arming.revision != wake.revision || arming.definition.revision() != wake.revision {
        return Ok(Err(NOT_ARMED));
    }
    if !arming.wakes_on(&wake.authority, &wake.turn)
        || !landed_turn_in_txn(vault, txn, wake.turn.turn, wake.turn.conversation)?
    {
        return Ok(Err(NOT_TRIGGERED));
    }
    match wake.authority.standing_in_txn(vault, txn)? {
        Standing::Stands(_) => {}
        Standing::Lapsed => return Ok(Err(AUTHORITY_LAPSED)),
        // His own refusal, recorded on this wake's admission alone (FIX
        // 11090); a host that cannot judge him keeps the wake instead.
        Standing::OwnerNotLive => return Ok(Err(crate::authority::OWNER_NOT_LIVE)),
        // Its own refusal, recorded on this wake's admission alone (FIX
        // 11593).
        Standing::Withdrawn { reason } => return Ok(Err(reason)),
    }
    if !super::arm::pin_stands_in_txn(vault, txn, &arming.definition)? {
        return Ok(Err(PIN_MOVED));
    }
    Ok(Ok(arming.definition))
}

/// Whether `turn` is a live TURN of `conversation`.
fn landed_turn_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    conversation: EntityId,
) -> Result<bool> {
    if crate::vault::live_entity_row_in_txn(&vault.store, txn, &turn)?.live_type()
        != Some(ENTITY_TYPE_TURN)
    {
        return Ok(false);
    }
    Ok(
        crate::dreamer_consolidation::redirty::conversation_in_txn(vault, txn, &turn)?
            == Some(conversation),
    )
}

/// The admission's Gate decision, allowed or refused, as the waking actor's.
fn gate_decision_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wake: &TurnProgramWake,
    admission: &[u8; 32],
    refused: Option<&str>,
    now: u64,
) -> Result<[u8; 16]> {
    let authority = &wake.authority;
    let decision_id = GateDecisionId::from_bytes(*vault.new_entity_id()?.as_bytes());
    let (outcome, reason) = match refused {
        Some(_) => ("deny", "gate.dreamer.turn_program_refused"),
        None => ("allow", "gate.dreamer.turn_program_admitted"),
    };
    let decision = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at: now,
        outcome: outcome.into(),
        reason_codes: vec![reason.into()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: authority.class()?.gate_actor_class().into(),
        actor_ref: Some(authority.actor().to_hex()),
        content_kind: "dreamer_turn_program".into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: authority.grant().as_ref().map(EntityId::to_hex),
        diff_handle: admission.to_vec(),
        read_frontier_hash: crate::gate::resolve_policy_manifest(&vault.store, &*txn)?
            .read_frontier_hash()?,
        // FIX 7500, 7499: its own admission, about the turn that woke it. A
        // refused wake runs nothing, so it names no run; neither names an
        // attempt, which is queued after this decision.
        context: GateDecisionContext::linked(
            GateLoopLink::admission(
                GateLoopSource::TurnProgram,
                refused.is_none().then(|| run_id(admission)),
                None,
            ),
            GateDecisionReadContext::about(Some(wake.turn.turn), vec![wake.turn.turn]),
        ),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &decision)?;
    Ok(decision_id.as_bytes())
}

/// Queues the admitted program as one Dreamer attempt with no parent: the
/// root of its run tree. Its payload names the admission, which its stamp
/// reads; its dedupe key is the admission's, and its run id the code run the
/// admission fixes.
fn queue_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    admission: &[u8; 32],
    now: u64,
) -> Result<AttemptId> {
    let hex = bytes_to_hex_lower(admission);
    let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        DREAMER_TURN_PROGRAM_ATTEMPT_KIND,
        DreamerAttemptPayload {
            attempt_type: DREAMER_TURN_PROGRAM_ATTEMPT_KIND.to_owned(),
            input: rmpv::Value::Binary(admission.to_vec()),
            parent_attempt: None,
        },
        Some(format!("{DREAMER_TURN_PROGRAM_ATTEMPT_KIND}:{hex}")),
        Some(run_id(admission)),
        now,
    )?;
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
    Ok(status.attempt.id)
}
