//! The owner's open question on a held claim follows the claim through the
//! engine's own changes to it (Engine ANSWER S17-1-HELD-CLAIM-DEMOTION-OWNER-QUESTION
//! = A, 19 Nov 20:31).
//!
//! A held claim is a Proposed claim whose ordinary tray row waits for its
//! owner's approve or decline. The engine may change that claim before the
//! owner answers: a decay or a stale mark rewrites it in place, a Dreamer
//! weakening supersedes it with a successor at a lower confidence, and any
//! supersession closes it. None of those is the owner's answer, and none may
//! leave the owner a question that refuses every answer:
//!
//! - an in-place demotion restates the question on the body the claim now
//!   stores ([`restate_owner_question_in_txn`]);
//! - a weakening parks the same question on the Dreamer's successor;
//! - a supersession closes the old claim's row silently, with a terminal
//!   receipt, as a retraction's does ([`close_superseded_owner_question_in_txn`]).
//!
//! A critical confirm keeps its own path (`record_inner`'s silent close and
//! the owner-answer obligation), and a row that belongs to a parked deferred
//! action stays with that action. Nothing here widens a claim: a restated
//! question still waits for the owner, and it is restated only when the owner
//! could answer it the moment before the change.

use super::{ClaimApprovalStatus, ClaimLifecycleStatus, decode_claim_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::critical_confirm_record::pending_row_holds_critical_confirm;
use crate::store::gate_reason::GateReceiptOutcome;
use crate::store::{
    GateReceipt, PendingGateConsentRecord, PolicyBasis, ReceiptActor, Store, TrayRemoval,
};
use crate::{EntityId, Result};

/// The reason a supersession's terminal receipt for its old claim's
/// question carries.
const CLAIM_SUPERSEDED_REASON: &str = "gate.pending.claim_superseded";

/// The live Active claim body `id` stores, or `None` when `id` holds no
/// live claim. Decoded as the owner's settle door decodes it, so a binding
/// compared here is the binding an answer is judged against.
fn stored_live_claim_body(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<super::ClaimBody>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok((body.lifecycle == ClaimLifecycleStatus::Active).then_some(body))
}

/// The ordinary tray row on `id` that belongs to no parked deferred action,
/// or `None`. A critical confirm is not one.
fn ordinary_question_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<PendingGateConsentRecord>> {
    let Some(row) = store.pending_gate_consent_in_txn(txn, id)? else {
        return Ok(None);
    };
    if pending_row_holds_critical_confirm(&row)
        || super::deferred::claim_has_deferred_action_in_txn(store, txn, id)?
    {
        return Ok(None);
    }
    Ok(Some(row))
}

/// The owner's open question on the held claim `id`: its ordinary tray row,
/// when the owner could answer it now, that is when the row binds the
/// Proposed body `id` stores under the current policy. `None` for a claim
/// with no such row, a stale row, a critical confirm or a deferred action's
/// row.
pub(crate) fn open_owner_question_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<PendingGateConsentRecord>> {
    let Some(row) = ordinary_question_in_txn(store, txn, id)? else {
        return Ok(None);
    };
    let Some(body) = stored_live_claim_body(store, txn, id)? else {
        return Ok(None);
    };
    if body.approval != ClaimApprovalStatus::Proposed {
        return Ok(None);
    }
    let (diff_handle, read_frontier_hash) =
        crate::gate::claim_consent_binding_parts(store, txn, &body)?;
    Ok(
        (row.diff_handle == diff_handle && row.read_frontier_hash == read_frontier_hash)
            .then_some(row),
    )
}

/// Parks `question` on the claim `to`, bound to the Proposed body `to` now
/// stores: a fresh pending receipt with the question's own reasons, and a
/// tray row the owner answers as before. It replaces a row `to` already
/// holds. A claim that is no longer a live proposal is asked nothing.
///
/// The restated receipt is the same question, so it keeps what the asked
/// decision recorded: the writer it names, which the bundle settle door
/// reads as the opener of a Dreamer bundle member (an Engine receipt names
/// no writer and that door refuses the whole bundle), and the receipt
/// reasons, which carry the checker's explanation the owner reads in the
/// tray. Both come from the engine's own ledger row, never from a caller. It
/// also keeps the asked decision's loop links, and drops the drift tripwire's
/// normal-baseline token: a restatement is no second write by the agent.
pub(crate) fn restate_owner_question_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    question: &PendingGateConsentRecord,
    to: &EntityId,
) -> Result<()> {
    let Some(body) = stored_live_claim_body(store, &*wtxn, to)? else {
        return Ok(());
    };
    if body.approval != ClaimApprovalStatus::Proposed {
        return Ok(());
    }
    let (diff_handle, read_frontier_hash) =
        crate::gate::claim_consent_binding_parts(store, &*wtxn, &body)?;
    let asked = store.gate_decision_in_txn(&*wtxn, question.decision_id)?;
    let actor = asked
        .as_ref()
        .map_or(ReceiptActor::Engine, |record| ReceiptActor::Verbatim {
            class: record.actor_class.clone(),
            actor_ref: record.actor_ref.clone(),
        });
    let mut receipt = GateReceipt::with_reasons(
        GateReceiptOutcome::Pending,
        "claim",
        question.reason_codes.clone(),
        actor,
        diff_handle.clone(),
        PolicyBasis::frontier(read_frontier_hash),
    );
    receipt.about = Some(*to);
    if let Some(record) = asked {
        // The same question inside the same loop: its loop links, based on
        // the asked decision, so a job-filtered receipt read and the owner's
        // answer still name the attempt that wrote the claim.
        receipt.context = crate::store::GateDecisionContext::answering(&record);
        // No new write by the agent: the drift tripwire's normal-baseline
        // token marks the asked write only.
        receipt.receipt_reasons = record
            .receipt_reasons
            .into_iter()
            .filter(|reason| {
                crate::self_heal::tripwires::normal_baseline_predicate(reason).is_none()
            })
            .collect();
    }
    let decision = store.record_gate_receipt_in_txn(wtxn, receipt)?;
    store.stamp_claim_gate_retention_context_in_txn(
        wtxn,
        decision.decision_id,
        to,
        crate::gate::GateRetentionContext {
            world: Some(body.world.unwrap_or_else(super::base_world_id)),
            project: Some(body.scope_project),
            sub_project: None,
            thread: None,
        },
    )?;
    store.put_pending_gate_consent_in_txn(
        wtxn,
        &PendingGateConsentRecord {
            version: crate::store::PENDING_GATE_CONSENT_VERSION,
            claim_id: *to.as_bytes(),
            decision_id: decision.decision_id,
            created_at: decision.created_at,
            diff_handle,
            read_frontier_hash,
            reason_codes: question.reason_codes.clone(),
            dreamer_run_id: question.dreamer_run_id.clone(),
            predicate: Some(body.predicate.clone()),
            expires_at: None,
        },
    )
}

/// Closes the ordinary tray row of `old`, which a supersession closes: a
/// terminal Superseded receipt answers its pending decision and the row goes
/// silently, as a retraction's does. The owner is shown no item for a claim
/// that is no longer current; a critical confirm and a deferred action's row
/// are left to their own paths.
pub(crate) fn close_superseded_owner_question_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    old: &EntityId,
) -> Result<()> {
    if ordinary_question_in_txn(store, &*wtxn, old)?.is_none() {
        return Ok(());
    }
    store.close_pending_gate_consent_as_in_txn(
        wtxn,
        old,
        GateReceiptOutcome::Superseded,
        vec![CLAIM_SUPERSEDED_REASON.to_owned()],
        None,
        TrayRemoval::Silent,
    )?;
    Ok(())
}
