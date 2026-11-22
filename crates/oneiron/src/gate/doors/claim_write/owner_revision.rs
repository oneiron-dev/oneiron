//! The owner's own revision of a held MACHINE claim answers the question the
//! claim asked (MACHINE-BIRTH-HELD-QUESTION-OWNER-SUCCESSOR = A, Engine 21 Nov
//! 03:24; S17-1 = A, "the question follows the claim").
//!
//! A MACHINE's Proposed claim that the gate holds has a tray row bound to the
//! body the machine proposed. When the vault's owner writes a same-id
//! revision of that claim in person, and the revision settles it (Auto or
//! Approved) with another body, the revision is the owner's answer: the row
//! is redeemed as the owner's amended approval of the body it showed, the
//! outcome [`crate::Vault::approve_inbox_member_with_edit`] records. Without
//! this the door redeemed the row against the revision's own body and refused
//! the owner's write `GateConsentStale`. Any other writer's revision still
//! meets that stale binding.
//!
//! The amended approval measures its Δ as the inbox's does: from the body
//! the row showed to the owner's revision, once that revision has landed.

use super::super::consent::claim_diff_handle;
use super::GateConsentBinding;
use crate::claim::{ClaimApprovalStatus, ClaimBody};
use crate::consent::OwnerAuthoredWrite;
use crate::edge::EdgeActorClass;
use crate::edit_distance::delta::{
    OUTCOME_APPROVED_AMENDED, approved_claim_body_bytes, live_revision_in_txn,
    measured_claim_amendment_in_txn, put_amendment_measurement_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::gate_receipt::gate_decision_receipt;
use crate::store::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionContext, GateDecisionId, GateDecisionRecord,
    PendingGateConsentRecord, Store, TrayRemoval,
};
use crate::vault::RevisionRef;
use crate::write_envelope::WriteEnvelope;

/// The reason code of the amended approval a held MACHINE claim's tray row
/// records when the vault's owner rewrote the claim in person.
const GATE_REASON_OWNER_REVISION_AMEND: &str = "gate.consent.owner_revision_amend";

/// Who wrote a claim revision, as the claim door knows it: the write's
/// envelope, and the owner's proof that door kept for that envelope.
pub(super) type RevisionWriter<'a> = (Option<&'a WriteEnvelope>, Option<&'a OwnerAuthoredWrite>);

/// The decision a claim revision recorded, as the claim door holds it: the
/// record this write appended, or the id of the one its same-transaction
/// preflight appended. A batch commit records its verdict at preflight and
/// applies with recording off, so the second is the commit's own landing.
pub(super) type RevisionLanding<'a> = (Option<&'a GateDecisionRecord>, Option<GateDecisionId>);

/// The amended approval an owner's revision recorded, carried to the put's
/// body stage, where the revision becomes the claim's live one: the receipt
/// the approval wrote, and the claim as the row showed it (its revision and
/// its Approved body), `None` when that end did not read.
pub(crate) struct OwnerRevisionAmendment {
    receipt_id: String,
    reviewed: Option<(RevisionRef, Vec<u8>)>,
}

/// Redeems `id`'s tray row as the owner's amended approval when this Allow
/// write is the owner's own revision of a held MACHINE claim: `body` settles
/// the claim, the row binds another body than `binding`, the stored claim is
/// MACHINE-born, and `writer` is the vault's owner. Any other write is left to
/// the door's stale binding.
///
/// Under the owner's proof the answer also closes the owner-answer
/// obligation the row names. Without the proof the obligation stays open,
/// and the revision's own put shows the owner an item for it. `landing` is
/// the revision's own recorded decision, appended by this write or by its
/// preflight: the receipt answers the row's decision and carries the
/// landing's read context. A write that records no decision in either place
/// appends no receipt. The receipt comes back with the reviewed end of its
/// Δ, for [`record_owner_revision_amendment_in_txn`] once the body lands.
pub(super) fn redeem_held_row_by_owner_revision(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    binding: &GateConsentBinding,
    (envelope, owner_write): RevisionWriter<'_>,
    landing: RevisionLanding<'_>,
) -> Result<Option<OwnerRevisionAmendment>> {
    if !matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) {
        return Ok(None);
    }
    let Some(pending) = store.pending_gate_consent_in_txn(&*wtxn, id)? else {
        return Ok(None);
    };
    if pending.diff_handle == binding.diff_handle
        || !super::stored_close::stored_claim_is_machine_born(store, &*wtxn, id)?
        || !writes_as_live_vault_owner(store, &*wtxn, envelope, owner_write)?
    {
        return Ok(None);
    }
    let original = store
        .gate_decision_in_txn(&*wtxn, pending.decision_id)?
        .ok_or(Error::CorruptedIndex("pending gate consent"))?;
    let removal = match owner_write {
        Some(proof) => match crate::gate::close_owner_answer_obligation_in_txn(
            store,
            wtxn,
            id,
            &pending.diff_handle,
            crate::gate::OwnerAnswer::owner(proof),
        )? {
            TrayRemoval::Unanswered => TrayRemoval::Silent,
            removal => removal,
        },
        None => TrayRemoval::Silent,
    };
    store.remove_pending_gate_consent_in_txn(wtxn, id, removal)?;
    let landing = match landing {
        (Some(recorded), _) => recorded.clone(),
        (None, Some(decision)) => {
            store
                .gate_decision_in_txn(&*wtxn, decision)?
                .ok_or(Error::InvariantViolation(
                    "owner revision preflight decision missing",
                ))?
        }
        (None, None) => return Ok(None),
    };
    let reviewed = reviewed_end(store, &*wtxn, id, &pending.diff_handle);
    let mut record = amended_approval_record(&original, &pending, &landing);
    store.append_fresh_gate_decision_in_txn(wtxn, &mut record)?;
    Ok(Some(OwnerRevisionAmendment {
        receipt_id: gate_decision_receipt(&record).receipt_id,
        reviewed,
    }))
}

/// Records the Δ of `amendment` once the owner's revision of `id` is the
/// claim's live revision: the measured Δ, or the uncaptured marker when an
/// end does not read or no lane measures. The Δ is telemetry, so a failed
/// measurement never refuses the owner's write.
///
/// # Errors
///
/// Storage errors writing the row.
pub(crate) fn record_owner_revision_amendment_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    amendment: &OwnerRevisionAmendment,
) -> Result<()> {
    let measured = amendment
        .reviewed
        .as_ref()
        .and_then(|(reviewed_at, reviewed)| {
            measured_claim_amendment_in_txn(store, &*wtxn, id, *reviewed_at, reviewed)
                .ok()
                .flatten()
        });
    put_amendment_measurement_in_txn(store, wtxn, &amendment.receipt_id, measured.as_ref())?;
    Ok(())
}

/// The claim as the row bound to `bound` showed it, read before the owner's
/// revision replaces it: its live revision and its body normalized to
/// Approved. `None` when either does not read, or when the stored body is
/// not the one the row bound.
fn reviewed_end(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    bound: &[u8],
) -> Option<(RevisionRef, Vec<u8>)> {
    let reviewed_at = live_revision_in_txn(store, txn, *id).ok().flatten()?;
    let reviewed = super::stored_close::stored_claim_body(store, txn, id)?;
    if claim_diff_handle(&reviewed).ok()? != bound {
        return None;
    }
    Some((reviewed_at, approved_claim_body_bytes(&reviewed).ok()?))
}

/// Whether this write is the vault owner's own: it carries the owner's proof
/// revalidated in this transaction, or its envelope names a human the owner
/// census counts as a live owner of the vault. An agent, a machine, a
/// delegate and a write with no envelope are not the owner's.
fn writes_as_live_vault_owner(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    envelope: Option<&WriteEnvelope>,
    owner_write: Option<&OwnerAuthoredWrite>,
) -> Result<bool> {
    if owner_write.is_some() {
        return Ok(true);
    }
    let Some(envelope) = envelope else {
        return Ok(false);
    };
    let actor = envelope.actor();
    if actor.actor_class() != EdgeActorClass::Human {
        return Ok(false);
    }
    crate::policy_model::is_live_vault_owner_for_store_in_txn(
        store,
        store.privacy_posture,
        txn,
        &actor.entity_ref(),
    )
}

/// The owner's amended approval of the row `pending` that `original`
/// recorded, as the inbox's approve-with-edit writes one: it names the
/// proposer and the reviewed body's binding, and answers `original` with the
/// read context of `landing`, the revision that answered it.
fn amended_approval_record(
    original: &GateDecisionRecord,
    pending: &PendingGateConsentRecord,
    landing: &GateDecisionRecord,
) -> GateDecisionRecord {
    GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: landing.decision_id,
        created_at: landing.created_at,
        outcome: OUTCOME_APPROVED_AMENDED.to_owned(),
        reason_codes: vec![GATE_REASON_OWNER_REVISION_AMEND.to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: original.actor_class.clone(),
        actor_ref: original.actor_ref.clone(),
        content_kind: original.content_kind.clone(),
        policy_manifest_version: original.policy_manifest_version.clone(),
        claim_id: Some(pending.claim_id),
        grant_ref: None,
        diff_handle: pending.diff_handle.clone(),
        read_frontier_hash: pending.read_frontier_hash,
        context: GateDecisionContext {
            read: landing.context.read.clone(),
            ..GateDecisionContext::answering(original)
        },
        redacted_at: None,
    }
}
