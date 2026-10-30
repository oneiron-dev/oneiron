//! The anchor a settled TASK's lifecycle row names (FIX 11620).
//!
//! ED routing pairs a run's edit cost with how its TASK ended only where an
//! owner or the world stands behind the settlement (ARCH-0056 §5). The row
//! the settling write keeps names its reporter; two fields beside it name
//! the anchor, when one stood: [`SETTLEMENT_ANCHOR_KIND_FIELD`], one of
//! [`SETTLEMENT_ANCHOR_ASK`], [`SETTLEMENT_ANCHOR_REVIEW`] or
//! [`SETTLEMENT_ANCHOR_WORLD_PROOF`], and [`SETTLEMENT_ANCHOR_REF_FIELD`],
//! the hex id of the ask the TASK's owner answered, of the review or verdict
//! decision, or of the typed pin's NOTE. A settlement keeps one settled row:
//! an anchor that comes after it lands on that row, and a row that already
//! names an anchor keeps it. A TASK no write has settled is anchored by
//! nothing.

use std::collections::BTreeMap;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::MemoryError;
use crate::store::GateDecisionRecord;

use super::ask_types::{TaskAskEvidenceReason, TaskAskOptionId, TaskAskResult, TaskAskSource};
use super::brief::decode_hex;
use super::highway_types::TaskVia;
use super::lifecycle_receipt;
use super::wire_decode::task_verb_body_in;

/// The settled row's field naming its anchor's kind.
pub(crate) const SETTLEMENT_ANCHOR_KIND_FIELD: &str = "anchor_kind";
/// The settled row's field naming its anchor's id, in hex.
pub(crate) const SETTLEMENT_ANCHOR_REF_FIELD: &str = "anchor_ref";
/// The TASK's owner answered the ask whose answer settled it.
pub(crate) const SETTLEMENT_ANCHOR_ASK: &str = "ask";
/// The owner accepted a review of the work: a run review or a team's
/// deliverable.
pub(crate) const SETTLEMENT_ANCHOR_REVIEW: &str = "review";
/// A bound try's typed pin proved the TASK's goal on the page.
pub(crate) const SETTLEMENT_ANCHOR_WORLD_PROOF: &str = "world_proof";

/// The call a settled row an anchor keeps records: a report, as every
/// settled row's does.
const SETTLED_CALL: &str = "report";
/// The outcome of a review decision the owner approved.
const APPROVED_OUTCOME: &str = "approved";

/// The two fields naming `kind` at `reference` as a settlement's anchor.
pub(super) fn anchor_fields(kind: &str, reference: &str) -> [(String, String); 2] {
    [
        (SETTLEMENT_ANCHOR_KIND_FIELD.to_owned(), kind.to_owned()),
        (SETTLEMENT_ANCHOR_REF_FIELD.to_owned(), reference.to_owned()),
    ]
}

/// Whether `fields` already name an anchor.
pub(super) fn names_anchor(fields: &BTreeMap<String, String>) -> bool {
    fields.contains_key(SETTLEMENT_ANCHOR_KIND_FIELD)
}

/// Whether `owner`'s own counted word chose `option` in `result`.
pub(super) fn owner_answered(
    result: &TaskAskResult,
    option: &TaskAskOptionId,
    owner: EntityId,
) -> bool {
    result.evidence.iter().any(|entry| {
        entry.source == TaskAskSource::Human
            && entry.reason == TaskAskEvidenceReason::Counted
            && entry.person_ref == owner
            && entry.word.option.as_ref() == Some(option)
    })
}

/// Names `kind` at `reference` as the anchor of `task`'s settlement, in the
/// anchoring write `txn`. The anchor lands on the row the settling write
/// kept; when it kept none, `by`'s anchoring keeps the settled row: a report
/// of the terminal disposition, at the time the TASK settled, naming `job`
/// when a try ran it.
///
/// # Errors
///
/// Storage errors, and a receipt that does not keep.
pub(crate) fn anchor_settlement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    kind: &str,
    reference: &str,
    by: EntityId,
    job: Option<AttemptId>,
) -> Result<()> {
    let Some(body) = task_verb_body_in(vault, txn, task)? else {
        return Ok(());
    };
    let Some(terminal) = body.terminal() else {
        return Ok(());
    };
    if let Some(id) =
        lifecycle_receipt::settled_in(vault, txn, task, terminal.finished_at).map_err(refused)?
    {
        return lifecycle_receipt::anchor_in(vault, txn, &id, kind, reference).map_err(refused);
    }
    let memory = vault.memory(by, EdgeActorClass::Human);
    if !memory.keeps_lifecycle() {
        return Ok(());
    }
    let mut lifecycle = memory.lifecycle_record(
        &TaskVia::Wire,
        SETTLED_CALL,
        terminal.disposition.as_str(),
        Some(task),
        job,
        terminal.finished_at,
    );
    lifecycle.fields.extend(anchor_fields(kind, reference));
    let id = lifecycle_receipt::receipt_id(
        SETTLED_CALL,
        &[task.as_bytes(), by.as_bytes(), reference.as_bytes()],
    )
    .map_err(refused)?;
    lifecycle_receipt::stamp_record_in(vault, txn, &lifecycle, id.clone(), None)
        .map_err(refused)?;
    lifecycle_receipt::mark_settled_in(vault, txn, &id).map_err(refused)
}

/// [`anchor_settlement_in_txn`] for an owner's review `decision`: approved,
/// it anchors the settlement of `task`, which `job` ran when a try did, as
/// the reviewing owner's. A rejection, or a decision that names no actor,
/// anchors nothing.
///
/// # Errors
///
/// As [`anchor_settlement_in_txn`].
pub(crate) fn anchor_accepted_review_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    decision: &GateDecisionRecord,
    job: Option<AttemptId>,
) -> Result<()> {
    if decision.outcome != APPROVED_OUTCOME {
        return Ok(());
    }
    let Some(owner) = decision
        .actor_ref
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(());
    };
    anchor_settlement_in_txn(
        vault,
        txn,
        task,
        SETTLEMENT_ANCHOR_REVIEW,
        &decision.decision_id.to_hex(),
        owner,
        job,
    )
}

/// [`anchor_accepted_review_in_txn`] for the owner's review `decision` of
/// run `run`: the TASK the run worked, joined through its attempt's pack
/// receipt as ED routing joins it. A run that names no attempt, or one whose
/// receipt names no TASK, anchors nothing.
///
/// # Errors
///
/// As [`anchor_settlement_in_txn`].
pub(crate) fn anchor_reviewed_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &str,
    decision: &GateDecisionRecord,
) -> Result<()> {
    let Some(attempt) = decode_hex::<16>(run).and_then(|bytes| AttemptId::from_bytes(&bytes).ok())
    else {
        return Ok(());
    };
    let receipt = crate::receipt::attempt_pack_receipt_in_txn(
        &vault.store,
        txn,
        &crate::receipt::attempt_pack_receipt_id(&attempt),
    )?;
    let Some(task) = receipt
        .and_then(|receipt| receipt.trigger_ref)
        .and_then(|hex| EntityId::from_hex(&hex).ok())
    else {
        return Ok(());
    };
    anchor_accepted_review_in_txn(vault, txn, task, decision, Some(attempt))
}

fn refused(error: MemoryError) -> Error {
    Error::InvalidConfig(format!("settlement anchor refused: {}", error.message))
}
