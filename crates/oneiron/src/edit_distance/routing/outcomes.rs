//! Anchored task outcomes beside edit cost (ARCH-0056 §8, FIX 7828).
//!
//! Low edit distance alone rewards short, bland, hard-to-object-to output. So
//! each folded run is paired with how the TASK it ran for ended, as the write
//! that settled that TASK recorded it, joined through the run's own receipts:
//! the judgment names the attempt, the attempt's pack receipt names its TASK,
//! and the TASK's settled lifecycle receipt names the disposition. The counts
//! ride beside the cost, never blended into it, and the attribution labels
//! never stand in for them. A run with no anchor along that chain adds no
//! count: absent, never invented.
//!
//! Only an owner or the world anchors a settlement (ARCH-0056 §5). The
//! settled receipt names its anchor two ways: the reporter that settled it,
//! an anchor when that reporter is a live owner of the vault, or the anchor
//! fields beside it, an anchor when they name an owner-answered ask, an
//! accepted review (FIX 12195) or a typed world proof (FIX 12213). A
//! worker's own Done, a default `Proceed`
//! and a bare `criteria_verdict = met` name none, so their outcome stays
//! absent.

use std::collections::BTreeMap;

use crate::Vault;
use crate::edit_distance::attribution::AmendmentJudgment;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::task_verb::settlement_anchor::{
    SETTLEMENT_ANCHOR_ASK, SETTLEMENT_ANCHOR_KIND_FIELD, SETTLEMENT_ANCHOR_REF_FIELD,
    SETTLEMENT_ANCHOR_REVIEW, SETTLEMENT_ANCHOR_WORLD_PROOF,
};

/// The settled disposition of the TASK the run behind `judgment` worked, read
/// in `txn`; `None` when the judgment names no attempt, the attempt's receipt
/// names no TASK, no write has settled it yet, or no owner stands behind its
/// settlement, as its reporter or its anchor (FIX 12195).
///
/// # Errors
///
/// Storage errors.
pub(super) fn run_outcome_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    judgment: &AmendmentJudgment,
) -> Result<Option<String>> {
    let Some(task) = task_of_run_in_txn(vault, txn, judgment)? else {
        return Ok(None);
    };
    let Some(settled) = crate::task_verb::settled_receipt_in(vault, txn, task)? else {
        return Ok(None);
    };
    let Some(settler) = settled
        .actor
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    let anchored = crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &settler)?
        || owner_anchored(&settled.fields);
    Ok(anchored.then_some(settled.outcome))
}

/// Whether `fields`, a settled row's, name an owner or world anchor: an
/// owner-answered ask or an accepted review (FIX 12195), or a typed world
/// proof (FIX 12213), as the settlement anchor writes them. An empty anchor
/// never counts.
fn owner_anchored(fields: &BTreeMap<String, String>) -> bool {
    let owner_kind = matches!(
        fields.get(SETTLEMENT_ANCHOR_KIND_FIELD).map(String::as_str),
        Some(SETTLEMENT_ANCHOR_ASK | SETTLEMENT_ANCHOR_REVIEW | SETTLEMENT_ANCHOR_WORLD_PROOF)
    );
    owner_kind
        && fields
            .get(SETTLEMENT_ANCHOR_REF_FIELD)
            .is_some_and(|reference| !reference.is_empty())
}

/// The TASK the run behind `judgment` worked: the judgment's attempt, joined
/// through its pack receipt's trigger ref. `None` when the judgment names no
/// attempt or the attempt names no TASK.
///
/// # Errors
///
/// Storage errors.
pub(super) fn task_of_run_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    judgment: &AmendmentJudgment,
) -> Result<Option<EntityId>> {
    let Some(attempt) = judgment.attempt_receipt.as_deref() else {
        return Ok(None);
    };
    let Some(receipt) = crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, attempt)?
    else {
        return Ok(None);
    };
    Ok(receipt
        .trigger_ref
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok()))
}
