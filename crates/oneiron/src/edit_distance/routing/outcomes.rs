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

use super::keys::{
    AGGREGATE, MEMBER, OUTCOME, ROW_VERSION, StoredHead, StoredOutcome, aggregate_key,
};
use super::write::{fold_of, head_of};
use crate::Vault;
use crate::edit_distance::attribution::{AmendmentJudgment, amendment_judgment_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::task_verb::settlement_anchor::{
    SETTLEMENT_ANCHOR_ASK, SETTLEMENT_ANCHOR_KIND_FIELD, SETTLEMENT_ANCHOR_REF_FIELD,
    SETTLEMENT_ANCHOR_REVIEW, SETTLEMENT_ANCHOR_WORLD_PROOF,
};
use crate::write_envelope::WriteActor;

/// The settled disposition of the TASK the run behind `judgment` worked, read
/// in `txn`; `None` when the judgment names no attempt, the attempt's receipt
/// names no TASK, no write has settled it yet, or no owner stands behind its
/// settlement, as its reporter or its anchor (FIX 12195).
///
/// An owner-anchored rework outcome (FIX 11706) wins over the settled
/// disposition: the later lifecycle event is what the run cost.
///
/// # Errors
///
/// Storage errors.
pub(super) fn run_outcome_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    judgment: &AmendmentJudgment,
) -> Result<Option<String>> {
    if let Some(outcome) = OUTCOME.get(&vault.store, txn, &judgment.receipt_id)? {
        return Ok(Some(outcome.outcome));
    }
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

/// A Keep later undone: the rework outcome the undo door anchors (FIX 11706).
pub(crate) const OUTCOME_UNDONE: &str = "undone";

/// A fork later merged: the rework outcome the merge door anchors (FIX 11706).
pub(crate) const OUTCOME_MERGED: &str = "merged";

/// Anchors `outcome` to the judged amendment behind `receipt_id` (FIX 11706):
/// first writer wins, a second put for the same stamp is a no-op, and the
/// receipt's count is refolded in the same transaction. Returns whether a
/// row was written. Only a live owner anchors; a non-owner writes nothing
/// and reads `Ok(false)`. No actor bytes are stored.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_routing_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_id: &str,
    outcome: &str,
    at: u64,
    actor: WriteActor,
) -> Result<bool> {
    let entity_ref = actor.entity_ref();
    if !crate::policy_model::is_live_vault_owner_in_txn(vault, wtxn, &entity_ref)? {
        return Ok(false);
    }
    let key = receipt_id.to_owned();
    if OUTCOME.contains(&vault.store, &*wtxn, &key)? {
        return Ok(false);
    }
    OUTCOME.put(
        &vault.store,
        wtxn,
        &key,
        &StoredOutcome {
            v: ROW_VERSION,
            outcome: outcome.to_owned(),
            at,
        },
    )?;
    refold_receipt_outcome_in_txn(vault, wtxn, receipt_id)?;
    Ok(true)
}

/// Refolds one receipt's count after its rework outcome lands (FIX 11706):
/// the receipt-keyed twin of the task-wide refold, recomputed through the
/// outcome choke so the just-written token counts. A receipt with no
/// judgment yet, or not yet folded, is a no-op: its later fold reads the
/// outcome row through the choke. Idempotent: the same outcome on the
/// same head short-circuits, as before.
///
/// # Errors
///
/// Storage errors.
fn refold_receipt_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_id: &str,
) -> Result<()> {
    let Some(judgment) = amendment_judgment_in_txn(vault, &*wtxn, receipt_id)? else {
        return Ok(());
    };
    let key = receipt_id.to_owned();
    let Some(mut member) = MEMBER.get(&vault.store, &*wtxn, &key)? else {
        return Ok(());
    };
    let outcome = run_outcome_in_txn(vault, &*wtxn, &judgment)?;
    let counted = if fold_of(&judgment, None)?.is_some() {
        outcome
    } else {
        None
    };
    // Nothing counted yet and still nothing stands counted: with no head
    // to compare, the now-named head is not even derived. Outcome and
    // head are stamped together wherever a fold counted, so outcome
    // `Some` implies head `Some` — `counted == outcome` on a `None`-head
    // row means both are `None`, never two equal `Some`s (FIX 11916).
    if counted == member.outcome && member.head.is_none() {
        return Ok(());
    }
    let agg_key = aggregate_key(&head_of(&judgment))?;
    let now = StoredHead::from(&agg_key);
    // Same outcome on the same head: nothing moved, as before (ruling 4).
    // Same outcome on another head: the count moves heads below (ruling 1).
    if counted == member.outcome && member.head.as_ref() == Some(&now) {
        return Ok(());
    }
    // No aggregate is ever created here: a now-named head with no row
    // skips the receipt entirely, as before (ruling 3).
    let Some(mut aggregate) = AGGREGATE.get(&vault.store, &*wtxn, &agg_key)? else {
        return Ok(());
    };
    // One decrement path off the stored head only (FIX 11916): a `None`
    // head has no decrement — its outcome is `None` by the invariant.
    if let Some(old_head) = member.head.as_ref()
        && let Some(old) = member.outcome.as_ref()
    {
        if old_head == &now {
            // The same head the fold counted on: the already-loaded
            // aggregate takes the decrement, no second get/put.
            if let Some(count) = aggregate.outcomes.get_mut(old) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    aggregate.outcomes.remove(old);
                }
            }
        } else {
            // Re-judged onto another head: the old head's token moves to
            // the new head. An old head with no row is a no-op decrement
            // (ruling 3); the new-head increment below still lands.
            let old_key = old_head.key();
            if let Some(mut old_aggregate) = AGGREGATE.get(&vault.store, &*wtxn, &old_key)?
                && let Some(count) = old_aggregate.outcomes.get_mut(old)
            {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    old_aggregate.outcomes.remove(old);
                }
                AGGREGATE.put(&vault.store, wtxn, &old_key, &old_aggregate)?;
            }
        }
    }
    if let Some(new) = &counted {
        *aggregate.outcomes.entry(new.clone()).or_insert(0) += 1;
    }
    AGGREGATE.put(&vault.store, wtxn, &agg_key, &aggregate)?;
    member.outcome = counted;
    // A row counting for the first time stamps the now-named head; a
    // moved count re-anchors. A same-head row writes back the head it
    // already named.
    member.head = Some(now);
    MEMBER.put(&vault.store, wtxn, &key, &member)?;
    Ok(())
}
