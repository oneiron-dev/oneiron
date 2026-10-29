//! Judged-amendment fold writes.

use super::keys::{
    AGGREGATE, MEMBER, ROW_VERSION, StoredAggregate, StoredExecutor, aggregate_key, invalid,
};
use super::outcomes::{run_outcome_in_txn, task_of_run_in_txn};
use super::scope::RoutingScopeKey;
use crate::Vault;
use crate::edit_distance::attribution::{
    AmendmentClass, AmendmentJudgment, amendment_judgment_in_txn, amendment_judgments,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// The write door
// ---------------------------------------------------------------------------

/// Folds the amendment judged against `delta_receipt` into its head.
///
/// **Receipt-bound.** The one argument is the receipt; the executor, the task
/// type, the scope, the edit mass and the labels are all read back out of
/// ED-03's judgment for it. There is no path here for a caller to supply the
/// numbers it would like folded, and the ledger stays rebuildable from
/// receipts alone (CID-7).
///
/// **The receipt names its executor.** The head is the executor the judgment
/// was stamped with when the drafting run began, never the model serving at
/// fold time (FIX 9812): a receipt first folded after a swap still lands on
/// the model that drafted it. A receipt with no stamp folds, truthfully, under
/// the unknown-executor key.
///
/// **Paired with how the work ended.** The fold counts the anchored outcome of
/// the TASK the run worked, joined through the run's own receipts, beside the
/// edit mass (FIX 7828). A TASK not settled yet adds no count; the
/// settle-time refold counts it in the settling write (FIX 11618), and a
/// rebuild reads it too.
///
/// **One fold per receipt.** A receipt already folded is never re-folded, so
/// two calls never count the same amendment twice. Re-judging a receipt is
/// reflected by
/// [`rebuild_routing_projection`](crate::edit_distance::routing::rebuild_routing_projection),
/// which re-reads every folded receipt's judgment.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the receipt carries no judgment, or its
/// judgment's scope or edit mass is unusable; storage errors.
pub fn record_judged_amendment(vault: &Vault, delta_receipt: &str) -> Result<()> {
    let Some(judgment) = judgment_for(vault, delta_receipt)? else {
        return Err(invalid("routing projection cites an unjudged receipt"));
    };
    let member_key = delta_receipt.to_owned();
    let scope_row_key = aggregate_key(&head_of(&judgment))?;
    let mut member = StoredExecutor {
        v: ROW_VERSION,
        executor: judgment.executor_key().to_owned(),
        outcome: None,
    };

    vault.with_write_txn_grouped(|wtxn| {
        // The binding is read in the transaction that writes it. An earlier
        // snapshot could only say the receipt was unfolded THEN, so two folds
        // of one receipt would both read "absent" and both count it — the
        // writer serialization below orders those writes without making either
        // one's decision to write correct.
        if MEMBER.contains(&vault.store, &*wtxn, &member_key)? {
            return Ok(());
        }
        let outcome = run_outcome_in_txn(vault, &*wtxn, &judgment)?;
        // A judgment that is unclear throughout HOLDS: it marks the receipt
        // folded, so a later re-judgment reaches its head on rebuild, but
        // weighs nothing until then.
        if let Some(fold) = fold_of(&judgment, outcome)? {
            member.outcome.clone_from(&fold.outcome);
            let mut aggregate = AGGREGATE
                .get(&vault.store, &*wtxn, &scope_row_key)?
                .unwrap_or_default();
            apply_fold(&mut aggregate, fold)?;
            AGGREGATE.put(&vault.store, wtxn, &scope_row_key, &aggregate)?;
        }
        MEMBER.put(&vault.store, wtxn, &member_key, &member)?;
        Ok(())
    })
}

/// The head `judgment` folds into: the executor, task type and measurement
/// version its own row carries.
pub(super) fn head_of(judgment: &AmendmentJudgment) -> RoutingScopeKey {
    let head = RoutingScopeKey::new(judgment.executor_key(), judgment.scope.clone())
        .measured_under(judgment.engine_ver.clone());
    match &judgment.type_ref {
        Some(type_ref) => head.typed(type_ref.clone()),
        None => head,
    }
}

/// One judgment's contribution: its edit mass, how much of it the judge could
/// attribute, how much of that was sound, whether it ran on the judge's own
/// model, when it was judged, and the anchored outcome of its run's TASK.
#[derive(Debug, Clone)]
pub(super) struct Fold {
    d_norm: f64,
    judged: f64,
    sound: f64,
    on_judge_model: bool,
    at: u64,
    outcome: Option<String>,
}

/// What one judgment contributes, or `None` when it holds.
///
/// A proposal is SOUND where the amendment says nothing was wrong with it — the
/// world moved ([`AmendmentClass::Environment`]) or the decider wanted it
/// otherwise ([`AmendmentClass::PreferenceShift`]). Every other class routes
/// from "the proposal was wrong on its own terms", including
/// [`AmendmentClass::Discovery`], which charges nobody but does not mean the
/// draft stood. A split folds its shares as they are: the sound share counts
/// for the scope, the rest of the attributed share against it, and an
/// `unclear` share for neither. A judgment that is unclear throughout holds
/// and folds nothing. The sound share is a label that explains the cost; it is
/// never an outcome. `outcome` is the run's anchored task outcome, when one is
/// joined.
pub(super) fn fold_of(
    judgment: &AmendmentJudgment,
    outcome: Option<String>,
) -> Result<Option<Fold>> {
    let d_norm = f64::from(judgment.d_norm);
    if !d_norm.is_finite() || d_norm < 0.0 {
        return Err(invalid(
            "a routing fold needs a finite non-negative edit mass",
        ));
    }
    let judged = (1.0 - f64::from(judgment.share_of(AmendmentClass::Unclear))).clamp(0.0, 1.0);
    if judgment.holds() || judged <= 0.0 {
        return Ok(None);
    }
    let sound = f64::from(
        judgment.share_of(AmendmentClass::Environment)
            + judgment.share_of(AmendmentClass::PreferenceShift),
    );
    Ok(Some(Fold {
        d_norm,
        judged,
        sound: sound.clamp(0.0, judged),
        on_judge_model: judgment.on_judge_model(),
        at: judgment.at,
        outcome,
    }))
}

pub(super) fn apply_fold(aggregate: &mut StoredAggregate, fold: Fold) -> Result<()> {
    let judged = aggregate.judged_weight();
    aggregate.v = ROW_VERSION;
    aggregate.runs = aggregate
        .runs
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("routing aggregate runs"))?;
    aggregate.d_norm_sum += fold.d_norm;
    // `sound` is a share of `judged`, which is a share of `runs`, so the bound
    // above is the bound on both.
    aggregate.judged = Some(judged + fold.judged);
    aggregate.sound += fold.sound;
    if fold.on_judge_model {
        aggregate.on_judge_model += 1;
    }
    aggregate.last_at = aggregate.last_at.max(fold.at);
    if let Some(outcome) = fold.outcome {
        *aggregate.outcomes.entry(outcome).or_insert(0) += 1;
    }
    Ok(())
}

fn judgment_for(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentJudgment>> {
    Ok(amendment_judgments(vault)?
        .into_iter()
        .find(|judgment| judgment.receipt_id == receipt_id))
}

/// Counts `task`'s anchored outcome on every already-folded receipt whose
/// run worked that TASK, in a savepoint of the settling write (FIX 11618):
/// a fold that landed before the settle counted no outcome, and without
/// this the counts would wait for the next rebuild. Each member row keeps
/// the outcome its fold counted, so the refold moves the head's counts from
/// that outcome to the one that stands now instead of recounting — a
/// re-settled or re-anchored TASK converges, and a receipt whose judgment
/// holds counts nothing either way. The head is the one the judgment as it
/// stands now names: a receipt re-judged onto another executor or scope
/// since its fold keeps its old head's count until the next rebuild, as
/// before. A refold that fails lands nothing and never fails the
/// settlement it rides.
pub(crate) fn refold_task_outcomes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
) {
    let landed = vault
        .store
        .env
        .nested_write_txn(txn)
        .map_err(Error::from)
        .and_then(|mut savepoint| {
            refold_task_in_txn(vault, &mut savepoint, task)?;
            Ok(savepoint.commit()?)
        });
    if let Err(error) = landed {
        tracing::warn!(
            kind = ?error.kind(),
            task = %task.to_hex(),
            "a settle-time routing refold did not land; the settlement stands"
        );
    }
}

/// [`refold_task_outcomes_in_txn`]'s write, in the caller's savepoint.
fn refold_task_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, task: EntityId) -> Result<()> {
    for receipt_id in MEMBER.scan_keys(&vault.store, &*txn, &[])? {
        let Some(judgment) = amendment_judgment_in_txn(vault, &*txn, &receipt_id)? else {
            continue;
        };
        if task_of_run_in_txn(vault, &*txn, &judgment)? != Some(task) {
            continue;
        }
        let Some(mut member) = MEMBER.get(&vault.store, &*txn, &receipt_id)? else {
            continue;
        };
        let outcome = run_outcome_in_txn(vault, &*txn, &judgment)?;
        let counted = if fold_of(&judgment, None)?.is_some() {
            outcome
        } else {
            None
        };
        if counted == member.outcome {
            continue;
        }
        let key = aggregate_key(&head_of(&judgment))?;
        let Some(mut aggregate) = AGGREGATE.get(&vault.store, &*txn, &key)? else {
            continue;
        };
        if let Some(old) = &member.outcome
            && let Some(count) = aggregate.outcomes.get_mut(old)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                aggregate.outcomes.remove(old);
            }
        }
        if let Some(new) = &counted {
            *aggregate.outcomes.entry(new.clone()).or_insert(0) += 1;
        }
        AGGREGATE.put(&vault.store, txn, &key, &aggregate)?;
        member.outcome = counted;
        MEMBER.put(&vault.store, txn, &receipt_id, &member)?;
    }
    Ok(())
}
