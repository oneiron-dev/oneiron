//! Judged-amendment fold writes.

use super::keys::{
    AGGREGATE, MEMBER, ROW_VERSION, StoredAggregate, StoredExecutor, aggregate_key, invalid,
};
use super::scope::RoutingScopeKey;
use crate::Vault;
use crate::edit_distance::attribution::{AmendmentClass, AmendmentJudgment, amendment_judgments};
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
    let fold = fold_of(&judgment)?;
    let scope_row_key = aggregate_key(&head_of(&judgment))?;
    let member = StoredExecutor {
        v: ROW_VERSION,
        executor: judgment.executor_key().to_owned(),
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
        // A judgment that is unclear throughout HOLDS: it marks the receipt
        // folded, so a later re-judgment reaches its head on rebuild, but
        // weighs nothing until then.
        if let Some(fold) = fold {
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
/// model, and when it was judged.
#[derive(Debug, Clone, Copy)]
pub(super) struct Fold {
    d_norm: f64,
    judged: f64,
    sound: f64,
    on_judge_model: bool,
    at: u64,
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
/// never an outcome.
pub(super) fn fold_of(judgment: &AmendmentJudgment) -> Result<Option<Fold>> {
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
    Ok(())
}

fn judgment_for(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentJudgment>> {
    Ok(amendment_judgments(vault)?
        .into_iter()
        .find(|judgment| judgment.receipt_id == receipt_id))
}
