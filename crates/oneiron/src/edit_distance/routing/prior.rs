//! The carried prior (ARCH-0056 §8, ARCH-0003 #prior-origins): what a head
//! with too few own runs reads beside them.
//!
//! An executor swap starts a new head with zero own runs. It carries the most
//! recent other executor's score for the same task class, task type and
//! measurement version as a weak prior of origin `carried`, with an explicit
//! weight in runs, and reads UNTESTED while its own runs are below that
//! weight. Real runs outweigh it: a head whose own runs reach the weight reads
//! on them alone. The carried runs stay evidence for the executor that made
//! them; nothing here counts them as the new head's own.

use super::keys::{StoredAggregate, runs_as_f64};
use super::scope::CarriedPrior;
use crate::edit_distance::attribution::UNKNOWN_EXECUTOR;
use crate::learning::PriorOrigin;

/// The most own runs a carried prior counts as. Canon names no value; this is
/// the learning family's borrowed-prior seed (`learning_borrowed_prior_runs`),
/// so a carried routing score weighs what a carried learning estimate weighs.
const CARRIED_PRIOR_RUNS: u64 = 2;

/// The prior a head of `executor` with `own_runs` own runs carries from
/// `peers` (every head of its task class, task type and measurement version),
/// or `None` when its own runs reach the weight, or no other executor has a
/// head to carry.
///
/// The unknown-executor key neither carries nor lends a prior: it names no
/// executor pair, only receipts whose stamp was absent.
pub(super) fn carried_prior(
    executor: &str,
    own_runs: u64,
    peers: &[(String, StoredAggregate)],
) -> Option<CarriedPrior> {
    if own_runs >= CARRIED_PRIOR_RUNS || executor == UNKNOWN_EXECUTOR {
        return None;
    }
    let (from, source) = peers
        .iter()
        .filter(|(peer, row)| peer != executor && peer != UNKNOWN_EXECUTOR && row.runs > 0)
        .max_by(|(left_executor, left), (right_executor, right)| {
            left.last_at
                .cmp(&right.last_at)
                .then_with(|| right_executor.cmp(left_executor))
        })?;
    // A source with fewer runs than the cap lends no more weight than it has.
    let weight_runs = source.runs.min(CARRIED_PRIOR_RUNS);
    if own_runs >= weight_runs {
        return None;
    }
    Some(CarriedPrior {
        origin: PriorOrigin::Carried,
        from: from.clone(),
        value: mean_of(source) as f32,
        weight_runs,
    })
}

/// The mean edit mass a head reads at: its own runs, joined by `prior`'s value
/// at the prior's weight; `None` with neither.
pub(super) fn head_mean(
    own: Option<&StoredAggregate>,
    prior: Option<&CarriedPrior>,
) -> Option<f64> {
    let (own_runs, own_sum) = own.map_or((0.0, 0.0), |row| (runs_as_f64(row.runs), row.d_norm_sum));
    let (prior_runs, prior_sum) = prior.map_or((0.0, 0.0), |prior| {
        let weight = runs_as_f64(prior.weight_runs);
        (weight, weight * f64::from(prior.value))
    });
    let weight = own_runs + prior_runs;
    (weight > 0.0).then(|| (own_sum + prior_sum) / weight)
}

/// A head's own mean edit mass; `row.runs` is non-zero.
pub(super) fn mean_of(row: &StoredAggregate) -> f64 {
    row.d_norm_sum / runs_as_f64(row.runs)
}
