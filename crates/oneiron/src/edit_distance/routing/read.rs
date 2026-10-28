//! Routing weight and data-bar reads.

use std::collections::BTreeMap;

use super::keys::{AGGREGATE, AggregateKey, StoredAggregate, peer_prefix, routing_scope};
use super::ladder::{rollout_rung, rung_in_txn};
use super::prior::{carried_prior, head_mean, mean_of};
use super::scope::{RolloutRung, RoutingScopeKey, RoutingScopeStats, WeightHint};
use crate::Vault;
use crate::edit_distance::attribution::UNKNOWN_EXECUTOR;
use crate::error::Result;

// ---------------------------------------------------------------------------
// The read doors
// ---------------------------------------------------------------------------

/// What routing may be told about `key` — `None` unless the task class has
/// GRADUATED, and `None` when the head has neither own runs nor a carried
/// prior to speak from.
///
/// A head with no own runs reads from the most recent other executor's head
/// of its task class and task type, marked UNTESTED (ARCH-0056 §8).
///
/// # Errors
///
/// [`Error::InvalidClaimBody`](crate::Error::InvalidClaimBody) on an unusable scope; storage errors;
/// [`Error::CorruptedIndex`](crate::Error::CorruptedIndex) on an undecodable row.
pub fn routing_weight_hint(vault: &Vault, key: &RoutingScopeKey) -> Result<Option<WeightHint>> {
    if rollout_rung(vault, &key.task_class)? != RolloutRung::Graduated {
        return Ok(None);
    }
    let prefix = peer_prefix(key)?;
    let rtxn = vault.store.env.read_txn()?;
    let peers: Vec<(String, StoredAggregate)> = AGGREGATE
        .scan_from(&vault.store, &rtxn, &prefix)?
        .into_iter()
        .map(|(key, aggregate)| (key.executor, aggregate))
        .collect();
    Ok(hint_of(&key.executor, &peers))
}

/// Every head of a task class promoted to at least [`RolloutRung::DataBar`],
/// in task-class, measurement-version, task-type, then executor order.
///
/// Shadow scopes are absent on purpose: their numbers exist and reach nothing,
/// which is what shadow MEANS. Graduated scopes stay listed — a scope that
/// feeds routing is exactly the one worth being able to see.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`](crate::Error::CorruptedIndex) on an undecodable row.
pub fn routing_data_bar(vault: &Vault) -> Result<Vec<RoutingScopeStats>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut groups: BTreeMap<(String, String, String), Vec<(String, StoredAggregate)>> =
        BTreeMap::new();
    for (key, aggregate) in AGGREGATE.scan(&vault.store, &rtxn)? {
        groups
            .entry((key.task_class, key.measurement_version, key.type_ref))
            .or_default()
            .push((key.executor, aggregate));
    }

    let mut out = Vec::new();
    for ((task_class, measurement_version, type_ref), peers) in &groups {
        let rung = rung_in_txn(vault, &rtxn, task_class)?;
        if rung == RolloutRung::Shadow {
            continue;
        }
        for (executor, _) in peers {
            let Some(hint) = hint_of(executor, peers) else {
                continue;
            };
            let key = routing_scope(&AggregateKey {
                task_class: task_class.clone(),
                measurement_version: measurement_version.clone(),
                type_ref: type_ref.clone(),
                executor: executor.clone(),
            })?;
            out.push(RoutingScopeStats { key, rung, hint });
        }
    }
    Ok(out)
}

/// The hint for `executor`'s head among `peers`, every head of its task
/// class, task type and measurement version.
fn hint_of(executor: &str, peers: &[(String, StoredAggregate)]) -> Option<WeightHint> {
    let own = peers
        .iter()
        .find(|(peer, _)| peer == executor)
        .map(|(_, row)| row)
        .filter(|row| row.runs > 0);
    let runs = own.map_or(0, |row| row.runs);
    let prior = carried_prior(executor, runs, peers);
    let edit_cost = head_mean(own, prior.as_ref())?;
    let untested = prior.as_ref().is_some_and(|prior| runs < prior.weight_runs);
    Some(WeightHint {
        relative_edit_cost: relative_cost(edit_cost, peers).map(|relative| relative as f32),
        edit_cost: edit_cost as f32,
        runs,
        prior,
        untested,
        outcomes: own
            .filter(|row| !row.outcomes.is_empty())
            .map(|row| row.outcomes.clone()),
        // The sound share of what the judge could attribute: an unclear share
        // holds, so it weighs neither for nor against the head.
        sound_share: own.and_then(|row| {
            let judged = row.judged_weight();
            (judged > 0.0).then(|| (row.sound / judged) as f32)
        }),
        on_judge_model: own.map_or(0, |row| row.on_judge_model),
    })
}

/// `mean` against the task type's observed floor and ceiling: the cheapest
/// and dearest own mean of any executor in it (FIX 7827). A degenerate range
/// — one executor, or floor equal to ceiling — is no signal and reads as
/// `None`. The unknown-executor head is no executor, so it sets no bound.
fn relative_cost(mean: f64, peers: &[(String, StoredAggregate)]) -> Option<f64> {
    let mut floor = f64::INFINITY;
    let mut ceiling = f64::NEG_INFINITY;
    let mut count = 0;
    for (peer, row) in peers {
        if row.runs == 0 || peer == UNKNOWN_EXECUTOR {
            continue;
        }
        let peer_mean = mean_of(row);
        floor = floor.min(peer_mean);
        ceiling = ceiling.max(peer_mean);
        count += 1;
    }
    if count <= 1 || !(ceiling > floor) {
        return None;
    }
    Some(((mean - floor) / (ceiling - floor)).clamp(0.0, 1.0))
}
