//! Routing weight and data-bar reads.

use std::collections::BTreeMap;

use super::keys::{AGGREGATE, StoredAggregate, aggregate_key, peer_prefix};
use super::ladder::{rollout_rung, rung_in_txn};
use super::scope::{RolloutRung, RoutingScopeKey, RoutingScopeStats, WeightHint};
use crate::Vault;
use crate::error::Result;

// ---------------------------------------------------------------------------
// The read doors
// ---------------------------------------------------------------------------

/// What routing may be told about `key` — `None` unless the task class has
/// GRADUATED, `None` when the scope has no runs to speak from, and `None`
/// when the task class holds no range to compare against.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`](crate::Error::InvalidClaimBody) on an unusable scope; storage errors;
/// [`Error::CorruptedIndex`](crate::Error::CorruptedIndex) on an undecodable row.
pub fn routing_weight_hint(vault: &Vault, key: &RoutingScopeKey) -> Result<Option<WeightHint>> {
    if rollout_rung(vault, &key.task_class)? != RolloutRung::Graduated {
        return Ok(None);
    }
    let aggregate_key = aggregate_key(key)?;
    let rtxn = vault.store.env.read_txn()?;
    let Some(own) = AGGREGATE.get(&vault.store, &rtxn, &aggregate_key)? else {
        return Ok(None);
    };
    let peers = peer_means(vault, &rtxn, key)?;
    Ok(hint_of(own, &peers))
}

/// Every scope a task class has promoted to at least [`RolloutRung::DataBar`],
/// in task-class then model-version order.
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
    let rows = aggregates(vault, &rtxn)?;
    let mut peers: BTreeMap<(String, String), Vec<f64>> = BTreeMap::new();
    for (key, aggregate) in &rows {
        if aggregate.runs == 0 {
            continue;
        }
        peers
            .entry(peer_group(key))
            .or_default()
            .push(aggregate.d_norm_sum / runs_as_f64(aggregate.runs));
    }

    let mut out = Vec::new();
    for (key, aggregate) in rows {
        let rung = rung_in_txn(vault, &rtxn, &key.task_class)?;
        if rung == RolloutRung::Shadow {
            continue;
        }
        let means = peers
            .get(&peer_group(&key))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let Some(hint) = hint_of(aggregate, means) else {
            continue;
        };
        out.push(RoutingScopeStats {
            key,
            rung,
            runs: aggregate.runs,
            hint,
        });
    }
    Ok(out)
}

/// The pair, computed against the task class's observed floor and ceiling:
/// the cheapest and dearest per-model mean in the same task class (FIX 7827).
/// A degenerate range — one model, or floor equal to ceiling — is no signal
/// and reads as `None`, the same absence the callers already skip.
fn hint_of(own: StoredAggregate, means: &[f64]) -> Option<WeightHint> {
    if own.runs == 0 {
        return None;
    }
    let own_mean = own.d_norm_sum / runs_as_f64(own.runs);
    let mut floor = f64::INFINITY;
    let mut ceiling = f64::NEG_INFINITY;
    let mut count = 0;
    for &mean in means {
        floor = floor.min(mean);
        ceiling = ceiling.max(mean);
        count += 1;
    }
    if count <= 1 || !(ceiling > floor) {
        return None;
    }
    let relative = (own_mean - floor) / (ceiling - floor);
    // The outcome is the sound share of what the judge could attribute: an
    // unclear share holds, so it weighs neither for nor against the scope.
    let judged = own.judged_weight();
    let outcome = if judged > 0.0 {
        own.sound / judged
    } else {
        0.0
    };
    Some(WeightHint {
        relative_edit_cost: relative as f32,
        outcome_score: outcome as f32,
    })
}

/// Run counts live far below `f64`'s exact-integer range, so this cast is the
/// identity every caller here means by it.
fn runs_as_f64(runs: u64) -> f64 {
    runs as f64
}

/// A scope's peers: the same task class, measured under the same version.
fn peer_group(key: &RoutingScopeKey) -> (String, String) {
    (key.task_class.clone(), key.measurement_version.clone())
}

fn peer_means(vault: &Vault, rtxn: &heed::RoTxn<'_>, key: &RoutingScopeKey) -> Result<Vec<f64>> {
    let prefix = peer_prefix(&key.task_class, &key.measurement_version)?;
    let mut means = Vec::new();
    for (_, aggregate) in AGGREGATE.scan_from(&vault.store, rtxn, &prefix)? {
        if aggregate.runs == 0 {
            continue;
        }
        means.push(aggregate.d_norm_sum / runs_as_f64(aggregate.runs));
    }
    Ok(means)
}

fn aggregates(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<(RoutingScopeKey, StoredAggregate)>> {
    Ok(AGGREGATE
        .scan(&vault.store, rtxn)?
        .into_iter()
        .map(|(key, aggregate)| {
            (
                RoutingScopeKey::new(key.model_version, key.task_class)
                    .measured_under(key.measurement_version),
                aggregate,
            )
        })
        .collect())
}
