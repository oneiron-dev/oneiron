//! Routing weight and data-bar reads.

use std::collections::BTreeMap;

use super::keys::{
    AGGREGATE_KEY_PREFIX, RUNG_KEY_PREFIX, StoredAggregate, aggregate_key, decoded_aggregate,
    meta_key, scope_key_of, task_class_prefix,
};
use super::ladder::{rollout_rung, rung_in_txn};
use super::scope::{RolloutRung, RoutingScopeKey, RoutingScopeStats, WeightHint};
use crate::Vault;
use crate::error::Result;

// ---------------------------------------------------------------------------
// The read doors
// ---------------------------------------------------------------------------

/// What routing may be told about `key` — `None` unless the task class has
/// GRADUATED, and `None` when the scope has no runs to speak from.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] on an unusable scope; storage errors;
/// [`Error::CorruptedIndex`] on an undecodable row.
pub fn routing_weight_hint(vault: &Vault, key: &RoutingScopeKey) -> Result<Option<WeightHint>> {
    if rollout_rung(vault, &key.task_class)? != RolloutRung::Graduated {
        return Ok(None);
    }
    let aggregate_key = aggregate_key(key)?;
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &aggregate_key)? else {
        return Ok(None);
    };
    let own = decoded_aggregate(&raw)?;
    let peers = peer_totals(vault, &rtxn, &key.task_class)?;
    Ok(hint_of(own, peers))
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
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn routing_data_bar(vault: &Vault) -> Result<Vec<RoutingScopeStats>> {
    let rtxn = vault.store.env.read_txn()?;
    let rows = aggregates(vault, &rtxn)?;
    let mut peers: BTreeMap<String, (f64, u64)> = BTreeMap::new();
    for (key, aggregate) in &rows {
        let totals = peers.entry(key.task_class.clone()).or_default();
        totals.0 += aggregate.d_norm_sum;
        totals.1 += aggregate.runs;
    }

    let mut out = Vec::new();
    for (key, aggregate) in rows {
        let rung_key = meta_key(RUNG_KEY_PREFIX, key.task_class.as_bytes());
        let rung = rung_in_txn(vault, &rtxn, &rung_key)?;
        if rung == RolloutRung::Shadow {
            continue;
        }
        let totals = peers.get(&key.task_class).copied().unwrap_or_default();
        let Some(hint) = hint_of(aggregate, totals) else {
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

/// The pair, computed against a task class's whole peer distribution.
///
/// The peer set INCLUDES the scope itself: a lone generation is then exactly at
/// par, which is the truthful reading of "no peer has ever done this work".
/// Excluding self would leave it dividing by nothing and inventing a verdict.
fn hint_of(own: StoredAggregate, peers: (f64, u64)) -> Option<WeightHint> {
    if own.runs == 0 {
        return None;
    }
    let own_mean = own.d_norm_sum / runs_as_f64(own.runs);
    let peer_mean = if peers.1 == 0 {
        0.0
    } else {
        peers.0 / runs_as_f64(peers.1)
    };
    // A task class nobody has ever had to edit is at par by every reading, and
    // the alternative is a division that means nothing.
    let relative = if peer_mean > 0.0 {
        own_mean / peer_mean
    } else {
        1.0
    };
    let outcome = runs_as_f64(own.sound) / runs_as_f64(own.runs);
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

fn peer_totals(vault: &Vault, rtxn: &heed::RoTxn<'_>, task_class: &str) -> Result<(f64, u64)> {
    let prefix = task_class_prefix(task_class)?;
    let mut sum = 0.0;
    let mut runs = 0_u64;
    for entry in vault.store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (_, raw) = entry?;
        let aggregate = decoded_aggregate(&raw)?;
        sum += aggregate.d_norm_sum;
        runs += aggregate.runs;
    }
    Ok((sum, runs))
}

fn aggregates(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<(RoutingScopeKey, StoredAggregate)>> {
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(rtxn, AGGREGATE_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        out.push((scope_key_of(&key)?, decoded_aggregate(&raw)?));
    }
    Ok(out)
}
