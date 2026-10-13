//! Causal floor updates: softenings clear only observed restrictions.
//!
//! A lowered floor lands at once like any other consented op; it is no longer
//! a delayed widen (identity canon, "Device-key widen ceremony (dead
//! 2026-08-05)").
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn effective_tier_floor(
    events: &BTreeMap<AuthorityEntryHash, (AuthorityTier, BTreeSet<AuthorityEntryHash>)>,
) -> Option<AuthorityTier> {
    let cleared: BTreeSet<_> = events
        .values()
        .flat_map(|(_, seen)| seen.iter().copied())
        .collect();
    events
        .iter()
        .filter(|(hash, _)| !cleared.contains(*hash))
        .map(|(_, (tier, _))| *tier)
        .reduce(most_restrictive_tier_floor)
}

pub(super) fn record_tier_floor(
    state: &mut FoldState,
    hash: AuthorityEntryHash,
    tier: AuthorityTier,
) {
    let observed = state.tier_floor_events.keys().copied().collect();
    state.tier_floor_events.insert(hash, (tier, observed));
    state.tier_floor = effective_tier_floor(&state.tier_floor_events).unwrap_or(tier);
}

/// The rows `present` keeps whose signer falls below a floor a concurrent
/// row among them set, with why.
pub(super) fn below_concurrent_tier_floors(
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    present: &dyn Fn(&AuthorityEntryHash) -> bool,
) -> BTreeMap<AuthorityEntryHash, AuthorityFoldIssue> {
    let floors: Vec<_> = states
        .iter()
        .filter(|(hash, _)| present(hash))
        .filter_map(|(hash, state)| {
            let requested = match entries[hash].op {
                AuthorityOp::Genesis { tier_floor, .. }
                | AuthorityOp::SetTierFloor { tier_floor } => tier_floor,
                _ => return None,
            };
            (state.tier_floor == requested).then_some((*hash, state.vault_id, requested))
        })
        .collect();
    states
        .iter()
        .filter(|(hash, _)| present(hash))
        .filter_map(|(hash, state)| {
            let signer = state.roster.get(entries[hash].signer_key())?;
            floors
                .iter()
                .any(|(floor_hash, vault, floor)| {
                    state.vault_id == *vault && hash != floor_hash
                // A tightening is not retroactive over its causal past.
                && !ancestors.get(floor_hash).is_some_and(|past| past.contains(hash))
                // A softening clears only floors in its causal past.
                && !state.tier_floor_events.values().any(|(_, seen)| seen.contains(floor_hash))
                && !tier_meets_floor(signer.tier, *floor)
                })
                .then_some((*hash, AuthorityFoldIssue::SignerBelowTierFloor(*hash)))
        })
        .collect()
}
