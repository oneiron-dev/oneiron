//! Causal floor updates: delayed softenings clear only observed restrictions.
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

pub(super) fn reject_below_concurrent_tier_floors(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    issues: &mut Vec<AuthorityFoldIssue>,
) {
    let floors: Vec<_> =
        states
            .iter()
            .filter_map(|(hash, state)| {
                let requested = match entries[hash].op {
                    AuthorityOp::Genesis { tier_floor, .. }
                    | AuthorityOp::SetTierFloor { tier_floor } => tier_floor,
                    _ => return None,
                };
                (!state.pending_widens.contains_key(hash) && state.tier_floor == requested)
                    .then_some((*hash, state.vault_id, requested))
            })
            .collect();
    let rejected: BTreeSet<_> = states
        .iter()
        .filter_map(|(hash, state)| {
            let signer = state.roster.get(entries[hash].signer_key())?;
            floors
                .iter()
                .any(|(floor_hash, vault, floor)| {
                    state.vault_id == *vault && hash != floor_hash
                // A tightening is not retroactive over its causal past.
                && !ancestors.get(floor_hash).is_some_and(|past| past.contains(hash))
                // A mature softening clears only floors in its causal past.
                && !state.tier_floor_events.values().any(|(_, seen)| seen.contains(floor_hash))
                && !tier_meets_floor(signer.tier, *floor)
                })
                .then_some(*hash)
        })
        .collect();
    states.retain(|hash, _| {
        if rejected.contains(hash) {
            issues.push(AuthorityFoldIssue::SignerBelowTierFloor(*hash));
            false
        } else if ancestors
            .get(hash)
            .is_some_and(|past| !past.is_disjoint(&rejected))
        {
            issues.push(AuthorityFoldIssue::InvalidAncestry(*hash));
            false
        } else {
            true
        }
    });
}
