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

/// One floor a present row set: the row, its vault and the tier it requires.
pub(super) type ConcurrentFloor = (AuthorityEntryHash, AuthorityVaultId, AuthorityTier);

/// The floors the rows `present` keeps set and still hold.
pub(super) fn concurrent_tier_floors(
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    present: &dyn Fn(&AuthorityEntryHash) -> bool,
) -> Vec<ConcurrentFloor> {
    states
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
        .collect()
}

/// Why the row `hash`, folded to `state`, falls under one of `floors` that it
/// neither precedes nor saw softened: its signer is below that floor, or its
/// consent or quorum rested on a cosigner below it (H71), as `participants`
/// judges them again with that floor in force. An owner anchor's rows rest on
/// no roster key, so a roster that also lists the anchor's public key at a low
/// tier prunes none of them (Sol code-R2 S2-F3).
pub(super) fn below_a_concurrent_floor(
    hash: &AuthorityEntryHash,
    state: &FoldState,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    floors: &[ConcurrentFloor],
    participants: &dyn Fn(AuthorityTier) -> std::result::Result<(), AuthorityFoldIssue>,
) -> Option<AuthorityFoldIssue> {
    if state.anchor_entries.contains(hash) {
        return None;
    }
    let entry = &entries[hash];
    let signer = state.roster.get(entry.signer_key())?;
    let mut concurrent = floors.iter().filter(|(floor_hash, vault, _)| {
        state.vault_id == *vault && hash != floor_hash
            // A tightening is not retroactive over its causal past.
            && !ancestors.get(floor_hash).is_some_and(|past| past.contains(hash))
            // A softening clears only floors in its causal past.
            && !state.tier_floor_events.values().any(|(_, seen)| seen.contains(floor_hash))
    });
    if concurrent
        .clone()
        .any(|(_, _, floor)| !tier_meets_floor(signer.tier, *floor))
    {
        return Some(AuthorityFoldIssue::SignerBelowTierFloor(*hash));
    }
    if entry.cosigns.is_empty() {
        return None;
    }
    concurrent.find_map(|(_, _, floor)| participants(*floor).err())
}

/// The rows `present` keeps that fall under a floor a concurrent row among
/// them set, with why.
pub(super) fn below_concurrent_tier_floors(
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    present: &dyn Fn(&AuthorityEntryHash) -> bool,
    context: FoldContext<'_>,
) -> BTreeMap<AuthorityEntryHash, AuthorityFoldIssue> {
    let floors = concurrent_tier_floors(states, entries, present);
    states
        .iter()
        .filter(|(hash, _)| present(hash))
        .filter_map(|(hash, state)| {
            let entry = &entries[hash];
            below_a_concurrent_floor(hash, state, entries, ancestors, &floors, &|floor| {
                participants_under_floor(entry, states, floor, context)
            })
            .map(|issue| (*hash, issue))
        })
        .collect()
}

/// Judges `entry`'s participants again over its parents' merged state, with
/// `floor` in force. A row whose parents did not all fold stands as it folded.
pub(super) fn participants_under_floor(
    entry: &AuthorityLogEntry,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    floor: AuthorityTier,
    context: FoldContext<'_>,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let mut merged: Option<FoldState> = None;
    for parent in &entry.parent_hashes {
        let Some(state) = states.get(parent) else {
            return Ok(());
        };
        merged = Some(match merged {
            Some(current) => merge_states(&current, state),
            None => state.clone(),
        });
    }
    let Some(state) = merged else {
        return Ok(());
    };
    participants_with_floor(state, entry, floor, context)
}

/// Judges `entry`'s participants over `state` with `floor` in force, so a
/// cosigner below it counts toward neither consent nor quorum.
pub(super) fn participants_with_floor(
    mut state: FoldState,
    entry: &AuthorityLogEntry,
    floor: AuthorityTier,
    context: FoldContext<'_>,
) -> std::result::Result<(), AuthorityFoldIssue> {
    state.tier_floor = most_restrictive_tier_floor(state.tier_floor, floor);
    participant_rules_hold(&state, entry, context)
}
