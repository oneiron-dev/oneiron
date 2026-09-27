//! Stalled-revocation bypass with freeze classifier and chain probe.
//!
use std::collections::{BTreeMap, BTreeSet};

use super::*;

pub(in crate::authority) fn revocation_bypass_states(
    entry: &AuthorityLogEntry,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<BTreeMap<AuthorityEntryHash, FoldState>> {
    if !matches!(
        entry.op,
        AuthorityOp::RevokeActor { .. }
            | AuthorityOp::SlipRevoke { .. }
            | AuthorityOp::SlipConsume { .. }
    ) {
        return None;
    }
    let mut substitutes = BTreeMap::new();
    for parent in &entry.parent_hashes {
        if states.contains_key(parent) {
            continue;
        }
        let nearest = nearest_unfrozen_ancestor_state(*parent, by_hash, states, pending, context)?;
        substitutes.insert(*parent, nearest);
    }
    // No unresolved parent means the entry stalled on something else entirely
    // (seq, consent); leave every other path exactly as it was.
    if substitutes.is_empty() {
        return None;
    }
    let mut merged = states.clone();
    merged.extend(substitutes);
    Some(merged)
}

/// Walks up from a frozen entry to the merge of the nearest folded states.
///
/// Every branch must terminate in a READY ancestor, crossing only entries the
/// pending-widen freeze is holding. Anything else — an invalid ancestor, a
/// missing one, a root that never folded, a parent waiting for some other
/// reason — refuses the bypass outright.
fn nearest_unfrozen_ancestor_state(
    start: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<FoldState> {
    let mut resolved: Option<FoldState> = None;
    let mut visited = BTreeSet::new();
    let mut frontier = vec![start];
    while let Some(hash) = frontier.pop() {
        if !visited.insert(hash) {
            continue;
        }
        if let Some(state) = states.get(&hash) {
            resolved = Some(match resolved {
                Some(current) if current.vault_id != state.vault_id => return None,
                Some(current) => merge_states(&current, state),
                None => state.clone(),
            });
            continue;
        }
        let entry = by_hash.get(&hash)?;
        if entry.parent_hashes.is_empty() {
            return None;
        }
        // Retiring a client-key op does not erase an independently authorized
        // withdrawal signed by its old root. Check the rejected row's OWN
        // signature, signer, quorum and ancestry under the historical rule,
        // but use only its *parents'* folded states for the withdrawal. Never
        // install the rejected operation's granted key or changed floor.
        let retired = context.pre_handoff_entries.is_some_and(|permitted| {
            !permitted.contains(&hash)
                && matches!(
                    entry.op,
                    AuthorityOp::EnrollDevice { .. }
                        | AuthorityOp::RotateKey { .. }
                        | AuthorityOp::SetTierFloor { .. }
                        | AuthorityOp::VetoPendingWiden { .. }
                )
        });
        if retired && !pending.contains(&hash) {
            if !entry
                .parent_hashes
                .iter()
                .all(|parent| states.contains_key(parent))
                || !matches!(
                    fold_entry_state(
                        entry,
                        hash,
                        states,
                        FoldContext {
                            pre_handoff_entries: None,
                            deadline_observer: None,
                            ..context
                        },
                    ),
                    EntryFold::Ready(_)
                )
            {
                return None;
            }
        } else if !pending.contains(&hash)
            || !entry_is_frozen_by_pending_widen(entry, by_hash, states, pending, context)
        {
            return None;
        }
        frontier.extend(entry.parent_hashes.iter().copied());
    }
    resolved
}

/// Whether `entry` is stalled by the pending-widen freeze specifically.
///
/// This is the bypass's load-bearing narrowing, so it is decided POSITIVELY
/// rather than by elimination: the entry's own ancestry must resolve, that
/// ancestry must actually carry a pending widen, and the entry's op must be one
/// the freeze defers. An entry that is waiting for any other reason fails this
/// and stops the walk.
///
/// The classification is read off the MERGED ancestry, because that is the only
/// picture the freeze itself ever sees. `fold_entry_state` merges every parent
/// state before testing `!state.pending_widens.is_empty()`, so a single
/// widen-bearing branch parks the entry no matter how many clean siblings it
/// has. Asking instead whether EVERY branch carries a widen would answer a
/// question the fold never poses, and the disagreement is attacker-selectable:
/// hanging one ordinary already-folded parent off a stall grant would make the
/// classifier call a frozen entry unfrozen and collapse the bypass
/// (`revoke_actor_folds_past_a_grant_frozen_through_only_one_of_its_parents`).
///
/// Every parent must still RESOLVE. That is the narrowing this shares with
/// [`nearest_unfrozen_ancestor_state`]: a branch that dead-ends in an invalid,
/// missing, or otherwise-waiting ancestor refuses the classification outright,
/// so "frozen" never widens to mean "stuck for some reason we did not identify."
pub(in crate::authority) fn entry_is_frozen_by_pending_widen(
    entry: &AuthorityLogEntry,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> bool {
    if !context.enforce_seen_time_delay || op_applies_despite_pending_widen(&entry.op) {
        return false;
    }
    let mut merged: Option<FoldState> = None;
    for parent in &entry.parent_hashes {
        let Some(state) =
            nearest_unfrozen_ancestor_state(*parent, by_hash, states, pending, context)
        else {
            return false;
        };
        merged = Some(match merged {
            Some(current) if current.vault_id != state.vault_id => return false,
            Some(current) => merge_states(&current, &state),
            None => state,
        });
    }
    merged.is_some_and(|state| !state.pending_widens.is_empty())
}

/// Chain-validation probe: re-folds `target_hash` over its own complete
/// ancestry.
///
/// It inherits exactly TWO things from the enclosing fold — the consent arm and
/// the admitted peer consent roots — because those define what "folds" MEANS.
/// A probe answering under different consent semantics than the fold it serves
/// would quietly disagree with it about which history can vouch a sequence floor.
pub(in crate::authority) fn entry_folds_on_available_ancestry(
    target_hash: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> bool {
    let Some(target_ancestors) = ancestors.get(&target_hash) else {
        return false;
    };
    if target_ancestors
        .iter()
        .any(|ancestor| !by_hash.contains_key(ancestor))
    {
        return false;
    }
    let first_seen_at_secs = BTreeMap::new();
    let vetoed_widens = BTreeSet::new();
    let mut states = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    let mut pending = target_ancestors.clone();
    pending.insert(target_hash);

    for _ in 0..=pending.len() {
        if states.contains_key(&target_hash) {
            return true;
        }
        let hashes: Vec<_> = pending.iter().copied().collect();
        let mut progressed = false;
        for hash in hashes {
            let Some(entry) = by_hash.get(&hash) else {
                return false;
            };
            match fold_entry_state(
                entry,
                hash,
                &states,
                FoldContext {
                    first_seen_at_secs: &first_seen_at_secs,
                    now_secs: None,
                    enforce_seen_time_delay: false,
                    vetoed_widens: &vetoed_widens,
                    entry_ancestors: Some(ancestors),
                    ..context
                },
            ) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Waiting => {}
                EntryFold::Invalid(_) => return false,
            }
        }
        if !progressed {
            return false;
        }
    }
    false
}
