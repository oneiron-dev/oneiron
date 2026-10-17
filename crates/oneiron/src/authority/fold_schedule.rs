//! The fold's per-entry scheduler.
//!
//! Each step applies the first pending entry, in (non-revocation, hash)
//! order, whose transition does not wait. A transition reads only its own
//! row and its parents' states, so an entry that waits keeps waiting until
//! one of its parents lands. The queue therefore holds only the entries that
//! may have changed since they last waited, and each step picks the entry a
//! full rescan of every pending entry would pick: the same fold, without the
//! rescan's quadratic work on a long chain (H72).

use std::collections::{BTreeMap, BTreeSet};

use super::ancestry_evaluator::{EvaluationPhase, evaluate_entry};
use super::*;

/// Folds every entry of `by_hash` it can, and records why each other entry
/// never folds.
pub(super) fn fold_entry_states(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    context: FoldContext<'_>,
    issues: &mut Vec<AuthorityFoldIssue>,
) -> BTreeMap<AuthorityEntryHash, FoldState> {
    fold_entry_states_seeded(by_hash, &BTreeMap::new(), context, issues)
}

/// [`fold_entry_states`] over `by_hash` with `seed` already folded (OF-469,
/// an adopted checkpoint's frontier states): a seed row is a parent state
/// only, never pending, replayed or counted, and every entry of `by_hash`
/// still passes its own transition's checks. The states returned hold the
/// seed's too. A full fold seeds nothing.
pub(super) fn fold_entry_states_seeded(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    seed: &BTreeMap<AuthorityEntryHash, FoldState>,
    context: FoldContext<'_>,
    issues: &mut Vec<AuthorityFoldIssue>,
) -> BTreeMap<AuthorityEntryHash, FoldState> {
    let mut children = BTreeMap::<AuthorityEntryHash, Vec<AuthorityEntryHash>>::new();
    for (hash, entry) in by_hash {
        for parent in &entry.parent_hashes {
            children.entry(*parent).or_default().push(*hash);
        }
    }
    // A revoke whose parent just landed goes before any ready grant.
    let order = |hash: &AuthorityEntryHash| {
        (
            !matches!(
                by_hash[hash].op,
                AuthorityOp::RevokeActor { .. } | AuthorityOp::RevokeDevice { .. }
            ),
            *hash,
        )
    };
    let mut states = seed.clone();
    let mut rejected_retired = BTreeSet::new();
    let mut pending: BTreeSet<AuthorityEntryHash> = by_hash
        .keys()
        .filter(|hash| !seed.contains_key(*hash))
        .copied()
        .collect();
    let mut queue: BTreeSet<_> = pending.iter().map(order).collect();
    loop {
        while let Some((_, hash)) = queue.pop_first() {
            let entry = &by_hash[&hash];
            match evaluate_entry(
                entry,
                hash,
                by_hash,
                &states,
                context,
                EvaluationPhase::Normal,
            ) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    let woken = children.get(&hash).into_iter().flatten();
                    queue.extend(woken.filter(|child| pending.contains(*child)).map(order));
                }
                EntryFold::Invalid(issue) => {
                    // Only the retired client-key door may be crossed as a
                    // valid folded revoke. Other rejected grants keep the
                    // separate, restriction-only proof path: their children
                    // do not become ordinary valid entries.
                    if matches!(entry.op, AuthorityOp::EnrollDevice { .. })
                        && entry_is_retired(entry, hash, context)
                    {
                        rejected_retired.insert(hash);
                    }
                    issues.push(issue);
                    pending.remove(&hash);
                }
                EntryFold::Waiting => {}
            }
        }
        if rejected_retired.is_empty() {
            break;
        }
        // Every hash still pending is stuck for good. Only here may a signed
        // withdrawal resolve against the ancestry above a retired client
        // enrollment it descends from. Retiring a client-key op does not
        // erase a withdrawal its old root authorized: the rejected row must
        // still fold under the historical rule (signature, signer, quorum,
        // ancestry), but its granted key is never installed.
        let crossable: BTreeSet<_> = rejected_retired
            .iter()
            .copied()
            .filter(|hash| {
                matches!(
                    fold_entry_state(
                        &by_hash[hash],
                        *hash,
                        &states,
                        FoldContext {
                            pre_handoff_entries: None,
                            ..context
                        },
                    ),
                    EntryFold::Ready(_)
                )
            })
            .collect();
        let stalled: Vec<_> = pending.iter().copied().collect();
        let mut progressed = false;
        for hash in stalled {
            if let EntryFold::Ready(state) = evaluate_entry(
                &by_hash[&hash],
                hash,
                by_hash,
                &states,
                context,
                EvaluationPhase::Stalled(&crossable),
            ) {
                states.insert(hash, state);
                pending.remove(&hash);
                let woken = children.get(&hash).into_iter().flatten();
                queue.extend(woken.filter(|child| pending.contains(*child)).map(order));
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    for hash in pending {
        issues.push(AuthorityFoldIssue::InvalidAncestry(hash));
    }
    states
}
