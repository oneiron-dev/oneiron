//! Verified actor-revocation floors that survive ancestry invalidation.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Only an ancestry-rejected RevokeActor may contribute outside the set of
/// fully folded entries. Re-run its ordinary authorization checks against the
/// nearest surviving ancestors: signatures alone cannot turn an outsider into
/// a revocation signer, and an invalid grant must not carry permissive state.
/// The result is derived afresh from this entry set on every fold.
pub(super) fn retain_invalid_ancestry_revoke_floors(
    merged: &mut FoldState,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    issues: &[AuthorityFoldIssue],
    context: FoldContext<'_>,
) {
    for issue in issues {
        let AuthorityFoldIssue::InvalidAncestry(hash) = issue else {
            continue;
        };
        let Some(entry) = entries.get(hash) else {
            continue;
        };
        let AuthorityOp::RevokeActor {
            authority_key,
            epoch,
        } = &entry.op
        else {
            continue;
        };
        // `entries` already passed origin and co-signature verification, but
        // shape (including a nonzero epoch) is checked by fold_entry_state.
        let mut parent_states = BTreeMap::new();
        let mut complete = true;
        for parent in &entry.parent_hashes {
            match nearest_surviving_ancestors(*parent, entries, states, context.entry_ancestors) {
                Some(state) => {
                    parent_states.insert(*parent, state);
                }
                None => {
                    complete = false;
                    break;
                }
            }
        }
        if !complete {
            continue;
        }
        if let EntryFold::Ready(proof) = fold_entry_state(entry, *hash, &parent_states, context) {
            if proof.vault_id != merged.vault_id {
                continue;
            }
            merged
                .actor_binding_revocations
                .entry(authority_key.clone())
                .and_modify(|floor| *floor = (*floor).max(*epoch))
                .or_insert(*epoch);
            merged
                .actor_revocation_hashes
                .entry(authority_key.clone())
                .or_default()
                .insert(*hash);
        }
    }
}

/// Walk over entries that did not survive the fold, WITHOUT applying their
/// operations. Every branch must reach real, same-vault folded authority;
/// absent or signature-invalid history cannot supply a substitute roster.
fn nearest_surviving_ancestors(
    start: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    ancestors: Option<&BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>>,
) -> Option<FoldState> {
    let mut frontier = vec![start];
    let mut visited = BTreeSet::new();
    let mut resolved: Option<FoldState> = None;
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
        let entry = entries.get(&hash)?;
        if entry.parent_hashes.is_empty()
            || ancestors
                .and_then(|index| index.get(&hash))
                .is_some_and(|past| past.contains(&hash))
        {
            return None;
        }
        frontier.extend(entry.parent_hashes.iter().copied());
    }
    if visited.iter().any(|hash| {
        !states.contains_key(hash)
            && entries[hash].vault_id != resolved.as_ref().map(|state| state.vault_id)
    }) {
        return None;
    }
    resolved
}
