//! Verified actor-revocation floors that survive ancestry invalidation.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Only an ancestry-rejected RevokeActor may contribute outside the set of
/// fully folded entries. A revoke that was Ready before retroactive pruning
/// keeps its already verified proof. If an equivocation loser prevented it
/// from becoming Ready, prove its signed branch in isolation. Intrinsically
/// invalid grants are skipped over within that same branch, never applied;
/// the global surviving-ancestry check is a fallback, not a separate proof
/// universe. Every proof and floor is derived afresh from this entry set.
pub(super) fn retain_invalid_ancestry_revoke_floors(
    merged: &mut FoldState,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    issues: &[AuthorityFoldIssue],
    ready_revokes: &BTreeMap<AuthorityEntryHash, AuthorityVaultId>,
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
        if let Some(vault_id) = ready_revokes.get(hash) {
            // This entry already passed shape, signature, vault, consent, quorum
            // and seq checks. Do not re-check it against a roster from which a
            // later collision removed its signer's enrollment.
            if *vault_id != merged.vault_id {
                continue;
            }
        } else if !revoke_folds_on_signed_branch(*hash, entries, context, merged.vault_id) {
            // An intrinsically invalid grant cannot become a proof of its
            // descendant's authority. Re-check against surviving ancestry.
            let mut parent_states = BTreeMap::new();
            let mut complete = true;
            for parent in &entry.parent_hashes {
                match nearest_surviving_ancestors(
                    *parent,
                    entries,
                    states,
                    context.entry_ancestors,
                    None,
                ) {
                    Some(state) => {
                        parent_states.insert(*parent, state);
                    }
                    None => {
                        complete = false;
                        break;
                    }
                }
            }
            if !complete
                || !matches!(
                    fold_entry_state(entry, *hash, &parent_states, context),
                    EntryFold::Ready(proof) if proof.vault_id == merged.vault_id
                )
            {
                continue;
            }
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

/// Walk over entries that did not survive the fold, WITHOUT applying their
/// operations. Every branch must reach real, same-vault folded authority;
/// absent or signature-invalid history cannot supply a substitute roster.
fn nearest_surviving_ancestors(
    start: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    ancestors: Option<&BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>>,
    skippable: Option<&BTreeSet<AuthorityEntryHash>>,
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
        if skippable.is_some_and(|allowed| !allowed.contains(&hash))
            || entry.parent_hashes.is_empty()
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

/// Independently verify a revoke over the complete branch it actually names.
/// A losing enrollment was valid before a competing sibling arrived; the
/// isolated branch must still prove signer, consent, quorum, vault, and seq.
/// Clear only the GLOBAL fork selection (which excluded that branch), not the
/// fold's observation time, sequence floors, consent arm or veto policy. The
/// resulting state is NEVER merged: only the proved revoke's floor escapes.
fn revoke_folds_on_signed_branch(
    target: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    context: FoldContext<'_>,
    vault_id: AuthorityVaultId,
) -> bool {
    let Some(ancestors) = context.entry_ancestors else {
        return false;
    };
    let Some(past) = ancestors.get(&target) else {
        return false;
    };
    if past.contains(&target) {
        return false;
    }
    let mut pending = past.clone();
    pending.insert(target);
    let mut signer_seqs = BTreeMap::new();
    for hash in &pending {
        let Some(entry) = entries.get(hash) else {
            return false;
        };
        // A single proof must not merge two equivocated grants from the SAME
        // signed ancestry into a made-up roster. A sibling outside the branch
        // is fine: it is precisely why this branch was excluded globally.
        if signer_seqs
            .insert((entry.signer_key().clone(), entry.seq), *hash)
            .is_some_and(|previous| previous != *hash)
        {
            return false;
        }
    }
    let empty_forks = BTreeMap::new();
    let empty_fork_vault_ids = BTreeMap::new();
    let empty_groups = BTreeMap::new();
    let empty_unresolved = BTreeSet::new();
    let branch_context = FoldContext {
        authority_forks: &empty_forks,
        authority_fork_vault_ids: &empty_fork_vault_ids,
        equivocation_groups: &empty_groups,
        unresolved_equivocation_groups: &empty_unresolved,
        chain_validated_fork_candidates: None,
        ..context
    };
    let mut states = BTreeMap::new();
    let mut invalid = BTreeSet::new();
    while !pending.is_empty() {
        let mut progressed = false;
        for hash in pending.clone() {
            match fold_entry_state(&entries[&hash], hash, &states, branch_context) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Invalid(_) if hash != target => {
                    // No permissive state enters this proof from an invalid
                    // entry. Its valid prefix can still authorize the revoke.
                    invalid.insert(hash);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Invalid(_) => return false,
                EntryFold::Waiting => {}
            }
        }
        if !progressed {
            break;
        }
    }
    if let Some(state) = states.get(&target) {
        return state.vault_id == vault_id;
    }
    if invalid.is_empty() {
        return false;
    }
    // A child of an invalid entry also cannot contribute permissive state.
    // Only unresolved descendants of an actual invalid ancestor may be
    // crossed; another kind of wait must not turn into an ancestry bypass.
    let skippable: BTreeSet<_> = invalid
        .iter()
        .copied()
        .chain(pending.iter().copied().filter(|hash| {
            *hash != target
                && ancestors
                    .get(hash)
                    .is_some_and(|past| !past.is_disjoint(&invalid))
        }))
        .collect();
    let mut parent_states = BTreeMap::new();
    for parent in &entries[&target].parent_hashes {
        let Some(state) = nearest_surviving_ancestors(
            *parent,
            entries,
            &states,
            context.entry_ancestors,
            Some(&skippable),
        ) else {
            return false;
        };
        parent_states.insert(*parent, state);
    }
    matches!(
        fold_entry_state(&entries[&target], target, &parent_states, branch_context),
        EntryFold::Ready(proof) if proof.vault_id == vault_id
    )
}
