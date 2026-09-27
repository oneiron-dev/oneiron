//! Verified actor-revocation floors that survive ancestry invalidation.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Only an ancestry-rejected RevokeActor may contribute outside the set of
/// fully folded entries. A revoke that was Ready before retroactive pruning
/// keeps its already verified proof, even if pruning also removes the signer or
/// cosigner enrollment. One that never became Ready must pass its ordinary
/// authorization checks against the nearest surviving ancestors. In either
/// case, invalid permissive entries contribute no state. Every proof and floor
/// is derived afresh from this entry set on every fold.
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
        } else {
            // `entries` passed origin and co-signature verification, but a
            // never-Ready revoke still needs shape and authority validation.
            let mut parent_states = BTreeMap::new();
            let mut complete = true;
            for parent in &entry.parent_hashes {
                match nearest_surviving_ancestors(*parent, entries, states, context.entry_ancestors)
                {
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
