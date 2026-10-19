//! A world edit, a world key record or a grant travel choice above a main-log
//! row the fold did not keep, folded again with that row crossed.
use std::collections::{BTreeMap, BTreeSet};

use super::world_privacy::side_world;
use super::*;

/// Settlement drops every row above a main-log row it refuses (a retired
/// signer's fence, a confirmation collision, an unsettled handoff), and the door names every main-log head as a parent, so
/// a world's edits would fall with an unrelated row and the world would read
/// wider than the owner set it (Wonder P2 round 1, W1). A world edit is judged
/// on the main log as the fold keeps it: every edit above a main-log row the
/// fold did not keep is folded again, in causal order, with each such row
/// crossed, never applied. An edit invalid on its own stays invalid. Crossing
/// gives no signer more than this replica's fold already gives the same edit
/// signed on the crossed row's parents instead (Wonder P2 round 2, W1).
pub(super) fn refold_world_edits(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
    issues: &mut Vec<AuthorityFoldIssue>,
) {
    let causal = |hashes: BTreeSet<AuthorityEntryHash>| {
        let mut hashes: Vec<_> = hashes.into_iter().collect();
        hashes.sort_by_key(|hash| (ancestors.get(hash).map_or(0, BTreeSet::len), *hash));
        hashes
    };
    let crossable = |hash: &AuthorityEntryHash| {
        !states.contains_key(hash)
            && by_hash
                .get(hash)
                .is_some_and(|entry| side_world(&entry.op).is_none())
    };
    // A world edit and a grant travel choice are main-log rows, but
    // restrictive: they must not fall with an unrelated row either (FIX
    // 2998; settings edits left the side branch for the mesh, contract §6),
    // and neither may the owner's checkpoint policy choice (mesh PR2c) or
    // home pick (DOOR-101).
    // An invalid edit or choice one descends from is crossed like any
    // main-log row.
    let lost = causal(
        by_hash
            .iter()
            .filter(|(hash, entry)| {
                (side_world(&entry.op).is_some()
                    || matches!(
                        entry.op,
                        AuthorityOp::WorldPrivacy(_)
                            | AuthorityOp::GrantTravelSet(_)
                            | AuthorityOp::CheckpointPolicySet(_)
                            | AuthorityOp::HomeNodePick(_)
                    ))
                    && !states.contains_key(*hash)
                    && ancestors
                        .get(*hash)
                        .is_some_and(|past| past.iter().any(crossable))
            })
            .map(|(hash, _)| *hash)
            .collect(),
    );
    if lost.is_empty() {
        return;
    }
    // A main-log row the fold did not keep stands for the merge of its
    // parents, each kept or crossed in turn. Its signed sequence still bounds
    // what its signer signs after it (Sol P2 round 5, F4).
    let crossed = causal(
        lost.iter()
            .filter_map(|hash| ancestors.get(hash))
            .flatten()
            .filter(|hash| crossable(hash))
            .copied()
            .collect(),
    );
    let mut stand_ins = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    for hash in crossed {
        let entry = &by_hash[&hash];
        let mut parents = entry
            .parent_hashes
            .iter()
            .map(|parent| states.get(parent).or_else(|| stand_ins.get(parent)));
        // Parents of two vaults stand for nothing (Sol P2 round 5, F6).
        let merged = parents.next().flatten().and_then(|first| {
            parents.try_fold(first.clone(), |merged, next| {
                next.filter(|state| state.vault_id == merged.vault_id)
                    .map(|state| merge_states(&merged, state))
            })
        });
        if let Some(mut state) = merged.filter(|state| entry.vault_id == Some(state.vault_id)) {
            let seq = state
                .seqs
                .entry(entry.signer_key().clone())
                .or_insert(entry.seq);
            *seq = (*seq).max(entry.seq);
            stand_ins.insert(hash, state);
        }
    }
    for hash in lost {
        let entry = &by_hash[&hash];
        let parents: BTreeMap<_, _> = entry
            .parent_hashes
            .iter()
            .filter_map(|parent| {
                states
                    .get(parent)
                    .or_else(|| stand_ins.get(parent))
                    .map(|state| (*parent, state.clone()))
            })
            .collect();
        if let EntryFold::Ready(state) = fold_entry_state(entry, hash, &parents, context) {
            states.insert(hash, state);
            issues.retain(|issue| {
                !matches!(issue,
                    AuthorityFoldIssue::InvalidEntry(row)
                    | AuthorityFoldIssue::InvalidAncestry(row)
                    | AuthorityFoldIssue::SignerNotInAncestry(row)
                    | AuthorityFoldIssue::NonMonotonicSeq(row) if *row == hash)
            });
        }
    }
}
