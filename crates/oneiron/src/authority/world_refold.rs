//! A world edit, a world key record, a grant travel choice, or a root request,
//! the owner's cancel of one or its result, above a main-log row the fold did
//! not keep, folded again with that row crossed.
use std::collections::{BTreeMap, BTreeSet};

use super::world_privacy::side_world;
use super::*;

/// Whether a row with no state is folded again above a main-log row the fold
/// did not keep: a world's side row, and the main-log rows that are
/// restrictive too. A world edit and a grant travel choice must not fall with
/// an unrelated row either (FIX 2998; settings edits left the side branch
/// for the mesh, contract §6), and neither may the owner's checkpoint policy
/// choice (mesh PR2c), home pick (DOOR-101) or a person's conversation
/// training choice (FIX 4489), nor a root request or the owner's cancel of
/// one ([`closes_root_work`], FIX 5584), nor a root request's result
/// ([`answers_root_work`], FIX 5649). `kind_of` reads the kind of the owner
/// work request signed as a hash from the request's own row, where the fold
/// holds one. A fold past an adopted image reads the same class (FIX 5463).
pub(super) fn refolds(
    op: &AuthorityOp,
    kind_of: impl Fn(&AuthorityEntryHash) -> Option<OwnerWorkKind>,
) -> bool {
    side_world(op).is_some()
        || closes_root_work(op)
        || answers_root_work(op, kind_of)
        || matches!(
            op,
            AuthorityOp::WorldPrivacy(_)
                | AuthorityOp::GrantTravelSet(_)
                | AuthorityOp::CheckpointPolicySet(_)
                | AuthorityOp::HomeNodePick(_)
                | AuthorityOp::ConversationTrainingSet(_)
                | AuthorityOp::ConversationTrainingVaultSet(_)
        )
}

/// A root request, or the owner's cancel of one (CALLS "FIX 5584 refold
/// scope"): either may close an older root request (CALLS ROOT_WORK_CANCEL,
/// ROOT_WORK_SUPERSESSION), so neither falls with an unrelated row. A world
/// key, bundle or custody request is not folded again; a root request's
/// result is ([`answers_root_work`]).
fn closes_root_work(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::OwnerWorkRequest(request) => request.kind() == OwnerWorkKind::Root,
        AuthorityOp::OwnerWorkCancel(_) => true,
        _ => false,
    }
}

/// A result of a root request (CALLS "FIX 5584 refold scope", FIX 5649), the
/// request's kind judged as [`closes_root_work`] and the result transition
/// judge it, from the request itself (`kind_of`): a root request recovered
/// past a lost main-log row never reads unanswered and runnable again with
/// its result lost, so root work never runs twice. A world key, bundle or
/// custody request's result keeps today's path, and so does a result whose
/// request the fold holds no row of.
fn answers_root_work(
    op: &AuthorityOp,
    kind_of: impl Fn(&AuthorityEntryHash) -> Option<OwnerWorkKind>,
) -> bool {
    matches!(op, AuthorityOp::OwnerWorkResult(result)
        if kind_of(&result.request) == Some(OwnerWorkKind::Root))
}

/// The kind of the owner work request `row` is; None for any other row.
pub(super) fn request_kind(row: &AuthorityLogEntry) -> Option<OwnerWorkKind> {
    match &row.op {
        AuthorityOp::OwnerWorkRequest(request) => Some(request.kind()),
        _ => None,
    }
}

/// The kind of the owner work request signed as `hash` whose body `image`
/// carries; None when it carries none, or no request's.
pub(super) fn carried_request_kind(
    image: &AuthorityCheckpointV2,
    hash: &AuthorityEntryHash,
) -> Option<OwnerWorkKind> {
    let body = image.rows.get(hash)?.body.as_ref()?;
    request_kind(&decode_authority_log_entry_body(body).ok()?)
}

/// Settlement drops every row above a main-log row it refuses (a retired
/// signer's fence, a confirmation collision, an unsettled handoff), and the door names every main-log head as a parent, so
/// a world's edits would fall with an unrelated row and the world would read
/// wider than the owner set it (Wonder P2 round 1, W1). A world edit is judged
/// on the main log as the fold keeps it: every edit above a main-log row the
/// fold did not keep is folded again, in causal order, with each such row
/// crossed, never applied. An edit invalid on its own stays invalid. Crossing
/// gives no signer more than this replica's fold already gives the same edit
/// signed on the crossed row's parents instead (Wonder P2 round 2, W1). A
/// root request, cancel or root request's result folded again folds before
/// the rows crossed above it, so what descends from it reads it (FIX 5584,
/// 5649).
pub(super) fn refold_world_edits(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
    issues: &mut Vec<AuthorityFoldIssue>,
) {
    let kind_of = |request: &AuthorityEntryHash| by_hash.get(request).and_then(request_kind);
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
    // An invalid edit or choice one descends from is crossed like any
    // main-log row.
    let lost = causal(
        by_hash
            .iter()
            .filter(|(hash, entry)| {
                refolds(&entry.op, kind_of)
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
    let selected: BTreeSet<_> = lost.iter().copied().collect();
    let mut stand_ins = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    for hash in crossed {
        let entry = &by_hash[&hash];
        // A root request, cancel or root request's result folded again, with
        // a row folded again above it, folds here on its parents' kept or
        // standing-in states, before any row crossed above it: a cancel or
        // newer request there so finds the request it closes (FIX 5584), and
        // a request recovered here keeps the result recovered after it (FIX
        // 5649). One that does not fold stands for its parents' merge, as
        // every other crossed row does.
        if (closes_root_work(&entry.op) || answers_root_work(&entry.op, kind_of))
            && selected.contains(&hash)
        {
            let parents = parent_states(entry, states, &stand_ins);
            if let EntryFold::Ready(state) = fold_entry_state(entry, hash, &parents, context) {
                keep(states, issues, hash, state);
                continue;
            }
        }
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
        // Folded above, before a row crossed above it.
        if states.contains_key(&hash) {
            continue;
        }
        let entry = &by_hash[&hash];
        let parents = parent_states(entry, states, &stand_ins);
        if let EntryFold::Ready(state) = fold_entry_state(entry, hash, &parents, context) {
            keep(states, issues, hash, state);
        }
    }
}

/// The states `entry`'s parents fold to here: each kept, or crossed and
/// standing for its own parents.
fn parent_states(
    entry: &AuthorityLogEntry,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    stand_ins: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> BTreeMap<AuthorityEntryHash, FoldState> {
    entry
        .parent_hashes
        .iter()
        .filter_map(|parent| {
            states
                .get(parent)
                .or_else(|| stand_ins.get(parent))
                .map(|state| (*parent, state.clone()))
        })
        .collect()
}

/// Keeps `state` as the fold of the row `hash`, without the issues its fold
/// above the crossed row raised.
fn keep(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    issues: &mut Vec<AuthorityFoldIssue>,
    hash: AuthorityEntryHash,
    state: FoldState,
) {
    states.insert(hash, state);
    issues.retain(|issue| {
        !matches!(issue,
            AuthorityFoldIssue::InvalidEntry(row)
            | AuthorityFoldIssue::InvalidAncestry(row)
            | AuthorityFoldIssue::SignerNotInAncestry(row)
            | AuthorityFoldIssue::NonMonotonicSeq(row) if *row == hash)
    });
}
