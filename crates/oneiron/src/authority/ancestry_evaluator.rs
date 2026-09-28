//! Shared stalled-revocation ancestry evaluation for ordinary and proof folds.
//!
//! A rejected permissive ancestor may be skipped only after its own transition
//! failed; its op is never applied in a substitute state. The caller receives a
//! scratch proof, not permissive state. This is the ancestry-invalidation rule
//! (identity canon, "Ancestry invalidation (2026-08-03)"): a verified
//! `RevokeActor` still lands its epoch floor when its ancestry turns invalid.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// One entry-progress rule for the ordinary fold and signed-branch proof.
/// During normal rounds no ancestry is bypassed. After a full stalled round,
/// only a signed withdrawal may cross proven-rejected permissive parents: a
/// RevokeActor, or a slip revoke or consume (the ordinary fold passes only
/// retired client enrollments; the signed-branch proof rescues only revokes).
pub(super) enum EvaluationPhase<'a> {
    Normal,
    Stalled(&'a BTreeSet<AuthorityEntryHash>),
}

pub(super) fn evaluate_entry(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    context: FoldContext<'_>,
    phase: EvaluationPhase<'_>,
) -> EntryFold {
    let result = fold_entry_state(entry, hash, states, context);
    let EvaluationPhase::Stalled(rejected) = phase else {
        return result;
    };
    if !matches!(result, EntryFold::Waiting) {
        return result;
    }
    stalled_actor_revoke(entry, hash, entries, states, rejected, context)
        .map_or(EntryFold::Waiting, EntryFold::Ready)
}

/// Rejected entries may only be crossed when they are permissive. The
/// caller's diagnostic set is not enough to bypass an arbitrary operation.
pub(super) fn skippable_permissive(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::BindActor { .. }
            | AuthorityOp::RebindActor { .. }
            | AuthorityOp::EnrollDevice { .. }
            | AuthorityOp::FederationLifecycle(_)
    )
}

/// Try a stalled withdrawal against explicitly rejected parents, which
/// signed-history verification passes as its own rejected ancestors.
fn stalled_actor_revoke(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    rejected: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<FoldState> {
    if !matches!(
        entry.op,
        AuthorityOp::RevokeActor { .. }
            | AuthorityOp::SlipRevoke { .. }
            | AuthorityOp::SlipConsume { .. }
    ) {
        return None;
    }
    let mut scratch = states.clone();
    let mut substituted = false;
    for parent in &entry.parent_hashes {
        if !scratch.contains_key(parent) {
            let state = resolve_parent(*parent, entries, states, rejected, context)?;
            scratch.insert(*parent, state);
            substituted = true;
        }
    }
    // A stall on consent or sequence is not a rejected parent.
    if !substituted {
        return None;
    }
    match fold_entry_state(entry, hash, &scratch, context) {
        EntryFold::Ready(state) => Some(state),
        EntryFold::Invalid(_) | EntryFold::Waiting => None,
    }
}

/// Explicit outcomes for EACH missing parent.
enum ParentOutcome<'a> {
    Ready(&'a FoldState),
    RejectedAncestry,
    Unavailable,
}

fn parent_outcome<'a>(
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
    states: &'a BTreeMap<AuthorityEntryHash, FoldState>,
    rejected: &BTreeSet<AuthorityEntryHash>,
) -> ParentOutcome<'a> {
    if let Some(state) = states.get(&hash) {
        return ParentOutcome::Ready(state);
    }
    if rejected.contains(&hash) && skippable_permissive(&entry.op) {
        return ParentOutcome::RejectedAncestry;
    }
    ParentOutcome::Unavailable
}

/// Resolve every branch to real folded evidence. An otherwise rejected grant
/// is skipped and its op never applies. Missing or cyclic history and
/// incompatible vault roots refuse the whole restrictive proof.
fn resolve_parent(
    start: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    rejected: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<FoldState> {
    let mut visited = BTreeSet::new();
    let mut frontier = vec![start];
    let mut merged: Option<FoldState> = None;
    let mut crossed_vaults = Vec::new();
    while let Some(hash) = frontier.pop() {
        if !visited.insert(hash) {
            continue;
        }
        let entry = entries.get(&hash)?;
        if context
            .entry_ancestors
            .and_then(|index| index.get(&hash))
            .is_some_and(|past| past.contains(&hash))
        {
            return None;
        }
        match parent_outcome(hash, entry, states, rejected) {
            ParentOutcome::Ready(state) => {
                merged = Some(match merged {
                    Some(current) if current.vault_id != state.vault_id => return None,
                    Some(current) => merge_states(&current, state),
                    None => state.clone(),
                });
            }
            ParentOutcome::RejectedAncestry => {
                if entry.parent_hashes.is_empty() {
                    return None;
                }
                crossed_vaults.push(entry.vault_id);
                frontier.extend(entry.parent_hashes.iter().copied());
            }
            ParentOutcome::Unavailable => return None,
        }
    }
    if crossed_vaults
        .iter()
        .any(|vault| *vault != merged.as_ref().map(|state| state.vault_id))
    {
        return None;
    }
    merged
}
