//! Shared stalled-revocation ancestry evaluation for ordinary and proof folds.
//!
//! A rejected permissive ancestor may be skipped only after its own transition
//! failed. A frozen one may be crossed only by the positive pending-widen
//! classifier in `revocation_bypass_states`. Neither op is ever applied in a
//! substitute state. The caller receives a scratch proof, not permissive state.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// One entry-progress rule for the ordinary fold and signed-branch proof.
/// During normal rounds no ancestry is bypassed. After a full stalled round,
/// only a RevokeActor may cross proven-rejected permissive parents, and the
/// positive pending-widen classifier is the sole way to cross frozen parents.
/// Slip revocations retain their existing frozen-only rule.
pub(super) enum EvaluationPhase<'a> {
    Normal,
    Stalled(&'a BTreeSet<AuthorityEntryHash>),
}

pub(super) fn evaluate_entry(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
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
    if matches!(entry.op, AuthorityOp::RevokeActor { .. }) {
        return stalled_actor_revoke(entry, hash, entries, states, pending, rejected, context)
            .map_or(EntryFold::Waiting, EntryFold::Ready);
    }
    revocation_bypass_states(entry, entries, states, pending, context)
        .and_then(
            |substitutes| match fold_entry_state(entry, hash, &substitutes, context) {
                EntryFold::Ready(state) => Some(state),
                EntryFold::Waiting | EntryFold::Invalid(_) => None,
            },
        )
        .map_or(EntryFold::Waiting, EntryFold::Ready)
}

/// Try a stalled actor revoke against explicitly rejected and/or frozen parents.
/// Normal folding passes an empty rejection set; signed-history verification
/// passes its own rejected ancestors. Both use the SAME frozen-parent bypass.
pub(super) fn stalled_actor_revoke(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    rejected: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<FoldState> {
    if !matches!(entry.op, AuthorityOp::RevokeActor { .. }) {
        return None;
    }
    let mut scratch = states.clone();
    if !rejected.is_empty() {
        for parent in &entry.parent_hashes {
            if rejected.contains(parent) && !scratch.contains_key(parent) {
                let state = skipped_parent_state(*parent, entries, &scratch, rejected)?;
                scratch.insert(*parent, state);
            }
        }
    }
    match fold_entry_state(entry, hash, &scratch, context) {
        EntryFold::Ready(state) => return Some(state),
        EntryFold::Invalid(_) => return None,
        EntryFold::Waiting => {}
    }
    let bypass = revocation_bypass_states(entry, entries, &scratch, pending, context)?;
    match fold_entry_state(entry, hash, &bypass, context) {
        EntryFold::Ready(state) => Some(state),
        EntryFold::Invalid(_) | EntryFold::Waiting => None,
    }
}

/// Substitute only a branch of *rejected* entries. Every leaf must be a
/// genuinely folded same-vault ancestor; missing history, cycles, and unrelated
/// waiting ancestors refuse the proof. Skipped operations never run.
fn skipped_parent_state(
    start: AuthorityEntryHash,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    rejected: &BTreeSet<AuthorityEntryHash>,
) -> Option<FoldState> {
    let mut visited = BTreeSet::new();
    let mut frontier = vec![start];
    let mut merged: Option<FoldState> = None;
    let mut crossed_vaults = Vec::new();
    while let Some(hash) = frontier.pop() {
        if !visited.insert(hash) {
            continue;
        }
        if let Some(state) = states.get(&hash) {
            merged = Some(match merged {
                Some(current) if current.vault_id != state.vault_id => return None,
                Some(current) => merge_states(&current, state),
                None => state.clone(),
            });
            continue;
        }
        if !rejected.contains(&hash) {
            return None;
        }
        let entry = entries.get(&hash)?;
        if entry.parent_hashes.is_empty() {
            return None;
        }
        frontier.extend(entry.parent_hashes.iter().copied());
        crossed_vaults.push(entry.vault_id);
    }
    if crossed_vaults
        .iter()
        .any(|vault| *vault != merged.as_ref().map(|state| state.vault_id))
    {
        return None;
    }
    merged
}
