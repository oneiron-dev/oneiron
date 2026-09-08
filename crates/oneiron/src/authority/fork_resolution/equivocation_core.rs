//! Equivocation group resolution driver, resolution types, and fork record/report helpers.
//!
//! MUST BE READ TOGETHER WITH [`super::super::entry_transition`]. The two files are
//! mutually recursive by direct call; any fork, quorum, or equivocation correctness
//! change has to be reasoned about across both files.

use std::collections::{BTreeMap, BTreeSet};

use super::super::*;
use super::ancestry_bypass::entry_waits_on_pending_parent_outside_group;
use super::quarantine_gate::fork_winner_post_quarantine_issue;
use super::restore_rank::{compare_fork_rank, equivocation_rank_state};

#[expect(
    clippy::large_enum_variant,
    reason = "transient per-group resolution value; one instance lives on the stack at a time"
)]
pub(crate) enum EquivocationResolution {
    Resolved {
        winner: Option<(AuthorityEntryHash, Box<FoldState>)>,
        fork: Option<AuthorityFork>,
        fork_vault_ids: BTreeSet<AuthorityVaultId>,
        issues: Vec<AuthorityFoldIssue>,
    },
    Waiting,
}

#[expect(
    clippy::large_enum_variant,
    reason = "transient per-entry fold value; one instance lives on the stack at a time"
)]
pub(crate) enum EntryFold {
    Ready(FoldState),
    Waiting,
    Invalid(AuthorityFoldIssue),
}

pub(crate) fn resolve_equivocation_group(
    group_key: &(AuthorityKey, u64),
    group: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> EquivocationResolution {
    let mut ready = Vec::<(AuthorityEntryHash, FoldState, FoldState)>::new();
    let mut invalid_candidates = Vec::new();
    let mut issues = Vec::new();
    for hash in group {
        let entry = &by_hash[hash];
        match fold_entry_state(entry, *hash, states, context) {
            EntryFold::Ready(state) => {
                let rank_state = equivocation_rank_state(entry, *hash, &state);
                ready.push((*hash, state, rank_state));
            }
            EntryFold::Invalid(issue) => {
                invalid_candidates.push(*hash);
                issues.push(issue);
            }
            EntryFold::Waiting
                if entry_waits_on_pending_parent_outside_group(entry, states, pending, group) =>
            {
                return EquivocationResolution::Waiting;
            }
            EntryFold::Waiting if entry_waits_on_unresolved_equivocation(entry, *hash, context) => {
                return EquivocationResolution::Waiting;
            }
            EntryFold::Waiting => {
                invalid_candidates.push(*hash);
                issues.push(AuthorityFoldIssue::InvalidAncestry(*hash));
            }
        }
    }

    if ready.is_empty() {
        let mut fork = authority_fork_from_group(&group_key.0, group_key.1, group);
        if fork_group_signer_has_resolution_revocation_in_folded_ancestry(
            &group_key.0,
            group,
            by_hash,
            states,
        ) && let Some(fork) = &mut fork
        {
            fork.status = AuthorityForkStatus::Resolved;
        }
        return EquivocationResolution::Resolved {
            winner: None,
            fork,
            fork_vault_ids: authority_fork_vault_ids_from_group(group, by_hash, states, None),
            issues,
        };
    }

    ready.sort_by(compare_fork_rank);
    let mut ready = ready.into_iter();
    let mut winner = None;
    let mut rejected_candidates = Vec::new();
    for (candidate_hash, mut candidate_state, _) in ready.by_ref() {
        record_authority_fork(&mut candidate_state, &group_key.0, group_key.1, group);
        if matches!(
            &by_hash[&candidate_hash].op,
            AuthorityOp::RevokeDevice { revoked_key } if revoked_key == &group_key.0
        ) {
            resolve_recorded_authority_fork(&mut candidate_state, &group_key.0, group_key.1);
        }
        if let Some(issue) = fork_winner_post_quarantine_issue(
            &candidate_state,
            states,
            context,
            candidate_hash,
            &by_hash[&candidate_hash],
            &group_key.0,
        ) {
            issues.push(issue);
            rejected_candidates.push(candidate_hash);
            continue;
        }
        winner = Some((candidate_hash, Box::new(candidate_state)));
        break;
    }
    if let Some((winner_hash, _)) = &winner {
        for loser in rejected_candidates
            .into_iter()
            .chain(invalid_candidates)
            .chain(ready.map(|(loser, _, _)| loser))
        {
            issues.push(AuthorityFoldIssue::EquivocationLoser {
                entry: loser,
                signer: group_key.0.clone(),
                seq: group_key.1,
                winner: *winner_hash,
            });
        }
    }
    let fork = winner
        .as_ref()
        .and_then(|(_, state)| state.authority_forks.get(group_key).cloned())
        .or_else(|| authority_fork_from_group(&group_key.0, group_key.1, group));
    let fork_vault_ids = authority_fork_vault_ids_from_group(
        group,
        by_hash,
        states,
        winner.as_ref().map(|(_, state)| state.as_ref()),
    );
    EquivocationResolution::Resolved {
        winner,
        fork,
        fork_vault_ids,
        issues,
    }
}

pub(crate) fn reconcile_reported_authority_forks(
    reported: &mut BTreeMap<(AuthorityKey, u64), AuthorityFork>,
    authority_fork_vault_ids: &BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>,
    resolved_vault_ids: &mut BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>,
    state: &FoldState,
) {
    for (key, fork) in reported.iter() {
        let applies_to_state = authority_fork_vault_ids
            .get(key)
            .is_some_and(|vault_ids| vault_ids.is_empty() || vault_ids.contains(&state.vault_id));
        let state_records_resolution = state
            .authority_forks
            .get(key)
            .is_some_and(|state_fork| state_fork.status == AuthorityForkStatus::Resolved);
        if applies_to_state
            && (state.fork_resolution_revocations.contains(&fork.signer)
                || state_records_resolution)
        {
            resolved_vault_ids
                .entry(key.clone())
                .or_default()
                .insert(state.vault_id);
        }
    }
    for (key, fork) in &state.authority_forks {
        if !authority_fork_vault_ids
            .get(key)
            .is_some_and(|vault_ids| vault_ids.is_empty() || vault_ids.contains(&state.vault_id))
        {
            continue;
        }
        if fork.status == AuthorityForkStatus::Resolved {
            resolved_vault_ids
                .entry(key.clone())
                .or_default()
                .insert(state.vault_id);
        }
        reported
            .entry(key.clone())
            .or_insert_with(|| AuthorityFork {
                status: AuthorityForkStatus::Quarantined,
                ..fork.clone()
            });
    }
    for (key, fork) in reported.iter_mut() {
        // A non-empty scope is resolved only after every named vault has a
        // real RevokeDevice/RecoveryReboot resolution in that vault. Empty
        // scope means universal: a local real revocation lifts only that
        // state's gate, while the global alarm remains quarantined because no
        // finite set of vaults can prove universal resolution.
        fork.status = if authority_fork_vault_ids.get(key).is_some_and(|vault_ids| {
            !vault_ids.is_empty()
                && resolved_vault_ids
                    .get(key)
                    .is_some_and(|resolved| vault_ids.is_subset(resolved))
        }) {
            AuthorityForkStatus::Resolved
        } else {
            AuthorityForkStatus::Quarantined
        };
    }
}

pub(crate) fn build_fork_alarms(forks: &[AuthorityFork]) -> Vec<AuthorityForkAlarm> {
    forks
        .iter()
        .map(|fork| AuthorityForkAlarm {
            signer: fork.signer.clone(),
            seq: fork.seq,
            first_hash: fork.first_hash,
            second_hash: fork.second_hash,
        })
        .collect()
}

fn record_authority_fork(
    state: &mut FoldState,
    signer: &AuthorityKey,
    seq: u64,
    group: &BTreeSet<AuthorityEntryHash>,
) {
    let Some(fork) = authority_fork_from_group(signer, seq, group) else {
        return;
    };
    state.authority_forks.insert((signer.clone(), seq), fork);
}

fn resolve_recorded_authority_fork(state: &mut FoldState, signer: &AuthorityKey, seq: u64) {
    if let Some(fork) = state.authority_forks.get_mut(&(signer.clone(), seq)) {
        fork.status = AuthorityForkStatus::Resolved;
    }
}

fn authority_fork_from_group(
    signer: &AuthorityKey,
    seq: u64,
    group: &BTreeSet<AuthorityEntryHash>,
) -> Option<AuthorityFork> {
    let first_hash = group.iter().next().copied()?;
    let second_hash = group.iter().next_back().copied()?;
    if first_hash == second_hash {
        return None;
    };
    let forked = AuthorityFork {
        signer: signer.clone(),
        seq,
        first_hash,
        second_hash,
        status: AuthorityForkStatus::Forked,
    };
    Some(AuthorityFork {
        status: AuthorityForkStatus::Quarantined,
        ..forked
    })
}

fn authority_fork_vault_ids_from_group(
    group: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    winner: Option<&FoldState>,
) -> BTreeSet<AuthorityVaultId> {
    // Fail closed across every plausible attack scope. Folded parent vaults
    // identify logs the candidates tried to extend, while claimed ids cover
    // missing-parent groups; a winner's vault covers entries without a claim.
    let mut vault_ids: BTreeSet<_> = group
        .iter()
        .filter_map(|hash| by_hash.get(hash))
        .flat_map(|entry| entry.parent_hashes.iter())
        .filter_map(|parent| states.get(parent).map(|state| state.vault_id))
        .collect();
    vault_ids.extend(
        group
            .iter()
            .filter_map(|hash| by_hash.get(hash).and_then(|entry| entry.vault_id)),
    );
    if let Some(winner) = winner {
        vault_ids.insert(winner.vault_id);
    }
    vault_ids
}

fn fork_group_signer_has_resolution_revocation_in_folded_ancestry(
    signer: &AuthorityKey,
    group: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> bool {
    group.iter().all(|hash| {
        let entry = &by_hash[hash];
        let mut parent_states = entry.parent_hashes.iter().map(|parent| states.get(parent));
        let Some(Some(first_parent)) = parent_states.next() else {
            return false;
        };
        let vault_id = first_parent.vault_id;
        let mut signer_has_resolution_revocation =
            first_parent.fork_resolution_revocations.contains(signer);
        for parent_state in parent_states {
            let Some(parent_state) = parent_state else {
                return false;
            };
            if parent_state.vault_id != vault_id {
                return false;
            }
            signer_has_resolution_revocation |=
                parent_state.fork_resolution_revocations.contains(signer);
        }
        signer_has_resolution_revocation
    })
}
