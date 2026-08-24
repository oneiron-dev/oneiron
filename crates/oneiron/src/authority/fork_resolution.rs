//! Equivocation and fork detection, ranking, quarantine, and restore markers.
//!
//! MUST BE READ TOGETHER WITH [`super::entry_transition`]. The two files are
//! mutually recursive by direct call — [`resolve_equivocation_group`] calls
//! [`super::entry_transition::fold_entry_state`], which calls back into the
//! quarantine and global-fork-resolution helpers here. Any fork, quorum, or
//! equivocation correctness change has to be reasoned about across both files;
//! the file boundary is a readability split, not a decoupling.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use super::*;

pub(super) fn reconcile_reported_authority_forks(
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

pub(super) fn build_fork_alarms(forks: &[AuthorityFork]) -> Vec<AuthorityForkAlarm> {
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

#[expect(
    clippy::large_enum_variant,
    reason = "transient per-entry fold value; one instance lives on the stack at a time"
)]
pub(super) enum EntryFold {
    Ready(FoldState),
    Waiting,
    Invalid(AuthorityFoldIssue),
}

#[expect(
    clippy::large_enum_variant,
    reason = "transient per-group resolution value; one instance lives on the stack at a time"
)]
pub(super) enum EquivocationResolution {
    Resolved {
        winner: Option<(AuthorityEntryHash, Box<FoldState>)>,
        fork: Option<AuthorityFork>,
        fork_vault_ids: BTreeSet<AuthorityVaultId>,
        issues: Vec<AuthorityFoldIssue>,
    },
    Waiting,
}

pub(super) fn resolve_equivocation_group(
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

fn fork_winner_post_quarantine_issue(
    state: &FoldState,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
    forked_key: &AuthorityKey,
) -> Option<AuthorityFoldIssue> {
    match &entry.op {
        AuthorityOp::RevokeDevice { .. } => {
            if active_roster_count_after_fork_quarantine(state, entry, context, hash, forked_key)
                < 2
            {
                return Some(AuthorityFoldIssue::MissingQuorum(hash));
            }
            if !state_has_authority_consent_after_fork_quarantine(
                state, entry, context, hash, forked_key,
            ) {
                return Some(AuthorityFoldIssue::MissingAuthorityConsent(hash));
            }
        }
        AuthorityOp::RecoveryReboot { .. } if entry_participants_include_key(entry, forked_key) => {
            let Some(parent_state) = folded_parent_state_for_entry(entry, states) else {
                return Some(AuthorityFoldIssue::MissingQuorum(hash));
            };
            let independent_participants = participants_without_key(entry, forked_key);
            if independent_participants.len() < 2
                || active_roster_count_after_fork_quarantine(
                    &parent_state,
                    entry,
                    context,
                    hash,
                    forked_key,
                ) < 2
            {
                return Some(AuthorityFoldIssue::MissingQuorum(hash));
            }
            if !has_authority_consent(&parent_state, &independent_participants, context) {
                return Some(AuthorityFoldIssue::MissingAuthorityConsent(hash));
            }
        }
        // Binding ops MINT or MOVE actor identity, and a fork winner's signer
        // is by construction the forked key — precisely the signature an
        // attacker holds. fix-1 already kills a binding whose BOUND key is
        // quarantined; that leaves the sibling hole this arm closes, where the
        // quarantined key spends its last pre-quarantine act binding owner
        // class onto a DIFFERENT, clean, owner-capable roster key. Nothing
        // downstream can see that: `folded_actor_bindings` judges the bound
        // key, which is spotless.
        //
        // The re-derivation demands NOTHING new — it is the entry's own two
        // admission rules (`has_authority_consent` over its participants, and
        // the peer-cosign quorum rule) run again with the forked key deleted
        // from both sides. A bind an untainted owner-capable cosigner
        // independently backs still stands; a bind whose only owner authority
        // WAS the forked key does not.
        AuthorityOp::BindActor { .. } | AuthorityOp::RebindActor { .. } => {
            let independent_participants = participants_without_key(entry, forked_key);
            if !has_authority_consent(state, &independent_participants, context) {
                return Some(AuthorityFoldIssue::MissingAuthorityConsent(hash));
            }
            if independent_participants.len() < 2
                && active_roster_count_after_fork_quarantine(state, entry, context, hash, forked_key)
                    >= 2
            {
                return Some(AuthorityFoldIssue::MissingQuorum(hash));
            }
        }
        AuthorityOp::Genesis { .. }
        | AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::SetCeiling { .. }
        | AuthorityOp::RotateKey { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::RecoveryReboot { .. }
        | AuthorityOp::FederationConfirm(_) | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        // RevokeActor only raises a revocation watermark: it strips authority
        // and can never mint it, so re-scrutinizing it could only resurrect a
        // binding the quarantined key wanted gone.
        | AuthorityOp::RevokeActor { .. } => {}
    }
    None
}

fn entry_participants_include_key(entry: &AuthorityLogEntry, key: &AuthorityKey) -> bool {
    std::iter::once(&entry.signer)
        .chain(entry.cosigns.iter())
        .any(|signature| signature.public_key == *key)
}

/// The entry's signer + cosigners with `key` deleted — the participant set a
/// post-quarantine re-check must judge the entry on.
fn participants_without_key(
    entry: &AuthorityLogEntry,
    key: &AuthorityKey,
) -> BTreeSet<AuthorityKey> {
    std::iter::once(&entry.signer)
        .chain(entry.cosigns.iter())
        .map(|signature| &signature.public_key)
        .filter(|participant| *participant != key)
        .cloned()
        .collect()
}

fn folded_parent_state_for_entry(
    entry: &AuthorityLogEntry,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> Option<FoldState> {
    let mut parent_state = None;
    for parent in &entry.parent_hashes {
        let state = states.get(parent)?;
        if parent_state
            .as_ref()
            .is_some_and(|current: &FoldState| current.vault_id != state.vault_id)
        {
            return None;
        }
        parent_state = Some(match parent_state {
            Some(current) => merge_states(&current, state),
            None => state.clone(),
        });
    }
    parent_state
}

fn active_roster_count_after_fork_quarantine(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
    forked_key: &AuthorityKey,
) -> usize {
    state
        .roster
        .iter()
        .filter(|(key, device)| {
            *key != forked_key
                && !device.revoked
                && device.roles != 0
                && !key_is_quarantined_for_entry(
                    state,
                    context,
                    key,
                    hash,
                    Some((entry.signer_key(), entry.seq)),
                )
        })
        .count()
}

fn state_has_authority_consent_after_fork_quarantine(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
    forked_key: &AuthorityKey,
) -> bool {
    state.roster.iter().any(|(key, device)| {
        key != forked_key
            && context.device_can_consent(device)
            && !key_is_quarantined_for_entry(
                state,
                context,
                key,
                hash,
                Some((entry.signer_key(), entry.seq)),
            )
    })
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

pub(super) fn resolve_global_forks_for_revoke(
    state: &mut FoldState,
    context: FoldContext<'_>,
    revoked_key: &AuthorityKey,
) {
    for (key, fork) in context.authority_forks {
        if &key.0 == revoked_key
            && context
                .authority_fork_vault_ids
                .get(key)
                .is_some_and(|vault_ids| {
                    vault_ids.is_empty() || vault_ids.contains(&state.vault_id)
                })
        {
            state
                .authority_forks
                .entry(key.clone())
                .and_modify(|existing| existing.status = AuthorityForkStatus::Resolved)
                .or_insert_with(|| AuthorityFork {
                    status: AuthorityForkStatus::Resolved,
                    ..fork.clone()
                });
        }
    }
}

pub(super) fn resolve_global_forks_for_recovery_reboot(
    state: &mut FoldState,
    context: FoldContext<'_>,
) {
    for (key, fork) in context.authority_forks {
        if context
            .authority_fork_vault_ids
            .get(key)
            .is_some_and(|vault_ids| vault_ids.is_empty() || vault_ids.contains(&state.vault_id))
            && state.fork_resolution_revocations.contains(&fork.signer)
        {
            state
                .authority_forks
                .entry(key.clone())
                .and_modify(|existing| existing.status = AuthorityForkStatus::Resolved)
                .or_insert_with(|| AuthorityFork {
                    status: AuthorityForkStatus::Resolved,
                    ..fork.clone()
                });
        }
    }
}

/// `prefork` carries the validated entry's own `(signer, seq)` when the
/// caller is judging that entry's participants. The forked signer's entries
/// at a chain position strictly before the fork seq are pre-fork by
/// construction (seq continuity is enforced against the folded parent
/// state), which matters when the fork candidates' ancestry is unresolvable
/// (missing parents) and the ancestor-based exemption cannot see them.
/// The exemption covers the entry SIGNER only: a cosign carries no chain
/// position, so cosigned entries need an ancestry proof or fail closed.
/// Scans without a concrete entry context pass `None` and stay fail-closed.
pub(super) fn key_is_quarantined_for_entry(
    state: &FoldState,
    context: FoldContext<'_>,
    key: &AuthorityKey,
    entry_hash: AuthorityEntryHash,
    prefork: Option<(&AuthorityKey, u64)>,
) -> bool {
    state
        .authority_forks
        .values()
        .any(|fork| fork_quarantines_key_for_entry(state, context, fork, key, entry_hash, prefork))
        || context.authority_forks.iter().any(|(fork_key, fork)| {
            context
                .authority_fork_vault_ids
                .get(fork_key)
                .is_some_and(|vault_ids| {
                    vault_ids.is_empty() || vault_ids.contains(&state.vault_id)
                })
                && fork_quarantines_key_for_entry(state, context, fork, key, entry_hash, prefork)
        })
}

fn fork_quarantines_key_for_entry(
    state: &FoldState,
    context: FoldContext<'_>,
    fork: &AuthorityFork,
    key: &AuthorityKey,
    entry_hash: AuthorityEntryHash,
    prefork: Option<(&AuthorityKey, u64)>,
) -> bool {
    let signer_at_or_after_fork =
        prefork.is_some_and(|(signer, entry_seq)| signer == key && entry_seq >= fork.seq);
    fork.signer == *key
        && fork.status == AuthorityForkStatus::Quarantined
        && !fork_resolved_in_state(state, key, fork.seq)
        // A fork candidate itself must remain evaluable. For every other
        // entry signed by the forked key, its own chain position is decisive:
        // seq >= fork.seq is post-fork and may not use any ancestry claim as
        // a prefork exemption.
        && !entry_is_fork_candidate(context, key, fork.seq, entry_hash)
        && (signer_at_or_after_fork
            || !entry_is_validated_prefork_ancestor(context, key, fork.seq, entry_hash))
        // Only the entry signer's own seq orders the entry against the fork
        // point (seq continuity: a second entry at the same seq would form
        // its own equivocation group). A cosign carries no chain position —
        // a folded-state seq below the fork proves only that the cosigner's
        // SIGNING chain stalled prefork, not that the cosign happened
        // prefork, and a quarantined key could keep cosigning new entries
        // forever without ever advancing it. Cosigned entries are therefore
        // exempt only via chain-validated ancestry proof above; without one
        // they fail closed.
        && !prefork.is_some_and(|(signer, seq)| signer == key && seq < fork.seq)
}

fn fork_resolved_in_state(state: &FoldState, key: &AuthorityKey, seq: u64) -> bool {
    state
        .authority_forks
        .get(&(key.clone(), seq))
        .is_some_and(|fork| fork.status == AuthorityForkStatus::Resolved)
}

fn entry_is_fork_candidate(
    context: FoldContext<'_>,
    key: &AuthorityKey,
    seq: u64,
    entry_hash: AuthorityEntryHash,
) -> bool {
    let lookup = (key.clone(), seq);
    context
        .equivocation_groups
        .get(&lookup)
        .is_some_and(|group| group.contains(&entry_hash))
}

fn entry_is_validated_prefork_ancestor(
    context: FoldContext<'_>,
    key: &AuthorityKey,
    seq: u64,
    entry_hash: AuthorityEntryHash,
) -> bool {
    let lookup = (key.clone(), seq);
    let Some(group) = context.equivocation_groups.get(&lookup) else {
        return false;
    };
    let Some(ancestors) = context.entry_ancestors else {
        return false;
    };
    let Some(chain_validated_candidates) = context.chain_validated_fork_candidates else {
        return false;
    };
    group.iter().any(|fork_hash| {
        chain_validated_candidates.contains(fork_hash)
            && ancestors
                .get(fork_hash)
                .is_some_and(|fork_ancestors| fork_ancestors.contains(&entry_hash))
    })
}

fn entry_is_claimed_prefork_or_fork_candidate(
    context: FoldContext<'_>,
    key: &AuthorityKey,
    seq: u64,
    entry_hash: AuthorityEntryHash,
) -> bool {
    let lookup = (key.clone(), seq);
    let Some(group) = context.equivocation_groups.get(&lookup) else {
        return false;
    };
    if group.contains(&entry_hash) {
        return true;
    }
    let Some(ancestors) = context.entry_ancestors else {
        return false;
    };
    group.iter().any(|fork_hash| {
        ancestors
            .get(fork_hash)
            .is_some_and(|fork_ancestors| fork_ancestors.contains(&entry_hash))
    })
}

pub(super) fn entry_waits_on_unresolved_equivocation(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    let signer = entry.signer_key();
    context
        .unresolved_equivocation_groups
        .iter()
        .any(|(fork_key, fork_seq)| {
            // Raw claimed ancestry is sufficient only for scheduling: a
            // candidate must not make the parent it claims wait on that same
            // candidate. Quarantine exemptions use chain-validated ancestry.
            if entry_is_claimed_prefork_or_fork_candidate(context, fork_key, *fork_seq, hash) {
                return false;
            }
            (fork_key == signer && *fork_seq < entry.seq)
                || entry
                    .cosigns
                    .iter()
                    .any(|signature| signature.public_key == *fork_key)
                || matches!(&entry.op, AuthorityOp::RevokeDevice { revoked_key } if revoked_key == fork_key)
                || (*fork_seq < entry.seq
                    && recovery_reboot_is_entangled_with_fork(entry, fork_key))
        })
}

fn recovery_reboot_is_entangled_with_fork(
    entry: &AuthorityLogEntry,
    fork_key: &AuthorityKey,
) -> bool {
    if !matches!(&entry.op, AuthorityOp::RecoveryReboot { .. }) {
        return false;
    }
    // Resolve earlier groups involving a reboot participant first so
    // quarantined authority cannot authorize recovery. Unrelated groups and
    // later groups do not affect this candidate's current admissibility.
    std::iter::once(&entry.signer)
        .chain(entry.cosigns.iter())
        .any(|signature| signature.public_key == *fork_key)
}

fn entry_waits_on_pending_parent_outside_group(
    entry: &AuthorityLogEntry,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    group: &BTreeSet<AuthorityEntryHash>,
) -> bool {
    entry.parent_hashes.iter().any(|parent| {
        !states.contains_key(parent) && pending.contains(parent) && !group.contains(parent)
    })
}

/// Substitute parent states that let a stalled `RevokeActor` fold against its
/// nearest READY ancestry, or `None` when the bypass does not apply.
///
/// THE HOLE THIS CLOSES. `op_applies_despite_pending_widen` exempts a
/// revocation from the pending-widen freeze, but that exemption is tested
/// AFTER `fold_entry_state` has resolved parents, and an unresolved parent
/// returns `Waiting` first. So a compromised key stalls its own revocation by
/// parenting it on a grant the key itself filed under an unrelated pending
/// widen: the grant defers (correctly — grants must freeze), and the child
/// revocation inherits the wait for the whole veto window. The withdrawal of
/// consent is exactly the operation that must not be delayable by its target.
///
/// WHY IT IS SAFE. Substituting an ancestry state that predates the frozen
/// parent cannot manufacture authority for the revocation:
///
/// * `RevokeActor` is authority-REMOVING only. Applying it raises
///   `actor_binding_revocations[key]` to at least `epoch` and touches nothing
///   else, so the worst a stale base state can do is withhold the revocation's
///   effect — the pre-fix behavior — never widen anything.
/// * The watermark merges by MAX, so once the frozen parent does fold the
///   revocation stays in force: no ordering can lower a raised watermark.
/// * The substituted states are real folded states of real ancestors, so every
///   other gate the entry passes through (signature, vault, roster, consent,
///   quorum, seq) still runs against genuinely folded authority.
///
/// WHY IT STAYS ONE OP WIDE, AND ONE CAUSE DEEP. Two independent narrowings,
/// because the bypass is the only place a fold walks past an unfolded entry:
///
/// * Only `RevokeActor` may USE it. A grant folded against a pre-widen roster
///   is precisely what the freeze exists to prevent, so `BindActor` and
///   `RebindActor` keep waiting.
/// * Only a parent FROZEN BY THE WIDEN may be stepped over — see
///   [`entry_is_frozen_by_pending_widen`]. A parent that is waiting for any
///   other reason, was ruled `Invalid`, or is simply absent from the log
///   refuses the whole bypass, so a revocation can never be folded over
///   ancestry this vault has not validated. The skipped parent is stepped over,
///   never applied.
///
/// The walk is bounded by the ancestry it traverses and introduces no clock
/// dependency: a revocation is not time-based, and this decides nothing about
/// when any pending widen matures.
///
/// KNOWN DURABILITY RESIDUAL. A revocation rescued by this bypass survives the
/// widen merely maturing
/// (`revocation_folded_past_a_freeze_survives_the_widen_maturing`), but NOT the
/// skipped grant later becoming retroactively invalid through the matured
/// state — that durability is a GATE-2 packet item, not an in-lane fix. Closing
/// it needs a representation in which an accepted revocation's effect outlives
/// ancestry invalidation of the entries above it (a journal, or per-hash bypass
/// state), which is a design surface rather than a change to this function.
pub(super) fn revocation_bypass_states(
    entry: &AuthorityLogEntry,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    pending: &BTreeSet<AuthorityEntryHash>,
    context: FoldContext<'_>,
) -> Option<BTreeMap<AuthorityEntryHash, FoldState>> {
    if !matches!(entry.op, AuthorityOp::RevokeActor { .. }) {
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
    // (equivocation, seq, consent); leave every other path exactly as it was.
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
        if !pending.contains(&hash)
            || entry.parent_hashes.is_empty()
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
fn entry_is_frozen_by_pending_widen(
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

pub(super) fn entry_ancestor_index(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>> {
    let mut index = BTreeMap::new();
    for hash in by_hash.keys().copied() {
        let mut ancestors = BTreeSet::new();
        let mut stack = by_hash[&hash].parent_hashes.clone();
        while let Some(parent) = stack.pop() {
            if !ancestors.insert(parent) {
                continue;
            }
            if let Some(parent_entry) = by_hash.get(&parent) {
                stack.extend(parent_entry.parent_hashes.iter().copied());
            }
        }
        index.insert(hash, ancestors);
    }
    index
}

pub(super) fn restore_prefix_divergence(
    group: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> bool {
    if group.len() != 2 {
        return false;
    }
    let mut hashes = group.iter().copied();
    let left = hashes.next().expect("len checked");
    let right = hashes.next().expect("len checked");
    let Some(left_ancestors) = ancestors.get(&left) else {
        return false;
    };
    let Some(right_ancestors) = ancestors.get(&right) else {
        return false;
    };
    if left_ancestors.is_subset(right_ancestors) && left_ancestors != right_ancestors {
        return branch_divergent_suffix_has_restore_marker(
            right,
            left_ancestors,
            by_hash,
            ancestors,
            context,
        );
    }
    if right_ancestors.is_subset(left_ancestors) && right_ancestors != left_ancestors {
        return branch_divergent_suffix_has_restore_marker(
            left,
            right_ancestors,
            by_hash,
            ancestors,
            context,
        );
    }
    false
}

fn branch_divergent_suffix_has_restore_marker(
    longer_hash: AuthorityEntryHash,
    shorter_ancestors: &BTreeSet<AuthorityEntryHash>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> bool {
    restore_marker_is_fold_admissible(longer_hash, by_hash, ancestors, context)
        || ancestors.get(&longer_hash).is_some_and(|branch_ancestors| {
            branch_ancestors
                .iter()
                .filter(|ancestor| !shorter_ancestors.contains(*ancestor))
                .any(|ancestor| {
                    restore_marker_is_fold_admissible(*ancestor, by_hash, ancestors, context)
                })
        })
}

fn restore_marker_is_fold_admissible(
    hash: AuthorityEntryHash,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
) -> bool {
    let Some(entry) = by_hash.get(&hash) else {
        return false;
    };
    if !matches!(entry.op, AuthorityOp::RecoveryReboot { .. }) {
        return false;
    }
    entry_folds_on_available_ancestry(hash, by_hash, ancestors, context)
}

/// Chain-validation probe: re-folds `target_hash` over its own complete
/// ancestry with fork state deliberately cleared.
///
/// It inherits exactly TWO things from the enclosing fold — the consent arm and
/// the admitted peer consent roots — because those define what "folds" MEANS.
/// A probe answering under different consent semantics than the fold it serves
/// would quietly disagree with it about which fork candidates are chain-valid.
pub(super) fn entry_folds_on_available_ancestry(
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
    let authority_forks = BTreeMap::new();
    let authority_fork_vault_ids = BTreeMap::new();
    let equivocation_groups = BTreeMap::new();
    let unresolved_equivocation_groups = BTreeSet::new();
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
                    authority_forks: &authority_forks,
                    authority_fork_vault_ids: &authority_fork_vault_ids,
                    equivocation_groups: &equivocation_groups,
                    unresolved_equivocation_groups: &unresolved_equivocation_groups,
                    entry_ancestors: Some(ancestors),
                    chain_validated_fork_candidates: None,
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

fn equivocation_rank_state(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    state: &FoldState,
) -> FoldState {
    let mut rank_state = state.clone();
    if rank_state.pending_widens.contains_key(&hash) {
        rank_state.pending_widens.remove(&hash);
        apply_op(&mut rank_state, &entry.op, hash, true, entry.signer_key());
    }
    rank_state
}

fn compare_fork_rank(
    (left_hash, _, left_rank): &(AuthorityEntryHash, FoldState, FoldState),
    (right_hash, _, right_rank): &(AuthorityEntryHash, FoldState, FoldState),
) -> Ordering {
    fork_rank(left_rank, *left_hash).cmp(&fork_rank(right_rank, *right_hash))
}

fn fork_rank(
    state: &FoldState,
    terminal_hash: AuthorityEntryHash,
) -> (usize, u32, u8, AuthorityEntryHash) {
    let mut active_devices = 0;
    let mut active_role_bits = 0;
    for device in state.roster.values() {
        if !device.revoked && device.roles != 0 {
            active_devices += 1;
            active_role_bits += device.roles.count_ones();
        }
    }
    let tier_floor = match state.tier_floor {
        AuthorityTier::CloudCustodial => 0,
        AuthorityTier::Hardware => 1,
        AuthorityTier::Software => 2,
    };
    (active_devices, active_role_bits, tier_floor, terminal_hash)
}
