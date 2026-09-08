//! Post-quarantine winner re-checks, roster/consent predicates, and global fork resolution.
//!
//! MUST BE READ TOGETHER WITH [`super::super::entry_transition`]. The two files are
//! mutually recursive by direct call; any fork, quorum, or equivocation correctness
//! change has to be reasoned about across both files.

use std::collections::{BTreeMap, BTreeSet};

use super::super::*;
use super::ancestry_bypass::entry_is_validated_prefork_ancestor;

pub(super) fn fork_winner_post_quarantine_issue(
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

/// `prefork` carries the validated entry's own `(signer, seq)` when the
/// caller is judging that entry's participants. The forked signer's entries
/// at a chain position strictly before the fork seq are pre-fork by
/// construction (seq continuity is enforced against the folded parent
/// state), which matters when the fork candidates' ancestry is unresolvable
/// (missing parents) and the ancestor-based exemption cannot see them.
/// The exemption covers the entry SIGNER only: a cosign carries no chain
/// position, so cosigned entries need an ancestry proof or fail closed.
/// Scans without a concrete entry context pass `None` and stay fail-closed.
pub(crate) fn key_is_quarantined_for_entry(
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

pub(crate) fn resolve_global_forks_for_revoke(
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

pub(crate) fn resolve_global_forks_for_recovery_reboot(
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
