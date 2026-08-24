//! Top-level fold orchestration.
//!
//! `FoldContext` plus the topological entry-by-entry driver and its local,
//! peer, and seen-time variants. Fork handling and per-entry state transitions
//! are called as black boxes from [`super::fork_resolution`] and
//! [`super::entry_transition`].

use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[derive(Clone, Copy)]
pub(super) struct FoldContext<'a> {
    pub(super) first_seen_at_secs: &'a BTreeMap<AuthorityEntryHash, u64>,
    pub(super) now_secs: Option<u64>,
    pub(super) enforce_seen_time_delay: bool,
    pub(super) vetoed_widens: &'a BTreeSet<AuthorityEntryHash>,
    pub(super) authority_forks: &'a BTreeMap<(AuthorityKey, u64), AuthorityFork>,
    pub(super) authority_fork_vault_ids:
        &'a BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>,
    pub(super) equivocation_groups: &'a BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityEntryHash>>,
    pub(super) unresolved_equivocation_groups: &'a BTreeSet<(AuthorityKey, u64)>,
    pub(super) entry_ancestors:
        Option<&'a BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>>,
    pub(super) chain_validated_fork_candidates: Option<&'a BTreeSet<AuthorityEntryHash>>,
    /// Consent roots of every ADMITTED PEER roster, keyed by peer vault id.
    ///
    /// EVIDENCE for FED-01 gesture acceptance, never a local consent
    /// constituency: nothing in this map can admit a local entry, hold local
    /// quorum, or enter the local roster. EMPTY on every fold path that has not
    /// been handed admitted peer logs — including the peer-side fold itself,
    /// which has no peers of its own.
    pub(super) peer_consent_roots: &'a BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    /// Which consent predicate this fold run admits entries under.
    ///
    /// [`folded_device_can_authority_consent`] on every LOCAL path;
    /// [`folded_peer_device_is_consent_root`] only inside
    /// [`fold_peer_authority_log`].
    pub(super) consent_arm: fn(&FoldedDevice) -> bool,
}

impl FoldContext<'_> {
    pub(super) fn device_can_consent(self, device: &FoldedDevice) -> bool {
        (self.consent_arm)(device)
    }
}

/// Folds a set of authority entries into a deterministic roster.
///
/// Entries missing local first-seen timestamps remain pending; callers with
/// local seen-time data should use [`fold_authority_log_with_seen_times`].
pub fn fold_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_inner(
        entries,
        &first_seen_at_secs,
        Some(0),
        true,
        &peer_consent_roots,
        folded_device_can_authority_consent,
    )
}

#[cfg(test)]
pub(super) fn fold_authority_log_without_seen_time_delay(
    entries: &[AuthorityLogEntry],
) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_inner(
        entries,
        &first_seen_at_secs,
        None,
        false,
        &peer_consent_roots,
        folded_device_can_authority_consent,
    )
}

/// Folds authority entries using local first-seen timestamps for delayed widens.
///
/// `first_seen_at_secs` is keyed by authority entry hash and must be sourced
/// from the local device's monotonic first-observation time. Entries missing a
/// timestamp remain pending until the caller can provide one.
pub fn fold_authority_log_with_seen_times(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
) -> AuthorityFold {
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_with_peer_consent_roots(
        entries,
        first_seen_at_secs,
        now_secs,
        &peer_consent_roots,
    )
}

/// [`fold_authority_log_with_seen_times`] with the consent roots of every
/// admitted peer roster in scope for FED-01 gesture acceptance.
///
/// The local fold is otherwise IDENTICAL — same consent arm, same roster, same
/// vault id. `peer_consent_roots` only widens which peer signature a lifecycle
/// gesture may carry, and only for the peer vault the gesture already names.
pub(crate) fn fold_authority_log_with_peer_consent_roots(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
) -> AuthorityFold {
    fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        true,
        peer_consent_roots,
        folded_device_can_authority_consent,
    )
}

/// Peer-side roster fold: same fold machinery, same transcript domain, two
/// swaps.
///
/// The consent arm becomes the unfiltered host-root predicate
/// (`folded_peer_device_is_consent_root`), and there are no seen-times: a
/// peer's widen is not a LOCAL observation, so it can never force a local
/// pending state. Peer entries carry no local first-observation time and stay
/// inside the peer fold's own epoch semantics.
///
/// The output is evidence, not authority: it never enters the local roster.
#[must_use]
pub fn fold_peer_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    let first_seen_at_secs = BTreeMap::new();
    let peer_consent_roots = BTreeMap::new();
    fold_authority_log_inner(
        entries,
        &first_seen_at_secs,
        None,
        false,
        &peer_consent_roots,
        folded_peer_device_is_consent_root,
    )
}

fn fold_authority_log_inner(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    enforce_seen_time_delay: bool,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    consent_arm: fn(&FoldedDevice) -> bool,
) -> AuthorityFold {
    let mut vetoed_widens = BTreeSet::new();
    let mut authority_forks = BTreeMap::new();
    let mut authority_fork_vault_ids = BTreeMap::new();
    let empty_equivocation_groups = BTreeMap::new();
    let empty_unresolved_equivocation_groups = BTreeSet::new();
    let (mut fold, mut folded_authority_fork_vault_ids) = fold_authority_log_once(
        entries,
        FoldContext {
            first_seen_at_secs,
            now_secs,
            enforce_seen_time_delay,
            vetoed_widens: &vetoed_widens,
            authority_forks: &authority_forks,
            authority_fork_vault_ids: &authority_fork_vault_ids,
            equivocation_groups: &empty_equivocation_groups,
            unresolved_equivocation_groups: &empty_unresolved_equivocation_groups,
            entry_ancestors: None,
            chain_validated_fork_candidates: None,
            peer_consent_roots,
            consent_arm,
        },
    );
    for _ in 0..=entries.len() {
        // Every fork discovered by the pass becomes quarantined input to the
        // next pass, even when a later sibling resolved its reported row. The
        // seeded quarantine is positional: entries outside the resolver's
        // ancestry are re-checked without the forked key, while folding the
        // resolver lifts the quarantine only for its descendants. Scope sets
        // keep this safe when the same fork spans conflicting vault roots.
        let mut next_authority_forks = BTreeMap::new();
        let mut next_authority_fork_vault_ids = BTreeMap::new();
        for fork in &fold.authority_forks {
            let key = (fork.signer.clone(), fork.seq);
            if let Some(fork_vault_ids) = folded_authority_fork_vault_ids.get(&key) {
                let mut quarantined = fork.clone();
                quarantined.status = AuthorityForkStatus::Quarantined;
                next_authority_forks.insert(key.clone(), quarantined);
                next_authority_fork_vault_ids.insert(key, fork_vault_ids.clone());
            }
        }
        if fold.vetoed_widens == vetoed_widens
            && next_authority_forks == authority_forks
            && next_authority_fork_vault_ids == authority_fork_vault_ids
        {
            return fold;
        }
        vetoed_widens = fold.vetoed_widens.clone();
        authority_forks = next_authority_forks;
        authority_fork_vault_ids = next_authority_fork_vault_ids;
        (fold, folded_authority_fork_vault_ids) = fold_authority_log_once(
            entries,
            FoldContext {
                first_seen_at_secs,
                now_secs,
                enforce_seen_time_delay,
                vetoed_widens: &vetoed_widens,
                authority_forks: &authority_forks,
                authority_fork_vault_ids: &authority_fork_vault_ids,
                equivocation_groups: &empty_equivocation_groups,
                unresolved_equivocation_groups: &empty_unresolved_equivocation_groups,
                entry_ancestors: None,
                chain_validated_fork_candidates: None,
                peer_consent_roots,
                consent_arm,
            },
        );
    }
    fold
}

fn fold_authority_log_once(
    entries: &[AuthorityLogEntry],
    context: FoldContext<'_>,
) -> (
    AuthorityFold,
    BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>,
) {
    let mut by_hash = BTreeMap::<AuthorityEntryHash, AuthorityLogEntry>::new();
    let mut issues = Vec::new();
    let mut by_signer_seq = BTreeMap::<(AuthorityKey, u64), BTreeSet<AuthorityEntryHash>>::new();
    for entry in entries {
        match authority_entry_hash(entry) {
            Ok(hash) if verify_entry_signatures(entry).is_ok() => {
                by_hash.entry(hash).or_insert_with(|| entry.clone());
                by_signer_seq
                    .entry((entry.signer_key().clone(), entry.seq))
                    .or_default()
                    .insert(hash);
            }
            Ok(hash) => issues.push(AuthorityFoldIssue::InvalidEntry(hash)),
            Err(_) => issues.push(AuthorityFoldIssue::InvalidEntry([0; 32])),
        }
    }
    let entry_ancestors = entry_ancestor_index(&by_hash);
    let mut equivocation_groups =
        BTreeMap::<(AuthorityKey, u64), BTreeSet<AuthorityEntryHash>>::new();
    let mut equivocation_by_hash = BTreeMap::<AuthorityEntryHash, (AuthorityKey, u64)>::new();
    for ((signer, seq), hashes) in by_signer_seq {
        if hashes.len() > 1 {
            if restore_prefix_divergence(&hashes, &by_hash, &entry_ancestors, context) {
                continue;
            }
            for hash in &hashes {
                equivocation_by_hash.insert(*hash, (signer.clone(), seq));
            }
            equivocation_groups.insert((signer.clone(), seq), hashes);
        }
    }
    // `entry_ancestors` is deliberately a raw graph index: fold scheduling
    // needs claimed ancestry to avoid making a parent wait on the candidate
    // that names it. It is not sufficient evidence that an entry predates a
    // fork, because signature-valid but chain-invalid candidates also
    // contribute arbitrary parent claims. Restrict that security-sensitive
    // exemption to candidates that independently fold over their complete
    // available ancestry.
    let chain_validated_fork_candidates = equivocation_groups
        .values()
        .flatten()
        .filter(|hash| {
            entry_folds_on_available_ancestry(**hash, &by_hash, &entry_ancestors, context)
        })
        .copied()
        .collect::<BTreeSet<_>>();
    let mut authority_forks = context.authority_forks.clone();
    let mut authority_fork_vault_ids = context.authority_fork_vault_ids.clone();
    let mut reported_authority_forks = BTreeMap::<(AuthorityKey, u64), AuthorityFork>::new();
    let mut reported_authority_fork_resolved_vault_ids =
        BTreeMap::<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>::new();
    let mut unresolved_equivocation_groups =
        BTreeSet::<(AuthorityKey, u64)>::from_iter(equivocation_groups.keys().cloned());

    let mut states = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    let mut pending: BTreeSet<AuthorityEntryHash> = by_hash.keys().copied().collect();
    let mut progressed = true;
    while progressed {
        progressed = false;
        let hashes: Vec<_> = pending.iter().copied().collect();
        for hash in hashes {
            let entry = &by_hash[&hash];
            if let Some(group_key) = equivocation_by_hash.get(&hash) {
                let group_key = group_key.clone();
                let group = &equivocation_groups[&group_key];
                let fold_context = FoldContext {
                    authority_forks: &authority_forks,
                    authority_fork_vault_ids: &authority_fork_vault_ids,
                    equivocation_groups: &equivocation_groups,
                    unresolved_equivocation_groups: &unresolved_equivocation_groups,
                    entry_ancestors: Some(&entry_ancestors),
                    chain_validated_fork_candidates: Some(&chain_validated_fork_candidates),
                    ..context
                };
                match resolve_equivocation_group(
                    &group_key,
                    group,
                    &by_hash,
                    &states,
                    &pending,
                    fold_context,
                ) {
                    EquivocationResolution::Waiting => continue,
                    EquivocationResolution::Resolved {
                        winner,
                        fork,
                        fork_vault_ids,
                        issues: group_issues,
                    } => {
                        // The per-round hash snapshot can revisit a second
                        // member of an already-resolved group; only the first
                        // resolution may emit facts, or every group member
                        // duplicates the detection and loser issues.
                        if !unresolved_equivocation_groups.remove(&group_key) {
                            continue;
                        }
                        if let Some(fork) = fork {
                            authority_forks.insert(group_key.clone(), fork.clone());
                            reported_authority_forks.insert(group_key.clone(), fork);
                            authority_fork_vault_ids.insert(group_key.clone(), fork_vault_ids);
                        }
                        if let Some((winner_hash, state)) = winner {
                            issues.push(AuthorityFoldIssue::EquivocationDetected {
                                signer: group_key.0.clone(),
                                seq: group_key.1,
                            });
                            states.insert(winner_hash, *state);
                        }
                        issues.extend(group_issues);
                        for group_hash in group {
                            pending.remove(group_hash);
                        }
                        progressed = true;
                        continue;
                    }
                }
            }
            let fold_context = FoldContext {
                authority_forks: &authority_forks,
                authority_fork_vault_ids: &authority_fork_vault_ids,
                equivocation_groups: &equivocation_groups,
                unresolved_equivocation_groups: &unresolved_equivocation_groups,
                entry_ancestors: Some(&entry_ancestors),
                chain_validated_fork_candidates: Some(&chain_validated_fork_candidates),
                ..context
            };
            match fold_entry_state(entry, hash, &states, fold_context) {
                EntryFold::Ready(state) => {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Invalid(issue) => {
                    issues.push(issue);
                    pending.remove(&hash);
                    progressed = true;
                }
                EntryFold::Waiting => {}
            }
        }
        if !progressed {
            // The round made no progress, so every hash still pending is stuck
            // for good under ordinary rules. ONLY here — never while entries may
            // still be waiting their turn — may a revocation resolve against the
            // ancestry ABOVE a parent that will never fold.
            let stalled: Vec<_> = pending.iter().copied().collect();
            for hash in stalled {
                if equivocation_by_hash.contains_key(&hash) {
                    continue;
                }
                let entry = &by_hash[&hash];
                let fold_context = FoldContext {
                    authority_forks: &authority_forks,
                    authority_fork_vault_ids: &authority_fork_vault_ids,
                    equivocation_groups: &equivocation_groups,
                    unresolved_equivocation_groups: &unresolved_equivocation_groups,
                    entry_ancestors: Some(&entry_ancestors),
                    chain_validated_fork_candidates: Some(&chain_validated_fork_candidates),
                    ..context
                };
                let Some(bypass_states) =
                    revocation_bypass_states(entry, &by_hash, &states, &pending, fold_context)
                else {
                    continue;
                };
                // Ready only. A revocation the bypass cannot justify stays
                // pending and is reported as `InvalidAncestry` below, exactly as
                // before — the bypass may rescue a revocation, never admit one.
                if let EntryFold::Ready(state) =
                    fold_entry_state(entry, hash, &bypass_states, fold_context)
                {
                    states.insert(hash, state);
                    pending.remove(&hash);
                    progressed = true;
                }
            }
        }
    }
    for hash in pending {
        issues.push(AuthorityFoldIssue::InvalidAncestry(hash));
    }

    let mut vault_ids = BTreeSet::new();
    for state in states.values() {
        vault_ids.insert(state.vault_id);
    }
    if vault_ids.len() > 1 {
        for (hash, state) in &states {
            issues.push(AuthorityFoldIssue::ConflictingVaultRoot {
                entry: *hash,
                vault_id: state.vault_id,
            });
        }
        for state in states.values() {
            reconcile_reported_authority_forks(
                &mut reported_authority_forks,
                &authority_fork_vault_ids,
                &mut reported_authority_fork_resolved_vault_ids,
                state,
            );
        }
        let authority_forks: Vec<_> = reported_authority_forks.values().cloned().collect();
        let fork_alarms = build_fork_alarms(&authority_forks);
        return (
            AuthorityFold {
                vault_id: None,
                valid_entries: BTreeSet::new(),
                roster: BTreeMap::new(),
                tier_floor: None,
                pending_widens: BTreeMap::new(),
                vetoed_widens: BTreeSet::new(),
                authority_forks,
                fork_alarms,
                federation_pacts: BTreeMap::new(),
                critical_write_confirms: BTreeMap::new(),
                consumed_critical_write_confirm_nonces: BTreeSet::new(),
                conflicted_critical_write_confirms: BTreeSet::new(),
                federation_grant_bindings: BTreeMap::new(),
                actor_bindings: BTreeMap::new(),
                issues,
            },
            authority_fork_vault_ids,
        );
    }

    let mut merged: Option<FoldState> = None;
    let mut valid_entries = BTreeSet::new();
    for (hash, state) in &states {
        valid_entries.insert(*hash);
        merged = Some(match merged {
            Some(current) => merge_states(&current, state),
            None => state.clone(),
        });
    }

    if let Some(state) = &merged {
        reconcile_reported_authority_forks(
            &mut reported_authority_forks,
            &authority_fork_vault_ids,
            &mut reported_authority_fork_resolved_vault_ids,
            state,
        );
    }
    let authority_forks: Vec<_> = reported_authority_forks.into_values().collect();
    let fork_alarms = build_fork_alarms(&authority_forks);
    // Collision poison is part of the externally auditable fold result, not
    // merely a settlement-time guard. Emit one deterministic issue per id.
    if let Some(state) = &merged {
        issues.extend(
            state
                .conflicted_critical_write_confirms
                .iter()
                .map(
                    |confirm_id| AuthorityFoldIssue::CriticalWriteConfirmConflict {
                        confirm_id: *confirm_id,
                    },
                ),
        );
    }
    let actor_bindings = merged.as_ref().map_or_else(BTreeMap::new, |state| {
        folded_actor_bindings(state, &authority_forks)
    });

    (
        AuthorityFold {
            vault_id: merged.as_ref().map(|state| state.vault_id),
            valid_entries,
            roster: merged
                .as_ref()
                .map_or_else(BTreeMap::new, |state| state.roster.clone()),
            tier_floor: merged.as_ref().map(|state| state.tier_floor),
            pending_widens: merged
                .as_ref()
                .map_or_else(BTreeMap::new, |state| state.pending_widens.clone()),
            vetoed_widens: merged
                .as_ref()
                .map_or_else(BTreeSet::new, |state| state.vetoed_widens.clone()),
            authority_forks,
            fork_alarms,
            federation_pacts: merged
                .as_ref()
                .map_or_else(BTreeMap::new, |state| state.federation_pacts.clone()),
            critical_write_confirms: merged
                .as_ref()
                .map_or_else(BTreeMap::new, |state| state.critical_write_confirms.clone()),
            consumed_critical_write_confirm_nonces: merged
                .as_ref()
                .map_or_else(BTreeSet::new, |state| {
                    state.consumed_critical_write_confirm_nonces.clone()
                }),
            conflicted_critical_write_confirms: merged
                .as_ref()
                .map_or_else(BTreeSet::new, |state| {
                    state.conflicted_critical_write_confirms.clone()
                }),
            federation_grant_bindings: merged.as_ref().map_or_else(BTreeMap::new, |state| {
                state.federation_grant_bindings.clone()
            }),
            actor_bindings,
            issues,
        },
        authority_fork_vault_ids,
    )
}
