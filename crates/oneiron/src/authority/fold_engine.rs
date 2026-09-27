//! Top-level fold orchestration.
//!
//! `FoldContext` plus the topological entry-by-entry driver and its local,
//! peer, and seen-time variants. Per-entry state transitions are delegated
//! to [`super::entry_transition`].

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[derive(Clone, Copy)]
pub(super) struct FoldContext<'a> {
    pub(super) first_seen_at_secs: &'a BTreeMap<AuthorityEntryHash, u64>,
    pub(super) now_secs: Option<u64>,
    /// Minimum future eligibility observed during ANY fold pass, including a
    /// pending widen subsequently removed by an accepted veto.
    pub(super) deadline_observer: Option<&'a Cell<Option<u64>>>,
    pub(super) sequence_floors: Option<&'a BTreeMap<AuthorityEntryHash, u64>>,
    pub(super) enforce_seen_time_delay: bool,
    pub(super) vetoed_widens: &'a BTreeSet<AuthorityEntryHash>,
    pub(super) entry_ancestors:
        Option<&'a BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>>,
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
    /// Only verified pre-handoff ancestry can use retired device-key ops.
    /// None is the legacy-only reference fold, never the posture-aware vault door.
    pub(super) pre_handoff_entries: Option<&'a BTreeSet<AuthorityEntryHash>>,
}

impl FoldContext<'_> {
    pub(super) fn device_can_consent(self, device: &FoldedDevice) -> bool {
        (self.consent_arm)(device)
    }
}

#[derive(Default, Clone, Copy)]
struct FoldLocalInputs<'a> {
    observations: Option<&'a AuthorityLocalObservations>,
    deadline_observer: Option<&'a Cell<Option<u64>>>,
    retire_device_ops: bool,
    pre_handoff_entries: Option<&'a BTreeSet<AuthorityEntryHash>>,
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
        FoldLocalInputs {
            retire_device_ops: true,
            ..FoldLocalInputs::default()
        },
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
        FoldLocalInputs::default(),
    )
}

// Historical signed-history reference for unit tests of pre-handoff ancestry.
// Never used by Vault, peers, cache, replay admission, or public authorization.
#[cfg(test)]
pub(super) fn fold_legacy_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    fold_authority_log_inner(
        entries,
        &BTreeMap::new(),
        Some(0),
        true,
        &BTreeMap::new(),
        folded_device_can_authority_consent,
        FoldLocalInputs::default(),
    )
}

#[cfg(test)]
pub(super) fn fold_legacy_authority_log_with_seen_times(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
) -> AuthorityFold {
    fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        true,
        &BTreeMap::new(),
        folded_device_can_authority_consent,
        FoldLocalInputs::default(),
    )
}

#[cfg(test)]
pub(super) fn fold_legacy_peer_authority_log(entries: &[AuthorityLogEntry]) -> AuthorityFold {
    fold_authority_log_inner(
        entries,
        &BTreeMap::new(),
        None,
        false,
        &BTreeMap::new(),
        folded_peer_device_is_consent_root,
        FoldLocalInputs::default(),
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
        FoldLocalInputs {
            retire_device_ops: true,
            ..FoldLocalInputs::default()
        },
    )
}

/// Folds under the vault's explicit hosting posture. Relay and self-host retain
/// owner-device consent; only managed hosts may treat a cloud key as root.
pub fn fold_authority_log_for_posture(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    posture: crate::HostingPrivacyPosture,
) -> AuthorityFold {
    let consent = if posture == crate::HostingPrivacyPosture::Hosted {
        folded_host_device_can_consent
    } else {
        folded_device_can_authority_consent
    };
    fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        true,
        peer_consent_roots,
        consent,
        FoldLocalInputs {
            retire_device_ops: true,
            ..FoldLocalInputs::default()
        },
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
        FoldLocalInputs {
            retire_device_ops: true,
            ..FoldLocalInputs::default()
        },
    )
}

/// Return the same reference fold plus the earliest future eligibility
/// observed in its fixed-point passes. This is cache metadata, not fold output.
/// A veto can erase its target from the final pending map even though that
/// target's eligibility still changes whether the veto is valid later.
pub(super) fn fold_authority_log_with_local_observations_and_posture_with_deadline(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    observations: &AuthorityLocalObservations,
    posture: crate::HostingPrivacyPosture,
) -> (AuthorityFold, Option<u64>) {
    let consent = if posture == crate::HostingPrivacyPosture::Hosted {
        folded_host_device_can_consent
    } else {
        folded_device_can_authority_consent
    };
    let deadline = Cell::new(None);
    let fold = fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        true,
        peer_consent_roots,
        consent,
        FoldLocalInputs {
            observations: Some(observations),
            deadline_observer: Some(&deadline),
            retire_device_ops: true,
            pre_handoff_entries: None,
        },
    );
    (fold, deadline.get())
}

fn fold_authority_log_inner(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    enforce_seen_time_delay: bool,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    consent_arm: fn(&FoldedDevice) -> bool,
    local: FoldLocalInputs<'_>,
) -> AuthorityFold {
    if local.retire_device_ops {
        // An unrelated retired sibling must not vote in a handoff probe:
        // its tier floor could otherwise disqualify a valid rotation before
        // the strict fold ever gets a chance to reject the sibling. Validate
        // each candidate against ONLY its own claimed signed ancestry.
        let (mut candidates, pending_handoff_ancestry) = verified_handoff_candidates(
            entries,
            first_seen_at_secs,
            now_secs,
            enforce_seen_time_delay,
            peer_consent_roots,
            consent_arm,
            local,
        );
        loop {
            let allowed = verified_handoff_ancestors(entries, &candidates);
            let result = fold_authority_log_inner(
                entries,
                first_seen_at_secs,
                now_secs,
                enforce_seen_time_delay,
                peer_consent_roots,
                consent_arm,
                FoldLocalInputs {
                    retire_device_ops: false,
                    pre_handoff_entries: Some(&allowed),
                    ..local
                },
            );
            let retained: BTreeSet<_> = candidates
                .intersection(&result.valid_entries)
                .copied()
                .collect();
            if retained == candidates {
                let mut result = result;
                // Pending pre-handoff ancestry does not grant a client key, but
                // its observed deadline still decides when a signed handoff
                // may retire the old root. Keep that fact for cache expiry and
                // fail-closed readonly folds with a missing local sidecar.
                result.pending_widens.extend(pending_handoff_ancestry);
                return result;
            }
            candidates = retained;
        }
    }
    let mut vetoed_widens = BTreeSet::new();
    let sequence_floors = local
        .observations
        .map(|observations| &observations.sequence_floors);
    let stale_roster_window_secs = local
        .observations
        .map_or(DEFAULT_STALE_ROSTER_WINDOW_SECS, |local| {
            local.policy.stale_roster_window_secs
        });
    let mut fold = fold_authority_log_once(
        entries,
        FoldContext {
            first_seen_at_secs,
            now_secs,
            deadline_observer: local.deadline_observer,
            sequence_floors,
            enforce_seen_time_delay,
            vetoed_widens: &vetoed_widens,
            entry_ancestors: None,
            peer_consent_roots,
            consent_arm,
            pre_handoff_entries: local.pre_handoff_entries,
        },
    );
    for _ in 0..=entries.len() {
        if fold.vetoed_widens == vetoed_widens {
            break;
        }
        vetoed_widens = fold.vetoed_widens.clone();
        fold = fold_authority_log_once(
            entries,
            FoldContext {
                first_seen_at_secs,
                now_secs,
                deadline_observer: local.deadline_observer,
                sequence_floors,
                enforce_seen_time_delay,
                vetoed_widens: &vetoed_widens,
                entry_ancestors: None,
                peer_consent_roots,
                consent_arm,
                pre_handoff_entries: local.pre_handoff_entries,
            },
        );
    }
    let mut fold = apply_stale_roster_window(
        entries,
        fold,
        first_seen_at_secs,
        now_secs,
        stale_roster_window_secs,
    );
    fold.append_heads = fold.valid_entries.clone();
    for entry in entries {
        // Advance beyond even a signed rejected local entry. A new local write
        // never reuses a sequence, though independently received siblings may.
        fold.append_sequences
            .entry(entry.signer.public_key.clone())
            .and_modify(|seq| *seq = (*seq).max(entry.seq))
            .or_insert(entry.seq);
        if authority_entry_hash(entry).is_ok_and(|hash| fold.valid_entries.contains(&hash)) {
            for parent in &entry.parent_hashes {
                fold.append_heads.remove(parent);
            }
        }
    }
    fold
}

/// Probe each signed re-root against its own causal history. A tier-floor or
/// other retired sibling outside that history has zero authority to eliminate
/// a candidate. The final strict fold rechecks these candidates as a set.
fn verified_handoff_candidates(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    enforce_seen_time_delay: bool,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    consent_arm: fn(&FoldedDevice) -> bool,
    local: FoldLocalInputs<'_>,
) -> (
    BTreeSet<AuthorityEntryHash>,
    BTreeMap<AuthorityEntryHash, AuthorityPendingWiden>,
) {
    let by_hash: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|entry| authority_entry_hash(entry).ok().map(|hash| (hash, entry)))
        .collect();
    let mut candidates = BTreeSet::new();
    let mut pending = BTreeMap::new();
    for (candidate, entry) in &by_hash {
        if !matches!(entry.op, AuthorityOp::ReRoot { .. })
            || entry.validate_shape().is_err()
            || verify_entry_signatures(entry).is_err()
        {
            continue;
        }
        let mut closure = BTreeSet::new();
        let mut stack = vec![*candidate];
        let mut complete = true;
        while let Some(hash) = stack.pop() {
            if !closure.insert(hash) {
                continue;
            }
            let Some(ancestor) = by_hash.get(&hash) else {
                complete = false;
                break;
            };
            stack.extend(ancestor.parent_hashes.iter().copied());
        }
        if !complete {
            continue;
        }
        let scoped: Vec<_> = closure
            .iter()
            .map(|hash| (*by_hash[hash]).clone())
            .collect();
        let probe = fold_authority_log_inner(
            &scoped,
            first_seen_at_secs,
            now_secs,
            enforce_seen_time_delay,
            peer_consent_roots,
            consent_arm,
            FoldLocalInputs {
                deadline_observer: local.deadline_observer,
                retire_device_ops: false,
                pre_handoff_entries: None,
                ..local
            },
        );
        if !probe.vault_root_is_conflicted() {
            pending.extend(probe.pending_widens);
            if probe.valid_entries.contains(candidate) {
                candidates.insert(*candidate);
            }
        }
    }
    (candidates, pending)
}

/// Retired device operations are usable only in a verified re-root's signed
/// ancestry and only before the first handoff on that branch. A later re-root
/// never revives device-key enrollment after a prior handoff.
fn verified_handoff_ancestors(
    entries: &[AuthorityLogEntry],
    valid_handoffs: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    let by_hash: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|entry| authority_entry_hash(entry).ok().map(|hash| (hash, entry)))
        .collect();
    let mut permitted = BTreeSet::new();
    for (hash, entry) in &by_hash {
        if !valid_handoffs.contains(hash) || !matches!(entry.op, AuthorityOp::ReRoot { .. }) {
            continue;
        }
        let mut stack = entry.parent_hashes.clone();
        let mut visited = BTreeSet::new();
        while let Some(parent) = stack.pop() {
            if !visited.insert(parent) {
                continue;
            }
            let Some(ancestor) = by_hash.get(&parent) else {
                continue;
            };
            if matches!(ancestor.op, AuthorityOp::ReRoot { .. }) {
                continue;
            }
            stack.extend(ancestor.parent_hashes.iter().copied());
            if matches!(
                ancestor.op,
                AuthorityOp::EnrollDevice { .. }
                    | AuthorityOp::RotateKey { .. }
                    | AuthorityOp::SetTierFloor { .. }
                    | AuthorityOp::VetoPendingWiden { .. }
            ) && !has_re_root_ancestor(ancestor, &by_hash)
            {
                permitted.insert(parent);
            }
        }
    }
    permitted
}

fn has_re_root_ancestor(
    entry: &AuthorityLogEntry,
    by_hash: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> bool {
    let mut stack = entry.parent_hashes.clone();
    let mut visited = BTreeSet::new();
    while let Some(hash) = stack.pop() {
        if !visited.insert(hash) {
            continue;
        }
        if let Some(ancestor) = by_hash.get(&hash) {
            if matches!(ancestor.op, AuthorityOp::ReRoot { .. }) {
                return true;
            }
            stack.extend(ancestor.parent_hashes.iter().copied());
        }
    }
    false
}

fn fold_authority_log_once(
    entries: &[AuthorityLogEntry],
    context: FoldContext<'_>,
) -> AuthorityFold {
    let mut by_hash = BTreeMap::<AuthorityEntryHash, AuthorityLogEntry>::new();
    let mut issues = Vec::new();
    for entry in entries {
        match authority_entry_hash(entry) {
            Ok(hash) if verify_entry_signatures(entry).is_ok() => {
                by_hash.entry(hash).or_insert_with(|| entry.clone());
            }
            Ok(hash) => issues.push(AuthorityFoldIssue::InvalidEntry(hash)),
            Err(_) => issues.push(AuthorityFoldIssue::InvalidEntry([0; 32])),
        }
    }
    let entry_ancestors = entry_ancestor_index(&by_hash);
    let causal_floors =
        super::sequence_ancestry::causal_sequence_floors(&by_hash, &entry_ancestors, context);
    let context = FoldContext {
        sequence_floors: causal_floors.as_ref(),
        entry_ancestors: Some(&entry_ancestors),
        ..context
    };

    // Restrictive facts are proved independently of the surviving roster.
    let revoke_facts =
        super::revoke_proof::derive_revoke_facts(&by_hash, &entry_ancestors, context);
    let mut states = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    let mut pending: BTreeSet<AuthorityEntryHash> = by_hash.keys().copied().collect();
    let mut progressed = true;
    while progressed {
        progressed = false;
        let mut hashes: Vec<_> = pending.iter().copied().collect();
        hashes.sort_by_key(|hash| {
            (
                !matches!(
                    by_hash[hash].op,
                    AuthorityOp::RevokeActor { .. } | AuthorityOp::RevokeDevice { .. }
                ),
                *hash,
            )
        });
        for hash in hashes {
            // Restart selection after one successful transition. A revoke
            // whose parent just landed is considered before any ready grant.
            if progressed {
                break;
            }
            let entry = &by_hash[&hash];
            let fold_context = context;
            match super::ancestry_evaluator::evaluate_entry(
                entry,
                hash,
                &by_hash,
                &states,
                &pending,
                fold_context,
                super::ancestry_evaluator::EvaluationPhase::Normal,
            ) {
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
                let entry = &by_hash[&hash];
                let fold_context = context;
                let empty_rejected = BTreeSet::new();
                if let EntryFold::Ready(state) = super::ancestry_evaluator::evaluate_entry(
                    entry,
                    hash,
                    &by_hash,
                    &states,
                    &pending,
                    fold_context,
                    super::ancestry_evaluator::EvaluationPhase::Stalled(&empty_rejected),
                ) {
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

    reject_below_concurrent_tier_floors(&mut states, &by_hash, &entry_ancestors, &mut issues);
    // Confirmations are consumable across branches, not only in ancestry.
    // Only entries already proven against their live roster can contend.
    reject_replayed_federation_confirms(&mut states, &by_hash, &entry_ancestors, &mut issues);
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
        return AuthorityFold {
            append_heads: BTreeSet::new(),
            append_sequences: BTreeMap::new(),
            actor_revocation_affected_writers: BTreeSet::new(),
            actor_write_frontiers: BTreeMap::new(),
            revoked_actor_keys: BTreeSet::new(),
            slips: SlipAuthorityState::default(),
            vault_id: None,
            valid_entries: BTreeSet::new(),
            roster: BTreeMap::new(),
            tier_floor: None,
            genesis_fragile: false,
            pending_widens: BTreeMap::new(),
            vetoed_widens: BTreeSet::new(),
            federation_pacts: BTreeMap::new(),
            federation_confirms: BTreeMap::new(),
            critical_write_confirms: BTreeMap::new(),
            consumed_critical_write_confirm_nonces: BTreeSet::new(),
            conflicted_critical_write_confirms: BTreeSet::new(),
            federation_grant_bindings: BTreeMap::new(),
            actor_bindings: BTreeMap::new(),
            issues,
        };
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
    if let Some(state) = &mut merged {
        revoke_facts.apply_to(state);
    }
    let actor_bindings = merged.as_ref().map_or_else(BTreeMap::new, |state| {
        folded_actor_bindings(state, context.consent_arm)
    });

    AuthorityFold {
        append_heads: BTreeSet::new(),
        append_sequences: BTreeMap::new(),
        actor_revocation_affected_writers: super::causal_write::revocation_affected_writers(
            &states,
            merged.as_ref(),
        ),
        actor_write_frontiers: super::causal_write::causal_actor_frontiers(
            &states,
            merged.as_ref(),
            &actor_bindings,
        ),
        revoked_actor_keys: merged.as_ref().map_or_else(BTreeSet::new, |state| {
            state.actor_revocation_hashes.keys().cloned().collect()
        }),
        slips: merged
            .as_ref()
            .map_or_else(SlipAuthorityState::default, |state| state.slips.clone()),
        vault_id: merged.as_ref().map(|state| state.vault_id),
        valid_entries,
        roster: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.roster.clone()),
        tier_floor: merged.as_ref().map(|state| state.tier_floor),
        genesis_fragile: merged.as_ref().is_some_and(|state| {
            state.genesis_recovery_dismissed && !state.recovery_redundancy_established
        }),
        pending_widens: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.pending_widens.clone()),
        vetoed_widens: merged
            .as_ref()
            .map_or_else(BTreeSet::new, |state| state.vetoed_widens.clone()),
        federation_pacts: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.federation_pacts.clone()),
        federation_confirms: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.federation_confirms.clone()),
        critical_write_confirms: merged
            .as_ref()
            .map_or_else(BTreeMap::new, |state| state.critical_write_confirms.clone()),
        consumed_critical_write_confirm_nonces: merged
            .as_ref()
            .map_or_else(BTreeSet::new, |state| {
                state.consumed_critical_write_confirm_nonces.clone()
            }),
        conflicted_critical_write_confirms: merged.as_ref().map_or_else(BTreeSet::new, |state| {
            state.conflicted_critical_write_confirms.clone()
        }),
        federation_grant_bindings: merged.as_ref().map_or_else(BTreeMap::new, |state| {
            state.federation_grant_bindings.clone()
        }),
        actor_bindings,
        issues,
    }
}

fn reject_replayed_federation_confirms(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    issues: &mut Vec<AuthorityFoldIssue>,
) {
    let mut ids = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut rejected = BTreeSet::new();
    // Hash order is a stable choice among otherwise valid concurrent asks.
    for hash in states.keys() {
        if let AuthorityOp::FederationConfirm(action) = &entries[hash].op {
            let vault = states[hash].vault_id;
            if ids.contains(&(vault, action.confirm_id)) || nonces.contains(&(vault, action.nonce))
            {
                rejected.insert(*hash);
            } else {
                ids.insert((vault, action.confirm_id));
                nonces.insert((vault, action.nonce));
            }
        }
    }
    states.retain(|hash, _| {
        if rejected.contains(hash) {
            issues.push(AuthorityFoldIssue::InvalidEntry(*hash));
            false
        } else if ancestors
            .get(hash)
            .is_some_and(|parents| !parents.is_disjoint(&rejected))
        {
            issues.push(AuthorityFoldIssue::InvalidAncestry(*hash));
            false
        } else {
            true
        }
    });
}
