//! Top-level fold orchestration.
//!
//! `FoldContext` plus the topological entry-by-entry driver; its local,
//! peer, and seen-time entry points live in `entry_points`. Per-entry state
//! transitions are delegated to [`super::entry_transition`].
//!
//! Seen-times feed only the post-fold stale-roster window; no entry waits on
//! them (the delayed-widen ceremony died 2026-08-05, identity canon "Device-key
//! widen ceremony (dead 2026-08-05)").

use std::collections::{BTreeMap, BTreeSet};

use super::*;

mod causal;
mod entry_points;

pub(super) use causal::{CausalPast, ImagePast, ParentSummaries, named_beneath};
pub use entry_points::*;

#[derive(Clone, Copy)]
pub(super) struct FoldContext<'a> {
    pub(super) sequence_floors: Option<&'a BTreeMap<AuthorityEntryHash, u64>>,
    /// Rows no floor refuses (a handoff's line, a removal's own branch); one
    /// past its floor still lands restriction only.
    pub(super) floor_vouched: Option<&'a BTreeSet<AuthorityEntryHash>>,
    /// Revisions and world edits held to restriction only (`install_fold::NoVouch`).
    pub(super) install_held: Option<&'a BTreeSet<AuthorityEntryHash>>,
    pub(super) entry_ancestors:
        Option<&'a BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>>,
    /// Where a fold with no `entry_ancestors` walks a row's past: a resumed
    /// fold's or an adopted image's row summaries ([`causal`], FIX 5464). It
    /// shows only whether a hash is beneath a row's parents, never what any
    /// row may do. None on a fold that holds the whole log.
    pub(super) causal_past: Option<&'a CausalPast<'a>>,
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
    /// The vault folds under the hosted posture, where the host's own root is
    /// the provider's key. Never inferred from the consent arm: a peer fold's
    /// arm admits cloud roots without saying whose root a key is.
    pub(super) hosted: bool,
    /// Which machines the roster rule admits as the owner's this install
    /// counts: a world edit from one it does not count only narrows.
    pub(super) machine_standing: super::machine_standing::InstallCounted<'a>,
    /// Only verified pre-handoff ancestry can use retired device-key ops.
    /// None is the legacy-only reference fold, never the posture-aware vault door.
    pub(super) pre_handoff_entries: Option<&'a BTreeSet<AuthorityEntryHash>>,
    /// The bytes this fold may project to hold at its peak.
    pub(super) memory_floor_bytes: u64,
    /// This install's pin on a fold of its own vault's log: which world-key
    /// records count here. It decides no entry's validity.
    pub(super) pin: Option<&'a PinnedRoot>,
}

impl FoldContext<'_> {
    pub(super) fn device_can_consent(self, device: &FoldedDevice) -> bool {
        (self.consent_arm)(device)
    }
}

#[derive(Default, Clone, Copy)]
pub(super) struct FoldLocalInputs<'a> {
    pub(super) observations: Option<&'a AuthorityLocalObservations>,
    pub(super) retire_device_ops: bool,
    pub(super) pre_handoff_entries: Option<&'a BTreeSet<AuthorityEntryHash>>,
    pub(super) hosted: bool,
    pub(super) machine_standing: Option<super::machine_standing::InstallCounted<'a>>,
    /// The handoffs valid on their own rows; only these settle. None settles
    /// every handoff the fold holds.
    pub(super) handoff_candidates: Option<&'a BTreeSet<AuthorityEntryHash>>,
    /// This install's pin, on a fold of its own vault's log. It moves trust
    /// only, never which entries are valid; a peer's log folds with none.
    pub(super) pin: Option<&'a PinnedRoot>,
    /// Where the strict fold leaves what a resumed fold starts from; never
    /// handed to a probe.
    pub(super) capture: Option<&'a super::fold_resume::FoldCapture>,
}

impl FoldLocalInputs<'_> {
    pub(super) const VAULT_DOOR: Self = Self {
        observations: None,
        retire_device_ops: true,
        pre_handoff_entries: None,
        hosted: false,
        machine_standing: None,
        handoff_candidates: None,
        pin: None,
        capture: None,
    };
}

pub(super) fn fold_authority_log_inner(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    consent_arm: fn(&FoldedDevice) -> bool,
    local: FoldLocalInputs<'_>,
) -> AuthorityFold {
    if local.retire_device_ops {
        // An unrelated retired sibling must not vote in a handoff probe:
        // it could otherwise disqualify a valid rotation before the strict
        // fold ever gets a chance to reject the sibling. Validate
        // each candidate against ONLY its own claimed signed ancestry.
        let mut candidates = verified_handoff_candidates(
            entries,
            first_seen_at_secs,
            now_secs,
            peer_consent_roots,
            consent_arm,
            local,
        );
        let mut rounds = 0_usize;
        loop {
            rounds += 1;
            let handoffs: BTreeSet<_> = candidates.keys().copied().collect();
            let allowed = verified_handoff_ancestors(entries, &handoffs);
            // Each candidate's line settles as it probed, under no local
            // sequence floor; every other row keeps its floor.
            let lines: BTreeSet<_> = candidates.values().flatten().copied().collect();
            let observations = local
                .observations
                .map(|observations| observations.vouching(&lines));
            let result = fold_authority_log_inner(
                entries,
                first_seen_at_secs,
                now_secs,
                peer_consent_roots,
                consent_arm,
                FoldLocalInputs {
                    observations: observations.as_ref(),
                    retire_device_ops: false,
                    pre_handoff_entries: Some(&allowed),
                    hosted: local.hosted,
                    machine_standing: local.machine_standing,
                    handoff_candidates: Some(&handoffs),
                    pin: local.pin,
                    capture: local.capture,
                },
            );
            // A handoff in conflict keeps its standing here: its fence stays
            // closed, so the handoff it conflicts with never settles alone.
            candidates.retain(|candidate, _| {
                result.valid_entries.contains(candidate)
                    || result.closed_handoffs.contains(candidate)
            });
            if candidates.len() == handoffs.len() {
                if let Some(capture) = local.capture
                    && rounds > 1
                {
                    capture.spoil();
                }
                return result;
            }
        }
    }
    super::install_fold::fold_as_install(
        entries,
        first_seen_at_secs,
        now_secs,
        peer_consent_roots,
        consent_arm,
        local,
    )
}

/// Probe each signed re-root against its own causal history, and map each
/// that stands there to that history, its line. A retired sibling outside
/// the line has zero authority to eliminate a candidate, and
/// neither has a local sequence floor. A floor records only which rows of a
/// signer this vault saw first, so a sibling that arrived first would decide
/// the settlement, and the same rows would settle differently in another
/// arrival order. The handoff vouches for its line as it vouches for its
/// parents, so the probe applies no floor inside it. The final strict fold
/// rechecks these candidates as a set, under the same rule.
fn verified_handoff_candidates(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    consent_arm: fn(&FoldedDevice) -> bool,
    local: FoldLocalInputs<'_>,
) -> BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>> {
    let by_hash: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|entry| authority_entry_hash(entry).ok().map(|hash| (hash, entry)))
        .collect();
    let mut candidates = BTreeMap::new();
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
        let observations = local
            .observations
            .map(|observations| observations.vouching(&closure));
        let probe = fold_authority_log_inner(
            &scoped,
            first_seen_at_secs,
            now_secs,
            peer_consent_roots,
            consent_arm,
            FoldLocalInputs {
                observations: observations.as_ref(),
                retire_device_ops: false,
                pre_handoff_entries: None,
                capture: None,
                ..local
            },
        );
        if !probe.vault_root_is_conflicted() && probe.valid_entries.contains(candidate) {
            candidates.insert(*candidate, closure);
        }
    }
    candidates
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
            if op_is_retired_device_op(&ancestor.op) && !has_re_root_ancestor(ancestor, &by_hash) {
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

/// The entries a fold of `entries` judges, by hash: each well signed, none
/// hanging off another branch's side entry. With the issues found.
fn judged_entries(
    entries: &[AuthorityLogEntry],
) -> (
    BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    Vec<AuthorityFoldIssue>,
) {
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
    // Before ancestry, floors and restrictive proofs: no fold path may
    // accept an entry that hangs off another branch's side entry.
    for hash in super::world_privacy::side_branch_violations(&by_hash) {
        by_hash.remove(&hash);
        issues.push(AuthorityFoldIssue::InvalidEntry(hash));
    }
    (by_hash, issues)
}

/// The floors a fold of `entries` under `context` applies, once causal
/// ancestry has vouched for every row it can (`sequence_ancestry`).
pub(super) fn causal_floors_of(
    entries: &[AuthorityLogEntry],
    context: FoldContext<'_>,
) -> Option<BTreeMap<AuthorityEntryHash, u64>> {
    let (by_hash, _) = judged_entries(entries);
    let (ancestors, _) = entry_ancestor_index(&by_hash, context.memory_floor_bytes)?;
    super::sequence_ancestry::causal_sequence_floors(&by_hash, &ancestors, context)
}

pub(super) fn fold_authority_log_once(
    entries: &[AuthorityLogEntry],
    context: FoldContext<'_>,
    handoffs: Option<&BTreeSet<AuthorityEntryHash>>,
    capture: Option<&super::fold_resume::FoldCapture>,
) -> AuthorityFold {
    let original_floors = context.sequence_floors;
    let (by_hash, mut issues) = judged_entries(entries);
    let Some((entry_ancestors, counted_ancestor_pairs)) =
        entry_ancestor_index(&by_hash, context.memory_floor_bytes)
    else {
        return super::log_budget::memory_floor_fold(context.memory_floor_bytes);
    };
    let causal_floors =
        super::sequence_ancestry::causal_sequence_floors(&by_hash, &entry_ancestors, context);
    let context = FoldContext {
        sequence_floors: causal_floors.as_ref(),
        entry_ancestors: Some(&entry_ancestors),
        ..context
    };

    // Restrictive facts are proved independently of the surviving roster.
    let mut revoke_facts =
        super::revoke_proof::derive_revoke_facts(&by_hash, &entry_ancestors, context);
    let mut states = super::fold_schedule::fold_entry_states(&by_hash, context, &mut issues);

    // A handoff's predecessor stays retired on every branch, not only its own.
    // Fences close before concurrent confirmations contend, so a retired
    // key's confirmation never prunes the new root's rows.
    let retirements = super::retired_signers::settle_handoffs(
        &mut states,
        &by_hash,
        &entry_ancestors,
        handoffs,
        &mut issues,
        |states, present| federation_confirm_losers(states, &by_hash, present),
    );
    super::world_refold::refold_world_edits(
        &mut states,
        &by_hash,
        &entry_ancestors,
        context,
        &mut issues,
    );
    let retired_keys = retirements.keys();
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
            anchor_heads: BTreeMap::new(),
            scope_heads: BTreeMap::new(),
            append_sequences: BTreeMap::new(),
            actor_revocation_affected_writers: BTreeSet::new(),
            actor_write_frontiers: BTreeMap::new(),
            revoked_actor_keys: BTreeSet::new(),
            slips: SlipAuthorityState::default(),
            vault_id: None,
            valid_entries: BTreeSet::new(),
            roster: BTreeMap::new(),
            retired_keys: BTreeSet::new(),
            closed_handoffs: BTreeSet::new(),
            genesis_fragile: false,
            federation_pacts: BTreeMap::new(),
            federation_confirms: BTreeMap::new(),
            critical_write_confirms: BTreeMap::new(),
            consumed_critical_write_confirm_nonces: BTreeSet::new(),
            conflicted_critical_write_confirms: BTreeSet::new(),
            federation_grant_bindings: BTreeMap::new(),
            actor_bindings: BTreeMap::new(),
            machines: BTreeMap::new(),
            pinned_root: None,
            root_anchors: BTreeMap::new(),
            anchor_entries: BTreeSet::new(),
            accepted_roster_marks: BTreeSet::new(),
            worlds: BTreeMap::new(),
            refused_world_edits: BTreeSet::new(),
            grant_travel: BTreeMap::new(),
            refused_grant_travel: BTreeSet::new(),
            checkpoint_policy: super::checkpoint_choice::FoldedCheckpointPolicy::default(),
            home_pick: super::home_pick::FoldedHomePick::default(),
            conversation_training:
                super::conversation_training::FoldedConversationTraining::default(),
            conversation_training_vault:
                super::conversation_training_vault::FoldedConversationTrainingVault::default(),
            home_candidacy: BTreeMap::new(),
            owner_work: super::owner_work::FoldedOwnerWork::default(),
            install: InstallBound::default(),
            counted_ancestor_pairs,
            world_keys: BTreeMap::new(),
            refused_world_keys: BTreeSet::new(),
            issues,
        };
    }

    revoke_facts.add_dropped_slip_restrictions(&by_hash, &entry_ancestors, context, &states);
    revoke_facts.forget_retired(&retirements, &by_hash, &entry_ancestors);
    revoke_facts.forget_unsettled(&states, &by_hash, &entry_ancestors);
    let mut merged: Option<FoldState> = None;
    let mut valid_entries = BTreeSet::new();
    for (hash, state) in &states {
        valid_entries.insert(*hash);
        merged = Some(match merged {
            Some(current) => merge_states(&current, state),
            None => state.clone(),
        });
    }

    let kept = capture.map(|_| {
        (
            merged.clone(),
            valid_entries.clone(),
            retired_keys.clone(),
            issues.clone(),
        )
    });
    let (fold, final_merged) = super::fold_project::project_once(
        super::fold_project::Settled {
            merged,
            valid_entries,
            by_hash: &by_hash,
            revoke_facts: &revoke_facts,
            retired_keys,
            closed_handoffs: retirements.handoffs(),
            unsettled: retirements.unsettled(),
            counted_ancestor_pairs,
            issues,
        },
        &super::fold_project::AllStates {
            by_hash: &by_hash,
            states: &states,
        },
        context,
    );
    if let (Some(capture), Some((Some(merged), valid_entries, retired_keys, issues))) =
        (capture, kept)
    {
        capture.record(super::fold_resume::OnceParts {
            by_hash: &by_hash,
            states: &states,
            entry_ancestors: &entry_ancestors,
            original_floors,
            merged,
            valid_entries,
            revoke_facts,
            retired_keys,
            closed_handoffs: retirements.handoffs(),
            unsettled: retirements.unsettled(),
            counted_ancestor_pairs,
            issues,
            final_merged: final_merged.as_ref(),
            fold: &fold,
        });
    }
    fold
}

/// The confirmations that lose a collision among the rows `present` keeps,
/// with why. Confirmations are consumable across branches, not only in
/// ancestry, and only entries already proven against their live roster
/// contend.
fn federation_confirm_losers(
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    present: &dyn Fn(&AuthorityEntryHash) -> bool,
) -> BTreeMap<AuthorityEntryHash, AuthorityFoldIssue> {
    let mut ids = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut rejected = BTreeMap::new();
    // Hash order is a stable choice among otherwise valid concurrent asks.
    for hash in states.keys().filter(|hash| present(hash)) {
        if let AuthorityOp::FederationConfirm(action) = &entries[hash].op {
            let vault = states[hash].vault_id;
            if ids.contains(&(vault, action.confirm_id)) || nonces.contains(&(vault, action.nonce))
            {
                rejected.insert(*hash, AuthorityFoldIssue::InvalidEntry(*hash));
            } else {
                ids.insert((vault, action.confirm_id));
                nonces.insert((vault, action.nonce));
            }
        }
    }
    rejected
}
