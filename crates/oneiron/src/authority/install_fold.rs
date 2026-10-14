//! The strict fold as this install reads it, once its handoffs settle: its
//! own sequence floors, the stale-roster window, and only the machines it
//! counts.

use std::collections::{BTreeMap, BTreeSet};

use super::fold_engine::{FoldLocalInputs, fold_authority_log_once};
use super::*;

pub(super) fn fold_as_install(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    consent_arm: fn(&FoldedDevice) -> bool,
    local: FoldLocalInputs<'_>,
) -> AuthorityFold {
    let sequence_floors = local
        .observations
        .map(|observations| &observations.sequence_floors);
    let stale_roster_window_secs = local
        .observations
        .map_or(DEFAULT_STALE_ROSTER_WINDOW_SECS, |local| {
            local.policy.stale_roster_window_secs
        });
    let standing = local
        .machine_standing
        .unwrap_or(&super::world_privacy::every_admitted_machine);
    let held = held_without_vouch(
        entries,
        first_seen_at_secs,
        now_secs,
        peer_consent_roots,
        consent_arm,
        local,
    );
    let context = FoldContext {
        sequence_floors,
        floor_vouched: local.observations.map(|observations| &observations.vouched),
        install_held: Some(&held),
        entry_ancestors: None,
        peer_consent_roots,
        consent_arm,
        hosted: local.hosted,
        machine_standing: standing,
        pre_handoff_entries: local.pre_handoff_entries,
    };
    // Staleness is this install's own projection, which the structural fold
    // never sees, and so is a roster left with no settled root. A machine
    // stale here, or one such a roster admitted, is one this install does not
    // count, so fold again without it: its world edits then only narrow. Both
    // rest on valid entries alone and counting changes no entry's validity, so
    // the second fold finds the same machines.
    let mut uncounted = BTreeSet::<crate::EntityId>::new();
    let mut fold = loop {
        let counted = |state: &FoldState, machine: &FoldedMachine| {
            !uncounted.contains(&machine.profile.machine) && standing(state, machine)
        };
        let fold = apply_stale_roster_window(
            entries,
            fold_authority_log_once(
                entries,
                FoldContext {
                    machine_standing: &counted,
                    ..context
                },
                local.handoff_candidates,
            ),
            first_seen_at_secs,
            now_secs,
            stale_roster_window_secs,
        );
        let now_uncounted: BTreeSet<_> = fold
            .machines
            .iter()
            .filter(|(_, machine)| machine.stale || machine.admitter_unsettled)
            .map(|(id, _)| *id)
            .collect();
        if fold.worlds.is_empty() || now_uncounted.is_subset(&uncounted) {
            break fold;
        }
        uncounted = now_uncounted;
    };
    fold.append_heads = super::world_privacy::main_log_heads(entries, &fold.valid_entries);
    for entry in entries {
        // Advance beyond even a signed rejected local entry. A new local write
        // never reuses a sequence, though independently received siblings may.
        fold.append_sequences
            .entry(entry.signer.public_key.clone())
            .and_modify(|seq| *seq = (*seq).max(entry.seq))
            .or_insert(entry.seq);
    }
    fold
}

/// [`fold_authority_log`] as an install that counts only some of the
/// machines the roster rule admits.
#[cfg(test)]
pub(super) fn fold_authority_log_with_machine_standing(
    entries: &[AuthorityLogEntry],
    standing: super::world_privacy::MachineStanding<'_>,
) -> AuthorityFold {
    super::fold_engine::fold_authority_log_inner(
        entries,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        folded_device_can_authority_consent,
        FoldLocalInputs {
            machine_standing: Some(standing),
            ..FoldLocalInputs::VAULT_DOOR
        },
    )
}

/// The rows a vouch never widens (the Engine's ruling on Sol P2 round 17).
/// The install effect of every machine revision and world edit comes from
/// the fold with no vouch at all, which runs its own handoff probes and
/// pre-handoff permissions; the vouch decides only which handoffs stand and
/// what the roster view shows. When this fold settles handoffs whose lines
/// hold a row a floor would refuse, every row that fold holds back lands
/// restriction only here too, and so does every machine revision or world
/// edit only the vouch admits that no candidate handoff precedes. A fresh
/// revision after a handoff still counts. With no such row in those lines
/// the vouch changes nothing, and nothing is held.
fn held_without_vouch(
    entries: &[AuthorityLogEntry],
    first_seen_at_secs: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    peer_consent_roots: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    consent_arm: fn(&FoldedDevice) -> bool,
    local: FoldLocalInputs<'_>,
) -> BTreeSet<AuthorityEntryHash> {
    let (Some(observations), Some(handoffs)) = (local.observations, local.handoff_candidates)
    else {
        return BTreeSet::new();
    };
    if observations.unvouched || observations.vouched.is_empty() {
        return BTreeSet::new();
    }
    let by_hash: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|entry| authority_entry_hash(entry).ok().map(|hash| (hash, entry)))
        .collect();
    // Only a row a floor would refuse needs the vouch.
    let rescues = observations.vouched.iter().any(|hash| {
        by_hash
            .get(hash)
            .zip(observations.sequence_floors.get(hash))
            .is_some_and(|(entry, floor)| {
                entry.seq < *floor && !super::entry_transition::lands_restriction_only(&entry.op)
            })
    });
    if !rescues {
        return BTreeSet::new();
    }
    let unvouched = observations.without_vouch();
    let fold = super::fold_engine::fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        now_secs,
        peer_consent_roots,
        consent_arm,
        FoldLocalInputs {
            observations: Some(&unvouched),
            retire_device_ops: true,
            pre_handoff_entries: None,
            handoff_candidates: None,
            ..local
        },
    );
    let after = after_handoffs(&by_hash, handoffs);
    let mut held = fold.held_back;
    held.extend(
        by_hash
            .iter()
            .filter(|(hash, entry)| {
                super::entry_transition::lands_restriction_only(&entry.op)
                    && !fold.valid_entries.contains(*hash)
                    && !after.contains(*hash)
            })
            .map(|(hash, _)| *hash),
    );
    held
}

/// The rows a handoff in `handoffs` precedes.
fn after_handoffs(
    by_hash: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    handoffs: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    let mut children = BTreeMap::<_, Vec<_>>::new();
    for (hash, entry) in by_hash {
        for parent in &entry.parent_hashes {
            children.entry(*parent).or_default().push(*hash);
        }
    }
    let mut after = BTreeSet::new();
    let mut stack: Vec<_> = handoffs.iter().copied().collect();
    while let Some(hash) = stack.pop() {
        for child in children.get(&hash).into_iter().flatten() {
            if after.insert(*child) {
                stack.push(*child);
            }
        }
    }
    after
}

/// The machine revisions and world edits `state` holds back on this install.
pub(super) fn held_back(state: &FoldState) -> BTreeSet<AuthorityEntryHash> {
    let mut held = BTreeSet::new();
    super::machine_profile::held_revisions(state, &mut held);
    super::world_privacy::held_edits(state, &mut held);
    held
}
