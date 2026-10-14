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
    let context = FoldContext {
        sequence_floors,
        floor_vouched: local.observations.map(|observations| &observations.vouched),
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
