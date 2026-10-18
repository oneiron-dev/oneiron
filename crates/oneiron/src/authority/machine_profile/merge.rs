//! How a machine's chains merge across branches: a higher revision
//! supersedes, divergent profiles at one revision poison, and a removal on
//! any branch is terminal.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::*;

/// Higher revision wins; divergent content at one revision is poison carried
/// by the byte-wise smaller profile, so the merge is the same in every order.
/// A strictly higher revision clears that poison, as it does for actor
/// bindings; a removal never clears.
pub(in crate::authority) fn merge_machine(
    left: &MachineRevision,
    right: &MachineRevision,
) -> MachineRevision {
    let mut merged = match left.profile.revision.cmp(&right.profile.revision) {
        Ordering::Greater => left.clone(),
        Ordering::Less => right.clone(),
        Ordering::Equal if left.profile == right.profile => MachineRevision {
            conflicted: left.conflicted || right.conflicted,
            ..left.clone().min_by_entry(right)
        },
        Ordering::Equal if left.profile < right.profile => MachineRevision {
            conflicted: true,
            ..left.clone()
        },
        Ordering::Equal => MachineRevision {
            conflicted: true,
            ..right.clone()
        },
    };
    merged.removed = left.removed || right.removed;
    merged
}

fn merge_chain(left: &MachineChain, right: &MachineChain) -> MachineChain {
    let mut owner_held_removals = left.owner_held_removals.clone();
    for (signer, removal) in &right.owner_held_removals {
        add_removal(&mut owner_held_removals, signer, removal);
    }
    MachineChain {
        head: merge_machine(&left.head, &right.head),
        owner_held: match (&left.owner_held, &right.owner_held) {
            (Some(left), Some(right)) => Some(merge_machine(left, right)),
            (one, other) => one.clone().or_else(|| other.clone()),
        },
        owner_held_removals,
        revisions: crate::authority::machine_standing::merge_revisions(
            &left.revisions,
            &right.revisions,
        ),
    }
}

/// Records `signer`'s removal, merged with any it signed before.
pub(super) fn add_removal(
    removals: &mut BTreeMap<AuthorityKey, MachineRevision>,
    signer: &AuthorityKey,
    removal: &MachineRevision,
) {
    let merged = match removals.get(signer) {
        Some(earlier) => merge_machine(earlier, removal),
        None => removal.clone(),
    };
    removals.insert(signer.clone(), merged);
}

fn join_chains(
    into: &mut BTreeMap<MachineAdmitter, MachineChain>,
    chains: &BTreeMap<MachineAdmitter, MachineChain>,
) {
    for (admitter, chain) in chains {
        match into.get_mut(admitter) {
            Some(existing) => *existing = merge_chain(existing, chain),
            None => {
                into.insert(*admitter, chain.clone());
            }
        }
    }
}

/// Joins one machine's chain from another state into `state`.
pub(in crate::authority) fn merge_machine_chain(
    state: &mut FoldState,
    machine: EntityId,
    admitter: MachineAdmitter,
    chain: &MachineChain,
) {
    join_chains(
        state.machines.entry(machine).or_default(),
        &BTreeMap::from([(admitter, chain.clone())]),
    );
}

pub(in crate::authority) fn merge_machine_maps(
    merged: &mut BTreeMap<EntityId, BTreeMap<MachineAdmitter, MachineChain>>,
    keys: &mut BTreeMap<[u8; 32], BTreeSet<KeyClaim>>,
    right: &FoldState,
) {
    for (machine, chains) in &right.machines {
        join_chains(merged.entry(*machine).or_default(), chains);
    }
    for (key, claims) in &right.machine_keys {
        keys.entry(*key).or_default().extend(claims.iter().cloned());
    }
}
