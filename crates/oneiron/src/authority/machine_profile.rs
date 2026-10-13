//! Folds `MachineProfile` entries into each physical machine's standing.
//!
//! A machine's standing is the owner's answer at the pairing ceremony, signed
//! by an owner roster key. It merges across branches as actor bindings do: a
//! higher revision supersedes, divergent profiles at one revision poison the
//! machine, and a removal on any branch is terminal. Liveness is derived, never
//! stored, so the facts that poison a machine (a shared key, an actor binding
//! to its row) apply in every arrival order.
//!
//! Revisions form one chain per admitter and supersede only their own chain.
//! The roster is the only admitter here; an owner anchor adds its own chain.
//! Each revision keeps whose authority signed it, and each chain keeps its
//! highest owner-held revision, which a custodian's later demote or removal
//! never erases.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::*;

/// Who admitted a chain of a machine's revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MachineAdmitter {
    /// The vault's roster, under the owner-held rule for an owned mark.
    Roster,
}

/// Whose authority signed a revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignerClass {
    /// A key the owner holds.
    OwnerHeld,
    /// A cloud root, or a key in the host's custody on a hosted vault: it
    /// registers, demotes or removes, and never answers for the owner.
    Custodial,
}

/// One machine's folded standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedMachine {
    pub profile: MachineProfile,
    /// Divergent profiles at one revision, a machine key claimed by two
    /// machines, or a row that is also an actor: never live.
    pub conflicted: bool,
    /// A `Removed` revision folded on some branch. Terminal.
    pub removed: bool,
    /// The winning revision rests on a roster key revoked since, past the
    /// stale-roster window, and no key still on the roster signed it again:
    /// not live on this install.
    pub stale: bool,
    /// The roster key that signed the revision, and its class.
    pub signer: AuthorityKey,
    pub signer_class: SignerClass,
    /// The authority-log entry that carried the revision.
    pub entry: AuthorityEntryHash,
}

/// One admitter's revisions of one machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MachineChain {
    pub(super) head: FoldedMachine,
    /// The highest revision an owner-held key signed.
    pub(super) owner_held: Option<FoldedMachine>,
}

impl FoldedMachine {
    /// Of two entries carrying one revision, the smaller entry speaks for it.
    fn min_by_entry(self, other: &Self) -> Self {
        if other.entry < self.entry {
            other.clone()
        } else {
            self
        }
    }

    #[must_use]
    pub fn is_live(&self) -> bool {
        !self.conflicted && !self.removed && !self.stale
    }

    /// Mine only by the owner's explicit `Yours`, and only while live.
    #[must_use]
    pub fn is_mine(&self) -> bool {
        self.is_live() && self.profile.says_mine()
    }
}

impl AuthorityFold {
    /// The folded standing of one MACHINE row, if the owner ever profiled it.
    #[must_use]
    pub fn machine(&self, machine: EntityId) -> Option<&FoldedMachine> {
        self.machines.get(&machine)
    }

    /// The live machine whose install key is `machine_key`.
    #[must_use]
    pub fn live_machine_by_key(&self, machine_key: &[u8; 32]) -> Option<&FoldedMachine> {
        self.machines
            .values()
            .find(|machine| machine.is_live() && &machine.profile.machine_key == machine_key)
    }
}

/// One fold transition, signed by an owner roster key, for a machine that is
/// not an actor and whose key is not authority. Only an owner-held key answers
/// "yours", "work/school" or "rented": a cloud or custodial root, which the
/// hosted posture lets consent, can register its own node or demote and remove
/// a machine, but never vouch for a machine as the owner's. Neither can the
/// host's own root on a hosted vault, whatever its role labels say.
pub(super) fn apply_machine_profile(
    state: &mut FoldState,
    signer: &AuthorityKey,
    profile: &MachineProfile,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let Some(device) = state
        .roster
        .get(signer)
        .filter(|device| device.roles & ROLE_OWNER != 0)
    else {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    };
    let signer_class = if folded_device_can_authority_consent(device)
        && !custodial_host_root(state, signer, context)
    {
        SignerClass::OwnerHeld
    } else {
        SignerClass::Custodial
    };
    let admitted = match profile.role {
        MachineRole::Owned(_) => signer_class == SignerClass::OwnerHeld,
        MachineRole::HostedNode | MachineRole::ExecutionNode | MachineRole::Removed => {
            context.device_can_consent(device)
        }
    };
    if !admitted {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    let head = roster_chain(state, profile.machine).map(|chain| &chain.head);
    if key_is_authority(state, &profile.machine_key)
        || machine_is_actor(state, profile.machine)
        || !profile.proof_verifies(&state.vault_id)
        || head.is_some_and(|folded| profile.revision <= folded.profile.revision)
    {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let folded = FoldedMachine {
        profile: profile.clone(),
        conflicted: false,
        removed: profile.role == MachineRole::Removed || head.is_some_and(|folded| folded.removed),
        stale: false,
        signer: signer.clone(),
        signer_class,
        entry: hash,
    };
    let chains = state.machines.entry(profile.machine).or_default();
    let owner_held = match chains.remove(&MachineAdmitter::Roster) {
        _ if signer_class == SignerClass::OwnerHeld => Some(folded.clone()),
        Some(chain) => chain.owner_held,
        None => None,
    };
    chains.insert(
        MachineAdmitter::Roster,
        MachineChain {
            head: folded,
            owner_held,
        },
    );
    state
        .machine_keys
        .entry(profile.machine_key)
        .or_default()
        .insert(profile.machine);
    Ok(())
}

/// A key in the host's custody on a hosted vault, where the host's root is
/// the provider's key and not the owner's: that root, or any key it admitted
/// directly or through another custodial key. Judged from provenance and the
/// vault's posture, so a key labelled owner-held still counts.
fn custodial_host_root(state: &FoldState, signer: &AuthorityKey, context: FoldContext<'_>) -> bool {
    context.hosted && state.host_custody_keys.contains(signer)
}

fn roster_chain(state: &FoldState, machine: EntityId) -> Option<&MachineChain> {
    state.machines.get(&machine)?.get(&MachineAdmitter::Roster)
}

/// An install key that is also a roster key or an actor's key is no machine's.
fn key_is_authority(state: &FoldState, machine_key: &[u8; 32]) -> bool {
    let key = AuthorityKey::Ed25519(*machine_key);
    state.roster.contains_key(&key) || state.actor_bindings.contains_key(&key)
}

/// A row any accepted binding ever named, on any branch, is an actor's.
fn machine_is_actor(state: &FoldState, machine: EntityId) -> bool {
    state.actor_rows.contains(&machine)
}

/// Higher revision wins; divergent content at one revision is poison carried
/// by the byte-wise smaller profile, so the merge is the same in every order.
/// A strictly higher revision clears that poison, as it does for actor
/// bindings; a removal never clears.
pub(super) fn merge_machine(left: &FoldedMachine, right: &FoldedMachine) -> FoldedMachine {
    let mut merged = match left.profile.revision.cmp(&right.profile.revision) {
        Ordering::Greater => left.clone(),
        Ordering::Less => right.clone(),
        Ordering::Equal if left.profile == right.profile => FoldedMachine {
            conflicted: left.conflicted || right.conflicted,
            ..left.clone().min_by_entry(right)
        },
        Ordering::Equal if left.profile < right.profile => FoldedMachine {
            conflicted: true,
            ..left.clone()
        },
        Ordering::Equal => FoldedMachine {
            conflicted: true,
            ..right.clone()
        },
    };
    merged.removed = left.removed || right.removed;
    merged
}

fn merge_chain(left: &MachineChain, right: &MachineChain) -> MachineChain {
    MachineChain {
        head: merge_machine(&left.head, &right.head),
        owner_held: match (&left.owner_held, &right.owner_held) {
            (Some(left), Some(right)) => Some(merge_machine(left, right)),
            (one, other) => one.clone().or_else(|| other.clone()),
        },
    }
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

/// Joins one machine's chains from another state into `state`.
pub(super) fn merge_machine_chains(
    state: &mut FoldState,
    machine: EntityId,
    chains: &BTreeMap<MachineAdmitter, MachineChain>,
) {
    join_chains(state.machines.entry(machine).or_default(), chains);
}

pub(super) fn merge_machine_maps(
    merged: &mut BTreeMap<EntityId, BTreeMap<MachineAdmitter, MachineChain>>,
    keys: &mut BTreeMap<[u8; 32], BTreeSet<EntityId>>,
    right: &FoldState,
) {
    for (machine, chains) in &right.machines {
        join_chains(merged.entry(*machine).or_default(), chains);
    }
    for (key, machines) in &right.machine_keys {
        keys.entry(*key)
            .or_default()
            .extend(machines.iter().copied());
    }
}

/// One machine with the derived poison applied: branches that never saw each
/// other may have given its key to two machines, or made its key or row an
/// actor's. Every reader of a machine's standing goes through this.
pub(super) fn derived_machine(state: &FoldState, id: EntityId) -> Option<FoldedMachine> {
    let mut folded = roster_chain(state, id)?.head.clone();
    let shared_key = state
        .machine_keys
        .get(&folded.profile.machine_key)
        .is_some_and(|machines| machines.len() > 1);
    folded.conflicted |= shared_key
        || key_is_authority(state, &folded.profile.machine_key)
        || machine_is_actor(state, id);
    Some(folded)
}

/// The fold's public view: each machine with the derived poison applied.
pub(super) fn folded_machines(state: &FoldState) -> BTreeMap<EntityId, FoldedMachine> {
    state
        .machines
        .keys()
        .filter_map(|id| derived_machine(state, *id).map(|folded| (*id, folded)))
        .collect()
}
