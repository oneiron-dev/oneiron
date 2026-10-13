//! Folds `WorldPrivacy` edits into each world's effective settings.
//!
//! Per world the fold keeps a multi-value register over the authority DAG:
//! the edits no later edit of that world has seen. An accepted edit supersedes
//! every live edit its parents carry, widening included, because the owner
//! saw them. A merge keeps the union of live edits minus the union of
//! superseded ones, so concurrent edits stay side by side and the effective
//! value is their meet: stricter wins (DEC-0005), never last-writer-wins. Two
//! one-machine picks naming different machines meet in a conflicted state that
//! is readable nowhere until the owner re-picks.
//!
//! An edit by a machine that is no longer the owner's counts at full strength
//! only if the revision that took "yours" away had seen it. One it never saw
//! raced the demotion (a stolen laptop widening a world offline) and counts
//! only as its meet with the settings it replaced.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::machine_profile::derived_machine;
use super::*;

/// Where a world may be read, after every live edit is met.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveRead {
    Everywhere,
    MyMachines,
    OneMachine(EntityId),
    /// Concurrent one-machine picks named different machines: readable
    /// nowhere until the owner re-picks from one of them.
    Conflicted {
        contenders: BTreeSet<EntityId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveModelOrder {
    Inherit,
    Ordered(Vec<String>),
    /// Concurrent edits named different orders.
    Conflicted,
}

/// One world's settings as the fold decides them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EffectiveWorldPrivacy {
    pub read: EffectiveRead,
    pub sealed: SealedCopies,
    pub models: EffectiveModelOrder,
}

impl Default for EffectiveWorldPrivacy {
    fn default() -> Self {
        PrivacyMeet::of(&WorldPrivacy::default()).effective()
    }
}

/// A machine a world's rows may go to, or one nobody proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Machine(EntityId),
    Unknown,
}

/// One world's folded settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedWorld {
    /// Each live edit and the machine that signed it.
    pub live: BTreeMap<AuthorityEntryHash, EntityId>,
    pub effective: EffectiveWorldPrivacy,
}

impl AuthorityFold {
    /// A world's effective settings; the default for a world nobody edited.
    #[must_use]
    pub fn world_privacy(&self, world: EntityId) -> EffectiveWorldPrivacy {
        self.worlds
            .get(&world)
            .map_or_else(EffectiveWorldPrivacy::default, |folded| {
                folded.effective.clone()
            })
    }

    /// Whether `world` may be readable on `destination`. A machine without a
    /// live profile is an unknown destination.
    #[must_use]
    pub fn world_readable_on(&self, world: EntityId, destination: Destination) -> bool {
        let is_mine = |machine: EntityId| self.machine(machine).is_some_and(FoldedMachine::is_mine);
        readable(&self.world_privacy(world).read, destination, is_mine)
    }

    /// Every edited world that may not be readable on `destination`.
    #[must_use]
    pub fn worlds_withheld_from(&self, destination: Destination) -> BTreeSet<EntityId> {
        self.worlds
            .keys()
            .copied()
            .filter(|world| !self.world_readable_on(*world, destination))
            .collect()
    }
}

fn readable(
    read: &EffectiveRead,
    destination: Destination,
    is_mine: impl Fn(EntityId) -> bool,
) -> bool {
    let machine = match destination {
        Destination::Machine(machine) if is_mine(machine) => Some(machine),
        _ => None,
    };
    match read {
        EffectiveRead::Everywhere => true,
        EffectiveRead::MyMachines => machine.is_some(),
        EffectiveRead::OneMachine(only) => machine == Some(*only),
        EffectiveRead::Conflicted { .. } => false,
    }
}

/// The settings lattice one edit, or a meet of edits, stands for. Each part
/// meets on its own (intersection, or, union, min, equality), so the meet is
/// commutative, associative and idempotent in every grouping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PrivacyMeet {
    /// `None`: no machine named. `Some`: the machines every one-machine pick
    /// in the meet names, empty once two picks disagree.
    named: Option<BTreeSet<EntityId>>,
    /// Some edit in the meet keeps the world on the owner's machines.
    mine_only: bool,
    /// Every machine any one-machine pick in the meet named.
    contenders: BTreeSet<EntityId>,
    sealed: SealedCopies,
    models: EffectiveModelOrder,
}

impl PrivacyMeet {
    fn of(settings: &WorldPrivacy) -> Self {
        let (named, mine_only) = match settings.read {
            ReadLocation::OneMachine(machine) => (Some(BTreeSet::from([machine])), false),
            ReadLocation::MyMachines => (None, true),
            ReadLocation::Everywhere => (None, false),
        };
        Self {
            contenders: named.clone().unwrap_or_default(),
            named,
            mine_only,
            sealed: settings.sealed,
            models: match &settings.models {
                ModelOrder::Inherit => EffectiveModelOrder::Inherit,
                ModelOrder::Ordered(routes) => EffectiveModelOrder::Ordered(routes.clone()),
            },
        }
    }

    fn meet(&self, other: &Self) -> Self {
        Self {
            named: match (&self.named, &other.named) {
                (None, named) | (named, None) => named.clone(),
                (Some(left), Some(right)) => Some(left.intersection(right).copied().collect()),
            },
            mine_only: self.mine_only || other.mine_only,
            contenders: self.contenders.union(&other.contenders).copied().collect(),
            sealed: self.sealed.min(other.sealed),
            models: if self.models == other.models {
                self.models.clone()
            } else {
                EffectiveModelOrder::Conflicted
            },
        }
    }

    fn effective(&self) -> EffectiveWorldPrivacy {
        let read = match &self.named {
            None if self.mine_only => EffectiveRead::MyMachines,
            None => EffectiveRead::Everywhere,
            Some(named) => match named.iter().next() {
                Some(only) if named.len() == 1 => EffectiveRead::OneMachine(*only),
                _ => EffectiveRead::Conflicted {
                    contenders: self.contenders.clone(),
                },
            },
        };
        EffectiveWorldPrivacy {
            read,
            sealed: self.sealed,
            models: self.models.clone(),
        }
    }
}

/// One accepted edit no later edit of its world has seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FrontierEdit {
    settings: WorldPrivacy,
    machine: EntityId,
    /// The world's settings at the edit's parents, which it replaced.
    prior: PrivacyMeet,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct WorldFrontier {
    live: BTreeMap<AuthorityEntryHash, FrontierEdit>,
    superseded: BTreeSet<AuthorityEntryHash>,
}

pub(super) fn merge_world_frontiers(
    merged: &mut BTreeMap<EntityId, WorldFrontier>,
    right: &BTreeMap<EntityId, WorldFrontier>,
) {
    for (world, frontier) in right {
        let into = merged.entry(*world).or_default();
        into.superseded.extend(frontier.superseded.iter().copied());
        for (hash, edit) in &frontier.live {
            into.live.entry(*hash).or_insert_with(|| edit.clone());
        }
        let superseded = &into.superseded;
        into.live.retain(|hash, _| !superseded.contains(hash));
    }
}

fn is_mine(state: &FoldState, machine: EntityId) -> bool {
    derived_machine(state, machine).is_some_and(|folded| folded.is_mine())
}

/// What one live edit contributes. Full strength while its machine is the
/// owner's, or when the revision that took that away had seen it; otherwise
/// it raced the demotion and only narrows what it replaced.
fn contribution(state: &FoldState, hash: &AuthorityEntryHash, edit: &FrontierEdit) -> PrivacyMeet {
    let own = PrivacyMeet::of(&edit.settings);
    let seen_by_demotion = derived_machine(state, edit.machine).is_some_and(|folded| {
        folded.is_mine()
            || (!folded.conflicted
                && folded.profile.seen_world_edits.contains(hash)
                && (!folded.removed || folded.profile.role == MachineRole::Removed))
    });
    if seen_by_demotion {
        own
    } else {
        own.meet(&edit.prior)
    }
}

fn world_meet(state: &FoldState, world: EntityId) -> PrivacyMeet {
    let mut contributions = state.worlds.get(&world).into_iter().flat_map(|frontier| {
        frontier
            .live
            .iter()
            .map(|(hash, edit)| contribution(state, hash, edit))
    });
    let first = contributions
        .next()
        .unwrap_or_else(|| PrivacyMeet::of(&WorldPrivacy::default()));
    contributions.fold(first, |meet, next| meet.meet(&next))
}

/// A machine edits a world only while it is the owner's and holds the world,
/// or while it is one of a conflict's contenders, which is how the owner
/// re-picks.
fn may_edit(state: &FoldState, machine: EntityId, world: EntityId) -> bool {
    if !is_mine(state, machine) {
        return false;
    }
    let read = world_meet(state, world).effective().read;
    match &read {
        EffectiveRead::Conflicted { contenders } => contenders.contains(&machine),
        _ => readable(&read, Destination::Machine(machine), |id| {
            is_mine(state, id)
        }),
    }
}

/// The `WorldPrivacy` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster check:
/// its signer is a machine's install key, never a roster key.
pub(super) fn apply_world_privacy(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    edit: &WorldPrivacyEdit,
    hash: AuthorityEntryHash,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() || edit.world == crate::claim::base_world_id() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    if !derived_machine(state, edit.machine).is_some_and(|folded| {
        folded.is_mine() && *signer == AuthorityKey::Ed25519(folded.profile.machine_key)
    }) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    if let ReadLocation::OneMachine(target) = edit.settings.read
        && !is_mine(state, target)
    {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    // Well signed but from a machine that cannot edit this world: valid and
    // without effect, so it never stalls what descends from it.
    if !may_edit(state, edit.machine, edit.world) {
        state.refused_world_edits.insert(hash);
        return Ok(());
    }
    let prior = world_meet(state, edit.world);
    let frontier = state.worlds.entry(edit.world).or_default();
    let seen = std::mem::take(&mut frontier.live);
    frontier.superseded.extend(seen.into_keys());
    frontier.live.insert(
        hash,
        FrontierEdit {
            settings: edit.settings.clone(),
            machine: edit.machine,
            prior,
        },
    );
    Ok(())
}

/// The fold's public view of every edited world.
pub(super) fn folded_worlds(state: &FoldState) -> BTreeMap<EntityId, FoldedWorld> {
    state
        .worlds
        .iter()
        .map(|(world, frontier)| {
            (
                *world,
                FoldedWorld {
                    live: frontier
                        .live
                        .iter()
                        .map(|(hash, edit)| (*hash, edit.machine))
                        .collect(),
                    effective: world_meet(state, *world).effective(),
                },
            )
        })
        .collect()
}

/// Entries that break the side branch: anything but a later edit of the same
/// world naming a world edit as its parent. A replica that may not hold a
/// world never receives its edits, so nothing else may depend on them.
pub(super) fn side_branch_violations(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> BTreeSet<AuthorityEntryHash> {
    let world_of = |entry: &AuthorityLogEntry| match &entry.op {
        AuthorityOp::WorldPrivacy(edit) => Some(edit.world),
        _ => None,
    };
    by_hash
        .iter()
        .filter(|(_, entry)| {
            entry.parent_hashes.iter().any(|parent| {
                by_hash
                    .get(parent)
                    .and_then(world_of)
                    .is_some_and(|parent_world| world_of(entry) != Some(parent_world))
            })
        })
        .map(|(hash, _)| *hash)
        .collect()
}

/// The append heads a new main-log entry takes as parents: valid entries no
/// valid main-log entry names. World edits never join them, and naming a
/// main-log entry as a parent does not retire it as a head.
pub(super) fn main_log_heads(
    entries: &[AuthorityLogEntry],
    valid: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    let mut heads = BTreeSet::new();
    let mut named = BTreeSet::new();
    for entry in entries {
        if matches!(entry.op, AuthorityOp::WorldPrivacy(_)) {
            continue;
        }
        let Ok(hash) = authority_entry_hash(entry) else {
            continue;
        };
        if valid.contains(&hash) {
            heads.insert(hash);
            named.extend(entry.parent_hashes.iter().copied());
        }
    }
    heads.retain(|hash| !named.contains(hash));
    heads
}

/// The live world edits `machine` signed: what a new profile revision lists
/// as seen, capped at the codec's limit (an unlisted edit only counts
/// stricter).
pub(super) fn live_edits_by(
    fold: &AuthorityFold,
    machine: EntityId,
) -> BTreeSet<AuthorityEntryHash> {
    fold.worlds
        .values()
        .flat_map(|world| world.live.iter())
        .filter(|(_, signer)| **signer == machine)
        .map(|(hash, _)| *hash)
        .take(MACHINE_SEEN_WORLD_EDITS_MAX)
        .collect()
}
