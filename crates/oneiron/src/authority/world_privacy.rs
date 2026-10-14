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
//! raced the demotion (a stolen laptop widening a world offline) and only
//! narrows: it counts as its meet with every edit it replaced, each judged the
//! same way in the current state, so a chain of raced widens never widens. So
//! does an edit whose machine the roster rule admits but this install does
//! not count: losing standing never widens a world.
//!
//! Which edits stand is judged on the meet the roster rule alone gives, the
//! same on every install. This install's counting makes the settings it reads
//! stricter and never decides who may edit: a stricter meet can name more
//! contenders, and a contender may edit (Sol P2 round 4, F1).
//!
//! A world whose read names no machine still the owner's is orphaned: any
//! machine of the owner's that stores it may re-pick it. A re-pick only makes
//! the world editable again; bringing its rows back is a restore's job.
//! Whether a world is orphaned is judged by the roster rule too, so a holder
//! stale on one install keeps its world until the owner removes or re-marks
//! it.
//!
//! An edit is valid when some chain of its machine's revisions admits the
//! machine as the owner's under the key that signed it: each admitter vouches
//! on its own.
//!
//! Under a conflicted vault root no world's settings can be known, so every
//! world reads as readable nowhere and the withheld set cannot be named.
//!
//! Edits are per-world side entries. An entry for world W takes as parents
//! the rows its standing rests on (from a machine holding W, its own and a
//! one-machine target's head revisions; for a W readable nowhere, the
//! main-log heads) and W's live edits. It is never a parent of a main-log
//! entry or of another world's entry, so a replica that may not hold W folds
//! the main log without W's entries.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::machine_profile::{
    acknowledged, counted_machine, derived_chains, derived_machine, mark_past,
};
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

impl EffectiveWorldPrivacy {
    /// Any world under a conflicted vault root: readable nowhere, editable by
    /// no one, with no sealed copies and no model order.
    fn unknowable() -> Self {
        Self {
            read: EffectiveRead::Conflicted {
                contenders: BTreeSet::new(),
            },
            sealed: SealedCopies::Off,
            models: EffectiveModelOrder::Conflicted,
        }
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
    /// The read the roster rule alone gives, the same on every install. Who
    /// may edit the world is judged on it, never on `effective`.
    pub roster_read: EffectiveRead,
}

impl AuthorityFold {
    /// A world's effective settings; the default for a world nobody edited.
    /// A conflicted vault root fails closed: no world is readable anywhere.
    #[must_use]
    pub fn world_privacy(&self, world: EntityId) -> EffectiveWorldPrivacy {
        if self.vault_root_is_conflicted() {
            return EffectiveWorldPrivacy::unknowable();
        }
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

    /// Every edited world that may not be readable on `destination`. Refused
    /// under a conflicted vault root, whose fold names no world: an empty set
    /// there would let every private world go.
    pub fn worlds_withheld_from(&self, destination: Destination) -> Result<BTreeSet<EntityId>> {
        if self.vault_root_is_conflicted() {
            return Err(invalid_authority());
        }
        Ok(self
            .worlds
            .keys()
            .copied()
            .filter(|world| !self.world_readable_on(*world, destination))
            .collect())
    }
}

/// How a machine of the owner's comes to edit a world, judged on the world's
/// effective read at the edit's parents. The door and the fold ask this one
/// rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldEditStanding {
    /// The world is readable on the machine.
    Holds,
    /// The machine is one of a conflict's contenders.
    Contends,
    /// No machine the world's read names is still the owner's.
    RepicksOrphan,
}

impl AuthorityFold {
    /// How `machine` may edit `world` now, or `None` when it may not.
    #[must_use]
    pub fn world_edit_standing(
        &self,
        machine: EntityId,
        world: EntityId,
    ) -> Option<WorldEditStanding> {
        edit_standing(
            &self.world_roster_read(world),
            machine,
            |id| self.machine(id).is_some_and(FoldedMachine::is_mine),
            |id| self.machine(id).is_some_and(mine_by_roster),
        )
    }

    /// The read the roster rule alone gives `world`, which decides who may
    /// edit it. A conflicted vault root fails closed, as for the settings.
    #[must_use]
    pub fn world_roster_read(&self, world: EntityId) -> EffectiveRead {
        if self.vault_root_is_conflicted() {
            return EffectiveWorldPrivacy::unknowable().read;
        }
        self.worlds.get(&world).map_or_else(
            || EffectiveWorldPrivacy::default().read,
            |folded| folded.roster_read.clone(),
        )
    }
}

/// Mine by the roster rule alone, as the fold judges standing at an edit's
/// parents. This install's own projections (a revision gone stale here, a
/// roster with no settled root) weaken an edit; they never decide whether it
/// stands, so every install keeps the same edits, and a machine losing its
/// standing here never turns a refused edit into an accepted one (Sol P2
/// round 3, F1).
pub(super) fn mine_by_roster(folded: &FoldedMachine) -> bool {
    FoldedMachine {
        stale: false,
        admitter_unsettled: false,
        floor_held: false,
        ..folded.clone()
    }
    .is_mine()
}

/// `read` is the roster rule's. `is_mine` judges the editor, `named_mine` the
/// machines the read names, both by the roster rule in the fold. The door
/// judges its own machine as this install counts it, which only refuses more.
fn edit_standing(
    read: &EffectiveRead,
    machine: EntityId,
    is_mine: impl Fn(EntityId) -> bool,
    named_mine: impl Fn(EntityId) -> bool,
) -> Option<WorldEditStanding> {
    if !is_mine(machine) {
        return None;
    }
    if readable(read, Destination::Machine(machine), &is_mine) {
        return Some(WorldEditStanding::Holds);
    }
    match read {
        EffectiveRead::Conflicted { contenders } if contenders.contains(&machine) => {
            Some(WorldEditStanding::Contends)
        }
        _ if !orphaned_from(read, named_mine).is_empty() => Some(WorldEditStanding::RepicksOrphan),
        _ => None,
    }
}

/// The machines `read` names when none of them is still the owner's; empty
/// when the world is not orphaned.
pub(super) fn orphaned_from(
    read: &EffectiveRead,
    is_mine: impl Fn(EntityId) -> bool,
) -> BTreeSet<EntityId> {
    let named = match read {
        EffectiveRead::OneMachine(machine) => BTreeSet::from([*machine]),
        EffectiveRead::Conflicted { contenders } => contenders.clone(),
        EffectiveRead::Everywhere | EffectiveRead::MyMachines => return BTreeSet::new(),
    };
    if named.iter().any(|machine| is_mine(*machine)) {
        BTreeSet::new()
    } else {
        named
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

/// Whether this install counts a machine the roster rule admits as the
/// owner's. Every one today; an owner anchor narrows it per install.
pub(super) type MachineStanding<'a> = &'a dyn Fn(&FoldState, &FoldedMachine) -> bool;

pub(super) fn every_admitted_machine(_: &FoldState, _: &FoldedMachine) -> bool {
    true
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

    /// The meet `effective` reads back as.
    fn of_effective(effective: &EffectiveWorldPrivacy) -> Self {
        let (named, mine_only, contenders) = match &effective.read {
            EffectiveRead::Everywhere => (None, false, BTreeSet::new()),
            EffectiveRead::MyMachines => (None, true, BTreeSet::new()),
            EffectiveRead::OneMachine(machine) => (
                Some(BTreeSet::from([*machine])),
                false,
                BTreeSet::from([*machine]),
            ),
            EffectiveRead::Conflicted { contenders } => {
                (Some(BTreeSet::new()), false, contenders.clone())
            }
        };
        Self {
            named,
            mine_only,
            contenders,
            sealed: effective.sealed,
            models: effective.models.clone(),
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

/// Whose counting a world's meet follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Counting {
    /// The roster rule alone, the same on every install: which edits stand.
    Roster,
    /// This install's, which only weakens: the settings this install reads.
    Install,
}

/// One accepted edit of a world.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct FrontierEdit {
    settings: WorldPrivacy,
    machine: EntityId,
    /// The live edits at the edit's parents, which it replaced.
    replaced: BTreeSet<AuthorityEntryHash>,
    /// This install did not count the machine at the edit's parents.
    narrow_only: bool,
    /// The machine's "yours" revision the edit was signed under.
    mark: AuthorityEntryHash,
    /// The machine's revisions in its mark's own past.
    prior: Arc<BTreeSet<AuthorityEntryHash>>,
    /// A later row of its signer reached this replica first, so it landed as
    /// restriction only: it never counts at full strength (Astra #1430).
    restriction_only: bool,
    /// Two copies of it disagreed on its mark, past or what it replaced: it
    /// never counts at full strength, it meets the default as well (Sol P2
    /// round 11), and no machine may edit its world (`roster_read`).
    disputed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct WorldFrontier {
    /// The edits no later edit of the world has seen.
    live: BTreeMap<AuthorityEntryHash, Arc<FrontierEdit>>,
    /// Every edit a later edit replaced, kept so an edit that only narrows
    /// is judged against what it replaced.
    superseded: BTreeMap<AuthorityEntryHash, Arc<FrontierEdit>>,
}

impl FrontierEdit {
    /// One edit folded twice (past a floor on one replica's pass, or crossed
    /// on another) keeps what both copies grant: either copy's restriction,
    /// what either replaced, the past both saw, and no full strength when
    /// they disagree on anything else. Order-free (Sol P2 rounds 10-11).
    fn meet(left: &Arc<Self>, right: &Arc<Self>) -> Arc<Self> {
        if Arc::ptr_eq(left, right) || left == right {
            return Arc::clone(left);
        }
        Arc::new(Self {
            settings: left.settings.clone(),
            machine: left.machine,
            replaced: left.replaced.union(&right.replaced).copied().collect(),
            narrow_only: left.narrow_only || right.narrow_only,
            mark: left.mark.min(right.mark),
            prior: Arc::new(left.prior.intersection(&right.prior).copied().collect()),
            restriction_only: left.restriction_only || right.restriction_only,
            disputed: left.disputed
                || right.disputed
                || left.mark != right.mark
                || left.prior != right.prior
                || left.replaced != right.replaced,
        })
    }
}

fn meet_copy(
    edits: &mut BTreeMap<AuthorityEntryHash, Arc<FrontierEdit>>,
    hash: AuthorityEntryHash,
    edit: &Arc<FrontierEdit>,
) {
    edits
        .entry(hash)
        .and_modify(|held| *held = FrontierEdit::meet(held, edit))
        .or_insert_with(|| Arc::clone(edit));
}

/// Joins two frontiers: an edit superseded on either side is superseded,
/// and two copies of one edit meet.
pub(super) fn merge_world_frontiers(
    merged: &mut BTreeMap<EntityId, WorldFrontier>,
    right: &BTreeMap<EntityId, WorldFrontier>,
) {
    for (world, frontier) in right {
        let into = merged.entry(*world).or_default();
        for (hash, edit) in &frontier.superseded {
            meet_copy(&mut into.superseded, *hash, edit);
        }
        for (hash, edit) in &frontier.live {
            meet_copy(&mut into.live, *hash, edit);
        }
        let moved: Vec<_> = into
            .live
            .keys()
            .filter(|hash| into.superseded.contains_key(*hash))
            .copied()
            .collect();
        for hash in moved {
            if let Some(edit) = into.live.remove(&hash) {
                meet_copy(&mut into.superseded, hash, &edit);
            }
        }
    }
}

fn is_mine(state: &FoldState, machine: EntityId) -> bool {
    derived_machine(state, machine).is_some_and(|folded| folded.is_mine())
}

/// Full strength while the edit's machine is the owner's, or when the owner
/// acknowledged it when taking "yours" away (`machine_profile::acknowledged`),
/// and this install counted the machine when the edit was made. A head that
/// still says "yours" took nothing away: when it stops standing for another
/// reason (its signer found in a host's custody) it acknowledges no edit (Sol
/// P2 round 3, F2). An edit that landed as restriction only past a sequence
/// floor never counts at full strength in the settings this install reads
/// (Astra #1430), nor does any edit of a machine whose winning revision
/// reached this install past its floor. Standing follows the roster rule
/// alone, as a replica with no floor reads it, so a floor never grants a
/// later edit standing (Sol P2 round 10, F1).
fn full_strength(
    state: &FoldState,
    hash: &AuthorityEntryHash,
    edit: &FrontierEdit,
    counting: Counting,
) -> bool {
    let roster = counting == Counting::Roster;
    let machine = if roster {
        derived_machine(state, edit.machine)
    } else {
        counted_machine(state, edit.machine)
    };
    !edit.disputed
        && (roster || !(edit.narrow_only || edit.restriction_only))
        && machine.is_some_and(|folded| {
            folded.is_mine()
                || (!folded.conflicted
                    && !folded.floor_held
                    && !folded.profile.says_mine()
                    && acknowledged(state, edit.machine, hash, &edit.mark, &edit.prior, roster)
                    && (!folded.removed || folded.profile.role == MachineRole::Removed))
        })
}

/// What one live edit contributes in the current state: its own settings at
/// full strength; otherwise the meet of its settings and of every edit it
/// replaced, each judged the same way, down to full-strength edits or the
/// default. Iterative, so a long chain of offline edits cannot exhaust the
/// stack.
fn contribution(
    state: &FoldState,
    frontier: &WorldFrontier,
    hash: AuthorityEntryHash,
    edit: &FrontierEdit,
    counting: Counting,
) -> PrivacyMeet {
    let mut meet = PrivacyMeet::of(&edit.settings);
    if full_strength(state, &hash, edit, counting) {
        return meet;
    }
    let mut visited = BTreeSet::from([hash]);
    let mut pending = vec![edit];
    while let Some(next) = pending.pop() {
        if next.replaced.is_empty() || next.disputed {
            meet = meet.meet(&PrivacyMeet::of(&WorldPrivacy::default()));
        }
        for replaced in &next.replaced {
            if !visited.insert(*replaced) {
                continue;
            }
            let Some(prior) = frontier
                .superseded
                .get(replaced)
                .or_else(|| frontier.live.get(replaced))
            else {
                continue;
            };
            meet = meet.meet(&PrivacyMeet::of(&prior.settings));
            if !full_strength(state, replaced, prior, counting) {
                pending.push(prior);
            }
        }
    }
    meet
}

fn world_meet(state: &FoldState, world: EntityId, counting: Counting) -> PrivacyMeet {
    let mut contributions = state.worlds.get(&world).into_iter().flat_map(|frontier| {
        frontier
            .live
            .iter()
            .map(|(hash, edit)| contribution(state, frontier, *hash, edit, counting))
    });
    let first = contributions
        .next()
        .unwrap_or_else(|| PrivacyMeet::of(&WorldPrivacy::default()));
    contributions.fold(first, |meet, next| meet.meet(&next))
}

/// The read that decides who may edit `world`. Where two copies of one of
/// its edits disagreed, each copy's view could admit a different editor, and
/// the narrower meet of both can admit one neither copy did: no machine may
/// edit it, as under a conflicted vault root (Sol P2 round 12, F1).
fn roster_read(state: &FoldState, world: EntityId) -> EffectiveRead {
    let disputed = state.worlds.get(&world).is_some_and(|frontier| {
        frontier
            .live
            .values()
            .chain(frontier.superseded.values())
            .any(|edit| edit.disputed)
    });
    if disputed {
        return EffectiveWorldPrivacy::unknowable().read;
    }
    world_meet(state, world, Counting::Roster).effective().read
}

fn may_edit(state: &FoldState, machine: EntityId, world: EntityId) -> bool {
    let is_mine = |id| is_mine(state, id);
    edit_standing(&roster_read(state, world), machine, is_mine, is_mine).is_some()
}

/// The `WorldPrivacy` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster check:
/// its signer is a machine's install key, never a roster key. Validity and
/// standing follow the roster rule, so every install keeps the same edits;
/// `standing` only weakens one this install does not count.
pub(super) fn apply_world_privacy(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    edit: &WorldPrivacyEdit,
    hash: AuthorityEntryHash,
    standing: MachineStanding<'_>,
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() || edit.world == crate::claim::base_world_id() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    let Some(mark) = derived_chains(state, edit.machine)
        .find(|folded| {
            folded.is_mine() && *signer == AuthorityKey::Ed25519(folded.profile.machine_key)
        })
        .map(|folded| folded.entry)
    else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
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
    let narrow_only = !counted_machine(state, edit.machine)
        .is_some_and(|folded| !folded.floor_held && standing(state, &folded));
    let prior = mark_past(state, edit.machine, &mark);
    let frontier = state.worlds.entry(edit.world).or_default();
    let seen = std::mem::take(&mut frontier.live);
    let replaced = seen.keys().copied().collect();
    frontier.superseded.extend(seen);
    frontier.live.insert(
        hash,
        Arc::new(FrontierEdit {
            settings: edit.settings.clone(),
            machine: edit.machine,
            replaced,
            narrow_only,
            mark,
            prior,
            restriction_only,
            disputed: false,
        }),
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
                    effective: world_meet(state, *world, Counting::Install).effective(),
                    roster_read: roster_read(state, *world),
                },
            )
        })
        .collect()
}

/// The world a per-world side entry belongs to; `None` for a main-log entry.
pub(super) fn side_world(op: &AuthorityOp) -> Option<EntityId> {
    match op {
        AuthorityOp::WorldPrivacy(edit) => Some(edit.world),
        _ => None,
    }
}

/// Entries that break the side branches: any entry naming a side entry of a
/// world other than its own as a parent. A replica that may not hold a world
/// never receives its entries, so nothing outside the world may depend on
/// them.
pub(super) fn side_branch_violations(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> BTreeSet<AuthorityEntryHash> {
    by_hash
        .iter()
        .filter(|(_, entry)| {
            entry.parent_hashes.iter().any(|parent| {
                by_hash
                    .get(parent)
                    .and_then(|parent| side_world(&parent.op))
                    .is_some_and(|parent_world| side_world(&entry.op) != Some(parent_world))
            })
        })
        .map(|(hash, _)| *hash)
        .collect()
}

/// The heads a new main-log entry takes as parents: the valid main-log
/// entries no valid main-log entry names. A side entry naming a main-log entry
/// does not retire it as a head.
pub(super) fn main_log_heads(
    entries: &[AuthorityLogEntry],
    valid: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    let mut main = BTreeSet::new();
    let mut named = BTreeSet::new();
    for entry in entries {
        let Ok(hash) = authority_entry_hash(entry) else {
            continue;
        };
        if valid.contains(&hash) && side_world(&entry.op).is_none() {
            main.insert(hash);
            named.extend(entry.parent_hashes.iter().copied());
        }
    }
    main.retain(|hash| !named.contains(hash));
    main
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

/// The edits that never count at full strength on this install: each one
/// valid without effect, and each live or replaced edit this install reads
/// as narrowing only (Sol P2 round 18, F1).
pub(super) fn held_edits(state: &FoldState, out: &mut BTreeSet<AuthorityEntryHash>) {
    out.extend(state.refused_world_edits.iter().copied());
    for frontier in state.worlds.values() {
        out.extend(
            frontier
                .live
                .iter()
                .chain(&frontier.superseded)
                .filter(|(hash, edit)| !full_strength(state, hash, edit, Counting::Install))
                .map(|(hash, _)| *hash),
        );
    }
}

/// What both settings allow.
pub(super) fn meet_effective(
    left: &EffectiveWorldPrivacy,
    right: &EffectiveWorldPrivacy,
) -> EffectiveWorldPrivacy {
    PrivacyMeet::of_effective(left)
        .meet(&PrivacyMeet::of_effective(right))
        .effective()
}
