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

use super::machine_profile::{acknowledges, derived_chains, derived_machine};
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct WorldFrontier {
    /// The edits no later edit of the world has seen.
    live: BTreeMap<AuthorityEntryHash, Arc<FrontierEdit>>,
    /// Every edit a later edit replaced, kept so an edit that only narrows
    /// is judged against what it replaced.
    superseded: BTreeMap<AuthorityEntryHash, Arc<FrontierEdit>>,
}

pub(super) fn merge_world_frontiers(
    merged: &mut BTreeMap<EntityId, WorldFrontier>,
    right: &BTreeMap<EntityId, WorldFrontier>,
) {
    for (world, frontier) in right {
        let into = merged.entry(*world).or_default();
        for (hash, edit) in &frontier.superseded {
            into.superseded
                .entry(*hash)
                .or_insert_with(|| Arc::clone(edit));
        }
        for (hash, edit) in &frontier.live {
            into.live.entry(*hash).or_insert_with(|| Arc::clone(edit));
        }
        let superseded = &into.superseded;
        into.live.retain(|hash, _| !superseded.contains_key(hash));
    }
}

fn is_mine(state: &FoldState, machine: EntityId) -> bool {
    derived_machine(state, machine).is_some_and(|folded| folded.is_mine())
}

/// Full strength while the edit's machine is the owner's, or when every
/// revision that took "yours" away had seen the edit, and this install
/// counted the machine when the edit was made. A revision that still says
/// "yours" took nothing away: when it stops standing for another reason (its
/// signer found in a host's custody) it acknowledges no edit (Sol P2 round 3,
/// F2). Nor does a later revision of a machine already not the owner's, such
/// as a removal after a demotion (Wonder P2 round 1, W2), or one that took
/// away a mark that did not stand, whenever its custody is found (round 2,
/// W2).
fn full_strength(
    state: &FoldState,
    hash: &AuthorityEntryHash,
    edit: &FrontierEdit,
    counting: Counting,
) -> bool {
    (counting == Counting::Roster || !edit.narrow_only)
        && derived_machine(state, edit.machine).is_some_and(|folded| {
            folded.is_mine()
                || (!folded.conflicted
                    && !folded.profile.says_mine()
                    && acknowledges(state, edit.machine, hash)
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
        if next.replaced.is_empty() {
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

fn may_edit(state: &FoldState, machine: EntityId, world: EntityId) -> bool {
    let read = world_meet(state, world, Counting::Roster).effective().read;
    let is_mine = |id| is_mine(state, id);
    edit_standing(&read, machine, is_mine, is_mine).is_some()
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
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() || edit.world == crate::claim::base_world_id() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    if !derived_chains(state, edit.machine).any(|folded| {
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
    let narrow_only =
        !derived_machine(state, edit.machine).is_some_and(|folded| standing(state, &folded));
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
        }),
    );
    Ok(())
}

/// Settlement drops every row above a main-log row it refuses (a concurrent
/// tier floor, a retired signer's fence, a confirmation collision, an
/// unsettled handoff), and the door names every main-log head as a parent, so
/// a world's edits would fall with an unrelated row and the world would read
/// wider than the owner set it (Wonder P2 round 1, W1). A world edit is judged
/// on the main log as the fold keeps it: every edit above a main-log row the
/// fold did not keep is folded again, in causal order, with each such row
/// crossed, never applied. An edit invalid on its own stays invalid. Crossing
/// gives no signer more than this replica's fold already gives the same edit
/// signed on the crossed row's parents instead (Wonder P2 round 2, W1).
pub(super) fn refold_world_edits(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    context: FoldContext<'_>,
    issues: &mut Vec<AuthorityFoldIssue>,
) {
    let causal = |hashes: BTreeSet<AuthorityEntryHash>| {
        let mut hashes: Vec<_> = hashes.into_iter().collect();
        hashes.sort_by_key(|hash| (ancestors.get(hash).map_or(0, BTreeSet::len), *hash));
        hashes
    };
    let crossable = |hash: &AuthorityEntryHash| {
        !states.contains_key(hash)
            && by_hash
                .get(hash)
                .is_some_and(|entry| side_world(&entry.op).is_none())
    };
    let lost = causal(
        by_hash
            .iter()
            .filter(|(hash, entry)| {
                side_world(&entry.op).is_some()
                    && !states.contains_key(*hash)
                    && ancestors
                        .get(*hash)
                        .is_some_and(|past| past.iter().any(crossable))
            })
            .map(|(hash, _)| *hash)
            .collect(),
    );
    if lost.is_empty() {
        return;
    }
    // A main-log row the fold did not keep stands for the merge of its
    // parents, each kept or crossed in turn. Its signed sequence still bounds
    // what its signer signs after it (Sol P2 round 5, F4).
    let crossed = causal(
        lost.iter()
            .filter_map(|hash| ancestors.get(hash))
            .flatten()
            .filter(|hash| crossable(hash))
            .copied()
            .collect(),
    );
    let mut stand_ins = BTreeMap::<AuthorityEntryHash, FoldState>::new();
    for hash in crossed {
        let entry = &by_hash[&hash];
        let mut parents = entry
            .parent_hashes
            .iter()
            .map(|parent| states.get(parent).or_else(|| stand_ins.get(parent)));
        // Parents of two vaults stand for nothing (Sol P2 round 5, F6).
        let merged = parents.next().flatten().and_then(|first| {
            parents.try_fold(first.clone(), |merged, next| {
                next.filter(|state| state.vault_id == merged.vault_id)
                    .map(|state| merge_states(&merged, state))
            })
        });
        if let Some(mut state) = merged.filter(|state| entry.vault_id == Some(state.vault_id)) {
            let seq = state
                .seqs
                .entry(entry.signer_key().clone())
                .or_insert(entry.seq);
            *seq = (*seq).max(entry.seq);
            stand_ins.insert(hash, state);
        }
    }
    for hash in lost {
        let entry = &by_hash[&hash];
        let parents: BTreeMap<_, _> = entry
            .parent_hashes
            .iter()
            .filter_map(|parent| {
                states
                    .get(parent)
                    .or_else(|| stand_ins.get(parent))
                    .map(|state| (*parent, state.clone()))
            })
            .collect();
        if let EntryFold::Ready(state) = fold_entry_state(entry, hash, &parents, context) {
            states.insert(hash, state);
            issues.retain(|issue| {
                !matches!(issue,
                    AuthorityFoldIssue::InvalidEntry(row)
                    | AuthorityFoldIssue::InvalidAncestry(row)
                    | AuthorityFoldIssue::SignerNotInAncestry(row)
                    | AuthorityFoldIssue::NonMonotonicSeq(row) if *row == hash)
            });
        }
    }
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
                    roster_read: world_meet(state, *world, Counting::Roster).effective().read,
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
