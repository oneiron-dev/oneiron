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

use crate::entity_id::EntityId;
use crate::error::Result;

use super::machine_standing::{InstallCounted, Standing, StandingView};
use super::world_strength::{full_strength, read_under, world_meet};
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
    pub(super) fn unknowable() -> Self {
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldedWorld {
    /// Each live edit and the machine that signed it.
    pub live: BTreeMap<AuthorityEntryHash, EntityId>,
    pub effective: EffectiveWorldPrivacy,
    /// The read the roster rule alone gives, the same on every install.
    pub roster_read: EffectiveRead,
    /// `read_X` for this install's own trust (its pinned anchor while the
    /// fold holds the root, else the roster): who may edit the world here,
    /// judged on it and never on `effective` (world privacy P6b). A read
    /// under another admitter is a fold under that admitter's pin.
    pub local_read: EffectiveRead,
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
        let is_mine = |machine: EntityId| self.trusted_machine(machine).is_some();
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
        self.world_edit_standing_by(machine, world)
            .map(|(standing, _)| standing)
    }

    /// How `machine` may edit `world` now, and under which admitter's read:
    /// this install's own trust alone, as every door judges (contract §4).
    /// Another chain that admits the machine can make its edit valid on
    /// every install, but never gives a door standing here (Astra code-S2-R1
    /// A1-F3). The read is `read_X`, judged by the roster rule, as the fold
    /// judges an edit's validity; the machine itself is judged as this
    /// install counts it, which only refuses more.
    pub(crate) fn world_edit_standing_by(
        &self,
        machine: EntityId,
        world: EntityId,
    ) -> Option<(WorldEditStanding, MachineAdmitter)> {
        let local = self.local_admitter();
        edit_standing(
            &self.world_local_read(world),
            machine,
            |id| {
                self.machine(id)
                    .is_some_and(|folded| folded.trusted_under(&local).is_some())
            },
            |id| mine_by_roster(self, id, local),
        )
        .map(|standing| (standing, local))
    }

    /// The admitter this install trusts: its pinned anchor while the fold
    /// holds the pinned root, else the roster.
    #[must_use]
    pub(crate) fn local_admitter(&self) -> MachineAdmitter {
        self.pinned_root.map_or(MachineAdmitter::Roster, |pin| {
            MachineAdmitter::Anchor(pin.anchor_key)
        })
    }

    /// `read_X(world)` for this install's own trust (its pinned anchor while
    /// the fold holds the pinned root, else the roster), which decides who
    /// may edit it here. A conflicted vault root fails closed, as for the
    /// settings.
    #[must_use]
    pub fn world_local_read(&self, world: EntityId) -> EffectiveRead {
        if self.vault_root_is_conflicted() {
            return EffectiveWorldPrivacy::unknowable().read;
        }
        self.worlds.get(&world).map_or_else(
            || EffectiveWorldPrivacy::default().read,
            |folded| folded.local_read.clone(),
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

/// Mine under `T(admitter)` by the roster rule alone, as the fold judges
/// standing at an edit's parents. This install's own projections (a chain
/// gone stale or held here, a roster with no settled root) weaken an edit;
/// they never decide whether it stands, so every install keeps the same
/// edits, and a machine losing its standing here never turns a refused edit
/// into an accepted one (Sol P2 round 3, F1).
pub(super) fn mine_by_roster(
    fold: &AuthorityFold,
    id: EntityId,
    admitter: MachineAdmitter,
) -> bool {
    fold.machine(id)
        .is_some_and(|folded| folded.roster_view().trusted_under(&admitter).is_some())
}

/// `read` is the roster rule's. `is_mine` judges the editor, `named_mine` the
/// machines the read names, both by the roster rule in the fold. The door
/// judges its own machine as this install counts it, which only refuses more.
pub(super) fn edit_standing(
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
    pub(super) fn of(settings: &WorldPrivacy) -> Self {
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

    pub(super) fn meet(&self, other: &Self) -> Self {
        #[cfg(test)]
        super::world_strength::WORLD_MEET_COPIES
            .with(|copies| copies.set(copies.get() + self.contenders.len()));
        let mut meet = self.clone();
        meet.meet_with(other);
        meet
    }

    /// [`Self::meet`] in place: the accumulated sets grow or shrink where
    /// they are, so a walk over many edits copies none of them (Sol S2-R3
    /// S3-F3).
    pub(super) fn meet_with(&mut self, other: &Self) {
        #[cfg(test)]
        super::world_strength::WORLD_MEET_COPIES
            .with(|copies| copies.set(copies.get() + other.contenders.len()));
        match (&mut self.named, &other.named) {
            (_, None) => {}
            (named @ None, Some(right)) => *named = Some(right.clone()),
            (Some(left), Some(right)) => left.retain(|machine| right.contains(machine)),
        }
        self.mine_only |= other.mine_only;
        self.contenders.extend(other.contenders.iter().copied());
        self.sealed = self.sealed.min(other.sealed);
        if self.models != other.models {
            self.models = EffectiveModelOrder::Conflicted;
        }
    }

    pub(super) fn effective(&self) -> EffectiveWorldPrivacy {
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

/// The fold's public view of every edited world: this install's settings,
/// under its pin and holds, the roster's read, and the read of this
/// install's own trust. No other admitter's read is evaluated here, so an
/// anchor that signs none of a world's edits adds no work to it (contract
/// §4's cost bound; Sol code-S2-R1 S1-F4, Astra A1-F4).
pub(super) fn folded_worlds(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> BTreeMap<EntityId, FoldedWorld> {
    let standing = Standing::new(state, pin, counted);
    state
        .worlds
        .iter()
        .map(|(world, frontier)| {
            let roster_read = read_under(&standing, *world, MachineAdmitter::Roster);
            let local_read = match standing.local() {
                MachineAdmitter::Roster => roster_read.clone(),
                local => read_under(&standing, *world, local),
            };
            (
                *world,
                FoldedWorld {
                    live: frontier
                        .live
                        .iter()
                        .map(|(hash, edit)| (*hash, edit.machine))
                        .collect(),
                    effective: world_meet(&standing, *world, StandingView::Install).effective(),
                    roster_read,
                    local_read,
                },
            )
        })
        .collect()
}

/// The world's settings revision in `state`: a digest of its live edits,
/// the same on every install.
pub(super) fn policy_revision(state: &FoldState, world: EntityId) -> PolicyRevision {
    PolicyRevision::of(
        state
            .worlds
            .get(&world)
            .into_iter()
            .flat_map(|frontier| frontier.live.keys().copied()),
    )
}

/// The world a per-world side entry belongs to; `None` for a main-log entry.
pub(super) fn side_world(op: &AuthorityOp) -> Option<EntityId> {
    match op {
        AuthorityOp::WorldPrivacy(edit) => Some(edit.world),
        AuthorityOp::WorldKeyWraps(record) => Some(record.key.world),
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
/// does not retire it as a head. The rows of an anchor this install does not
/// pin are left out and retire nothing, so no door here names them and a
/// host's own roots never crowd a door's parents past the format bound
/// (Astra S2-R2 A2-F4). Each such anchor's own heads come back beside, for
/// the rows that anchor signs: only a main-log entry, which carries them, or
/// that anchor's own row retires one, so another anchor naming them never
/// takes an anchor's door off its own rows.
pub(super) fn main_log_heads(
    rows: &[super::fold_resume::RowMeta<'_>],
    valid: &BTreeSet<AuthorityEntryHash>,
    anchored: &BTreeSet<AuthorityEntryHash>,
    pinned_anchor: Option<[u8; 32]>,
) -> (
    BTreeSet<AuthorityEntryHash>,
    BTreeMap<[u8; 32], BTreeSet<AuthorityEntryHash>>,
) {
    let mut main = BTreeSet::new();
    let mut named = BTreeSet::new();
    let mut foreign: BTreeMap<[u8; 32], (BTreeSet<_>, BTreeSet<_>)> = BTreeMap::new();
    for row in rows {
        let Some(hash) = row.hash else {
            continue;
        };
        if !valid.contains(&hash) || row.world.is_some() {
            continue;
        }
        match row.signer {
            AuthorityKey::Ed25519(anchor)
                if anchored.contains(&hash) && pinned_anchor != Some(*anchor) =>
            {
                let (heads, own_named) = foreign.entry(*anchor).or_default();
                heads.insert(hash);
                own_named.extend(row.parents.iter().copied());
            }
            _ => {
                main.insert(hash);
                named.extend(row.parents.iter().copied());
            }
        }
    }
    main.retain(|hash| !named.contains(hash));
    let foreign = foreign
        .into_iter()
        .filter_map(|(anchor, (mut heads, own_named))| {
            heads.retain(|hash| !named.contains(hash) && !own_named.contains(hash));
            (!heads.is_empty()).then_some((anchor, heads))
        })
        .collect();
    (main, foreign)
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
pub(super) fn held_edits(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
    out: &mut BTreeSet<AuthorityEntryHash>,
) {
    out.extend(state.refused_world_edits.iter().copied());
    let standing = Standing::new(state, pin, counted);
    for frontier in state.worlds.values() {
        out.extend(
            frontier
                .live
                .iter()
                .chain(&frontier.superseded)
                .filter(|(hash, edit)| !full_strength(&standing, hash, edit, StandingView::Install))
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
