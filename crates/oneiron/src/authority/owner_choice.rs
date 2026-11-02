//! The register every vault-wide single-value owner choice keeps: the
//! checkpoint root policy (mesh PR2c, [`super::checkpoint_choice`]) and each
//! later kind. Each kind keeps its own register, its own wire kind, target
//! and revision domain; one algorithm judges them all. A kind keyed by many
//! targets (a person's own choice, [`super::conversation_training`], keyed
//! by PERSON) keeps one frontier per target in the same register and reads
//! each through [`folded_owner_choices`].
//!
//! The choices keep the world-privacy register over the authority DAG
//! ([`super::world_strength`]): a choice supersedes exactly the live choices
//! its parents carry, which its `seen` names, so a later act whose `seen`
//! covers both heads of a conflict supersedes both. Concurrent choices stay
//! side by side. A choice has no meet, so concurrent different choices
//! conflict: while they do, the last unconflicted choice stays in force (the
//! newest choice every contender descends from), and the owner's surface
//! reads the conflict. A clear (no choice) hands the vault back to its kind's
//! default. No advisory time, signature or hash ever picks a winner between
//! different choices.
//!
//! Any live machine of the vault may carry a choice, in any role
//! ([`super::owner_act_signer_admits`], the one carrier rule every owner act
//! shares), and its owner must be live at the act's causal point. A choice
//! this install does not count at full strength (its carrier raced its
//! removal, it landed restriction only, or it is disputed) counts as not
//! made: the choice it replaced stays in force. Choices are main-log
//! entries, so every machine the owner admits folds them, and the fold reads
//! the log alone.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_standing::{InstallCounted, Mark, Standing, StandingView};
use super::world_strength::{FrontierEdit, WorldFrontier, merge_world_frontiers};
use super::*;

/// What one signed choice states: the value chosen (none for a clear), and
/// its advisory time, shown as when the owner chose and never judged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct SignedOwnerChoice<P> {
    choice: Option<P>,
    at: u64,
}

impl<P> Default for SignedOwnerChoice<P> {
    fn default() -> Self {
        Self {
            choice: None,
            at: 0,
        }
    }
}

type ChoiceFrontier<P> = WorldFrontier<SignedOwnerChoice<P>>;

/// One kind's choices in one fold state: the frontier of each target (only
/// the vault's own for a vault-wide kind, which the record's shape check
/// pins; each acting PERSON's own for a person's kind), and every
/// well-signed choice whose carrier the one rule did not admit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct OwnerChoiceState<P> {
    frontiers: BTreeMap<EntityId, ChoiceFrontier<P>>,
    refused: BTreeSet<AuthorityEntryHash>,
}

impl<P> Default for OwnerChoiceState<P> {
    fn default() -> Self {
        Self {
            frontiers: BTreeMap::new(),
            refused: BTreeSet::new(),
        }
    }
}

/// Joins two states' choices: a choice superseded on either side is
/// superseded, and two copies of one choice meet.
pub(super) fn merge_owner_choices<P: Clone + PartialEq>(
    merged: &mut OwnerChoiceState<P>,
    right: &OwnerChoiceState<P>,
) {
    merge_world_frontiers(&mut merged.frontiers, &right.frontiers);
    merged.refused.extend(right.refused.iter().copied());
}

/// One choice as a surface shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerChoiceHead<P> {
    /// The choice's authority entry hash.
    pub act: AuthorityEntryHash,
    /// The carrier: the machine whose install key signed it.
    pub machine: EntityId,
    /// The value chosen; `None` for a clear.
    pub choice: Option<P>,
    /// Its advisory time, for display only.
    pub at: u64,
}

/// One kind's folded choices, as this install counts them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedOwnerChoice<P> {
    /// Each live choice: what the next choice's `seen` covers.
    pub(crate) live: BTreeMap<AuthorityEntryHash, OwnerChoiceHead<P>>,
    /// The choice in force here; `None` when no choice counts (the kind's
    /// default holds).
    pub(crate) in_force: Option<OwnerChoiceHead<P>>,
    /// The counted live choices that conflict; empty when none do.
    pub(crate) conflict: Vec<OwnerChoiceHead<P>>,
    /// Well-signed choices without effect: their carrier was not admitted, or
    /// their owner not live, at their parents.
    pub(crate) refused: BTreeSet<AuthorityEntryHash>,
}

impl<P> Default for FoldedOwnerChoice<P> {
    fn default() -> Self {
        Self {
            live: BTreeMap::new(),
            in_force: None,
            conflict: Vec::new(),
            refused: BTreeSet::new(),
        }
    }
}

impl<P> FoldedOwnerChoice<P> {
    /// The owner's value in force; `None` when the kind's default holds (no
    /// choice counts, or a clear is in force).
    pub(crate) fn selected(&self) -> Option<&P> {
        self.in_force.as_ref()?.choice.as_ref()
    }

    /// The kind's revision under its own `context`: what a surface shows the
    /// owner and passes back as `seen`.
    pub(crate) fn revision(&self, context: &[u8]) -> [u8; 32] {
        act_revision(context, self.live.keys().copied())
    }
}

/// One choice as its kind's op carries it.
pub(super) struct OwnerChoiceOp<'a, P> {
    /// The owner's act: its `target` names the frontier, its `seen` the live
    /// choices its parents carry.
    pub(super) act: &'a OwnerAct,
    /// The carrier: the machine whose install key signed the choice.
    pub(super) machine: EntityId,
    /// The value chosen; `None` for a clear.
    pub(super) choice: Option<&'a P>,
    /// The kind's revision domain, which `seen` is under.
    pub(super) context: &'static [u8],
}

/// What a valid choice does to its register ([`OwnerChoiceState::land`]).
pub(super) enum OwnerChoiceLanding<P> {
    /// Valid without effect: its carrier was not admitted, or its owner not
    /// live, at its parents.
    Refused(AuthorityEntryHash),
    /// It supersedes exactly the live choices of its target.
    Recorded {
        target: EntityId,
        hash: AuthorityEntryHash,
        settings: SignedOwnerChoice<P>,
        machine: EntityId,
        key: [u8; 32],
        narrow_only: bool,
        marks: BTreeMap<MachineAdmitter, Mark>,
        restriction_only: bool,
    },
}

/// An owner choice transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check: its signer is a machine's install key, never a roster key (FIX
/// 2222: the host root acts as nobody). Some chain of the machine must name
/// the key, and the act's `seen` must be the live choices its parents carry.
/// A choice carried while the machine was not admitted, or by an owner the
/// parents hold removed, is valid and without effect, so it never stalls
/// what descends from it. `pin` and `counted` only weaken a choice this
/// install does not count. Reads only; the kind's adapter lands the result
/// into its own register.
pub(super) fn owner_choice_landing<P: Clone>(
    state: &FoldState,
    register: &OwnerChoiceState<P>,
    entry: &AuthorityLogEntry,
    op: OwnerChoiceOp<'_, P>,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<OwnerChoiceLanding<P>, AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    let AuthorityKey::Ed25519(key) = signer else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    let key = *key;
    let standing = Standing::new(state, pin, counted);
    if !standing.names_key(op.machine, &key) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    let live = register
        .frontiers
        .get(&op.act.target)
        .into_iter()
        .flat_map(|frontier| frontier.live.keys().copied());
    if op.act.seen != act_revision(op.context, live) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(op.machine, &key, roster);
    let marks = standing.live_signing_chains(op.machine, signer);
    let narrow_only = !standing.admits_owner_act_signer(op.machine, &key, StandingView::Install);
    drop(standing);
    if !admitted || !super::owner_act::owner_live_at(state, op.act.owner) {
        return Ok(OwnerChoiceLanding::Refused(hash));
    }
    Ok(OwnerChoiceLanding::Recorded {
        target: op.act.target,
        hash,
        settings: SignedOwnerChoice {
            choice: op.choice.cloned(),
            at: entry.ts,
        },
        machine: op.machine,
        key,
        narrow_only,
        marks,
        restriction_only,
    })
}

impl<P> OwnerChoiceState<P> {
    /// Whether no choice of the kind was ever folded: a register an image
    /// need not carry (FIX 4624).
    pub(super) fn is_empty(&self) -> bool {
        self.frontiers.is_empty() && self.refused.is_empty()
    }

    /// Lands a valid choice: a refused one is kept without effect; a
    /// recorded one supersedes the live choices of its target.
    pub(super) fn land(&mut self, landing: OwnerChoiceLanding<P>) {
        match landing {
            OwnerChoiceLanding::Refused(hash) => {
                self.refused.insert(hash);
            }
            OwnerChoiceLanding::Recorded {
                target,
                hash,
                settings,
                machine,
                key,
                narrow_only,
                marks,
                restriction_only,
            } => {
                let frontier = self.frontiers.entry(target).or_default();
                let seen = std::mem::take(&mut frontier.live);
                let replaced = seen.keys().copied().collect();
                frontier.superseded.extend(seen);
                frontier.live.insert(
                    hash,
                    Arc::new(FrontierEdit {
                        settings,
                        machine,
                        key,
                        replaced,
                        narrow_only,
                        marks,
                        restriction_only,
                        disputed: false,
                    }),
                );
            }
        }
    }
}

fn choice_of<'f, P>(
    frontier: &'f ChoiceFrontier<P>,
    hash: &AuthorityEntryHash,
) -> Option<&'f Arc<FrontierEdit<SignedOwnerChoice<P>>>> {
    frontier
        .live
        .get(hash)
        .or_else(|| frontier.superseded.get(hash))
}

/// Full strength on this install: not disputed, counted here at its
/// parents, landed in full, and its removal race passes now
/// ([`Standing::owner_act_race`]).
fn counts_here<P>(
    standing: &Standing<'_>,
    hash: &AuthorityEntryHash,
    choice: &FrontierEdit<SignedOwnerChoice<P>>,
) -> bool {
    !choice.disputed
        && !choice.narrow_only
        && !choice.restriction_only
        && standing.owner_act_race(
            choice.machine,
            hash,
            &choice.key,
            &choice.marks,
            StandingView::Install,
        )
}

/// Every choice `hash` descends from, through the choices each replaced.
fn ancestors<P>(
    frontier: &ChoiceFrontier<P>,
    hash: &AuthorityEntryHash,
) -> BTreeSet<AuthorityEntryHash> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<_> = choice_of(frontier, hash)
        .map(|choice| choice.replaced.iter().copied().collect())
        .unwrap_or_default();
    while let Some(next) = stack.pop() {
        if seen.insert(next)
            && let Some(choice) = choice_of(frontier, &next)
        {
            stack.extend(choice.replaced.iter().copied());
        }
    }
    seen
}

/// The choices that stand for `from` on this install: each one that counts
/// at full strength, and for one that does not, what it replaced, judged the
/// same way. Only the newest stand: a choice another standing one descends
/// from is dropped.
fn standing_heads<P>(
    standing: &Standing<'_>,
    frontier: &ChoiceFrontier<P>,
    from: impl IntoIterator<Item = AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    let mut heads = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut stack: Vec<_> = from.into_iter().collect();
    while let Some(hash) = stack.pop() {
        if !visited.insert(hash) {
            continue;
        }
        let Some(choice) = choice_of(frontier, &hash) else {
            continue;
        };
        if counts_here(standing, &hash, choice) {
            heads.insert(hash);
        } else {
            stack.extend(choice.replaced.iter().copied());
        }
    }
    let older: BTreeSet<_> = heads
        .iter()
        .flat_map(|hash| ancestors(frontier, hash))
        .collect();
    heads.retain(|hash| !older.contains(hash));
    heads
}

/// The choice in force and the counted live choices in conflict (CALLS
/// "mesh PR2c choice in force"). When the standing heads agree, the first
/// of them is in force. When they differ, they conflict, and the newest
/// choices every one of them descends from are judged the same way, until
/// they agree or none is left (the kind's default then holds).
fn in_force<P: PartialEq>(
    standing: &Standing<'_>,
    frontier: &ChoiceFrontier<P>,
) -> (Option<AuthorityEntryHash>, BTreeSet<AuthorityEntryHash>) {
    let mut heads = standing_heads(standing, frontier, frontier.live.keys().copied());
    let mut conflict = BTreeSet::new();
    loop {
        let mut choices = heads
            .iter()
            .filter_map(|hash| choice_of(frontier, hash))
            .map(|choice| &choice.settings.choice);
        let Some(first) = choices.next() else {
            return (None, conflict);
        };
        if choices.all(|choice| choice == first) {
            return (heads.first().copied(), conflict);
        }
        if conflict.is_empty() {
            conflict.clone_from(&heads);
        }
        let common = heads
            .iter()
            .map(|hash| ancestors(frontier, hash))
            .reduce(|left, right| left.intersection(&right).copied().collect())
            .unwrap_or_default();
        heads = standing_heads(standing, frontier, common);
    }
}

fn head_of<P: Clone>(
    frontier: &ChoiceFrontier<P>,
    hash: &AuthorityEntryHash,
) -> Option<OwnerChoiceHead<P>> {
    choice_of(frontier, hash).map(|choice| OwnerChoiceHead {
        act: *hash,
        machine: choice.machine,
        choice: choice.settings.choice.clone(),
        at: choice.settings.at,
    })
}

/// The fold's view of one kind's choices, under this install's pin and
/// holds.
pub(super) fn folded_owner_choice<P: Clone + PartialEq>(
    state: &FoldState,
    register: &OwnerChoiceState<P>,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedOwnerChoice<P> {
    let mut folded = FoldedOwnerChoice {
        refused: register.refused.clone(),
        ..FoldedOwnerChoice::default()
    };
    let Some(frontier) = register.frontiers.values().next() else {
        return folded;
    };
    let standing = Standing::new(state, pin, counted);
    fold_frontier(&standing, frontier, &mut folded);
    folded
}

/// The fold's view of each target's choices, for a kind keyed by many
/// targets, under this install's pin and holds: every target judged as
/// [`folded_owner_choice`] judges the one. Each view's `refused` is empty: a
/// refused choice names no frontier, and the register's own set
/// ([`refused_owner_choices`]) keeps it.
pub(super) fn folded_owner_choices<P: Clone + PartialEq>(
    state: &FoldState,
    register: &OwnerChoiceState<P>,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> BTreeMap<EntityId, FoldedOwnerChoice<P>> {
    if register.frontiers.is_empty() {
        return BTreeMap::new();
    }
    let standing = Standing::new(state, pin, counted);
    register
        .frontiers
        .iter()
        .map(|(target, frontier)| {
            let mut folded = FoldedOwnerChoice::default();
            fold_frontier(&standing, frontier, &mut folded);
            (*target, folded)
        })
        .collect()
}

/// Every well-signed choice of the kind whose carrier the one rule did not
/// admit, or whose owner was not live, at its parents.
pub(super) fn refused_owner_choices<P>(
    register: &OwnerChoiceState<P>,
) -> &BTreeSet<AuthorityEntryHash> {
    &register.refused
}

/// One frontier's live choices, the choice in force and the conflict.
fn fold_frontier<P: Clone + PartialEq>(
    standing: &Standing<'_>,
    frontier: &ChoiceFrontier<P>,
    folded: &mut FoldedOwnerChoice<P>,
) {
    let (act, conflict) = in_force(standing, frontier);
    folded.live = frontier
        .live
        .keys()
        .filter_map(|hash| Some((*hash, head_of(frontier, hash)?)))
        .collect();
    folded.in_force = act.and_then(|hash| head_of(frontier, &hash));
    folded.conflict = conflict
        .iter()
        .filter_map(|hash| head_of(frontier, hash))
        .collect();
}

/// The choices that never count at full strength on this install: each one
/// valid without effect, and each live or replaced choice it does not count.
pub(super) fn held_owner_choices<P>(
    state: &FoldState,
    register: &OwnerChoiceState<P>,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
    out: &mut BTreeSet<AuthorityEntryHash>,
) {
    out.extend(register.refused.iter().copied());
    let standing = Standing::new(state, pin, counted);
    for frontier in register.frontiers.values() {
        out.extend(
            frontier
                .live
                .iter()
                .chain(&frontier.superseded)
                .filter(|(hash, choice)| !counts_here(&standing, hash, choice))
                .map(|(hash, _)| *hash),
        );
    }
}

/// The live choices `machine` carried, for its next profile revision's
/// acknowledged set ([`super::world_privacy::live_edits_by`]).
pub(super) fn live_choices_by<P>(
    folded: &FoldedOwnerChoice<P>,
    machine: EntityId,
) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
    folded
        .live
        .values()
        .filter(move |head| head.machine == machine)
        .map(|head| head.act)
}
