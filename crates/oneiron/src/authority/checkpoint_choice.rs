//! Folds the owner's signed choices of his vault's checkpoint root policy
//! (mesh PR2c, §A 06, K06; CALLS "mesh PR2-checkpoint-choice").
//!
//! The vault's choices keep the world-privacy register over the authority
//! DAG ([`super::world_strength`]): a choice supersedes exactly the live
//! choices its parents carry, which its `seen` names, so a later act whose
//! `seen` covers both heads of a conflict supersedes both. Concurrent
//! choices stay side by side. Root policies have no meet, so concurrent
//! different choices conflict: while they do, the last unconflicted choice
//! stays in force (the newest choice every contender descends from), the
//! owner's surface reads the conflict, and checkpointing never stops. A
//! clear (no choice) hands the vault back to the policy its hosting posture
//! fixes.
//!
//! Any live machine of the vault may carry a choice, in any role
//! ([`super::owner_act_signer_admits`], the one carrier rule every owner act
//! shares), and its owner must be live at the act's causal point. A choice
//! this install does not count at full strength (its carrier raced its
//! removal, it landed restriction only, or it is disputed) counts as not
//! made: the choice it replaced stays in force. Choices are main-log
//! entries, so every machine the owner admits folds them, and the fold reads
//! the log alone. Pins never move with a choice: a folding install follows
//! it, and an adopting install keeps the pin its pairing gave it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_standing::{InstallCounted, Standing, StandingView};
use super::world_strength::{FrontierEdit, WorldFrontier, merge_world_frontiers};
use super::*;

/// What one signed choice states: the roots and quorum (none for a clear),
/// and its advisory time, shown as when the owner chose and never judged.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct SignedPolicyChoice {
    choice: Option<CheckpointRootChoice>,
    at: u64,
}

type ChoiceFrontier = WorldFrontier<SignedPolicyChoice>;

/// The vault's choices in one fold state: the frontier of each target (only
/// the vault's own, which the record's shape check pins), and every
/// well-signed choice whose carrier the one rule did not admit.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct CheckpointChoiceState {
    frontiers: BTreeMap<EntityId, ChoiceFrontier>,
    refused: BTreeSet<AuthorityEntryHash>,
}

/// Joins two states' choices: a choice superseded on either side is
/// superseded, and two copies of one choice meet.
pub(super) fn merge_checkpoint_choices(
    merged: &mut CheckpointChoiceState,
    right: &CheckpointChoiceState,
) {
    merge_world_frontiers(&mut merged.frontiers, &right.frontiers);
    merged.refused.extend(right.refused.iter().copied());
}

/// One choice as a surface shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointPolicyHead {
    /// The choice's authority entry hash.
    pub act: AuthorityEntryHash,
    /// The carrier: the machine whose install key signed it.
    pub machine: EntityId,
    /// The roots and quorum chosen; `None` for a clear.
    pub choice: Option<CheckpointRootChoice>,
    /// Its advisory time, for display only.
    pub at: u64,
}

/// The vault's folded checkpoint policy choices, as this install counts
/// them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedCheckpointPolicy {
    /// Each live choice: what the next choice's `seen` covers.
    pub(crate) live: BTreeMap<AuthorityEntryHash, CheckpointPolicyHead>,
    /// The choice in force here; `None` when no choice counts (the posture
    /// fixes the policy).
    pub(crate) in_force: Option<CheckpointPolicyHead>,
    /// The counted live choices that conflict; empty when none do.
    pub(crate) conflict: Vec<CheckpointPolicyHead>,
    /// Well-signed choices without effect: their carrier was not admitted, or
    /// their owner not live, at their parents.
    pub(crate) refused: BTreeSet<AuthorityEntryHash>,
}

impl FoldedCheckpointPolicy {
    /// The owner's roots and quorum in force; `None` when the posture fixes
    /// the policy (no choice counts, or a clear is in force).
    pub(crate) fn selected(&self) -> Option<&CheckpointRootChoice> {
        self.in_force.as_ref()?.choice.as_ref()
    }

    /// The vault's checkpoint policy revision: what a surface shows the owner
    /// and passes back as `seen`.
    pub(crate) fn revision(&self) -> [u8; 32] {
        checkpoint_policy_revision(self.live.keys().copied())
    }
}

/// The `CheckpointPolicySet` transition, after the shape, signature,
/// retired, sequence-floor, parent-merge and vault checks and before any
/// roster check: its signer is a machine's install key, never a roster key
/// (FIX 2222: the host root acts as nobody). Some chain of the machine must
/// name the key, and the act's `seen` must be the live choices its parents
/// carry. A choice carried while the machine was not admitted, or by an
/// owner the parents hold removed, is valid and without effect, so it never
/// stalls what descends from it. `pin` and `counted` only weaken a choice
/// this install does not count.
pub(super) fn apply_checkpoint_policy(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    set: &CheckpointPolicySet,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    let AuthorityKey::Ed25519(key) = signer else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    let key = *key;
    let standing = Standing::new(state, pin, counted);
    if !standing.names_key(set.machine, &key) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    let live = state
        .checkpoint_policy
        .frontiers
        .get(&set.act.target)
        .into_iter()
        .flat_map(|frontier| frontier.live.keys().copied());
    if set.act.seen != checkpoint_policy_revision(live) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(set.machine, &key, roster);
    let marks = standing.live_signing_chains(set.machine, signer);
    let narrow_only = !standing.admits_owner_act_signer(set.machine, &key, StandingView::Install);
    drop(standing);
    if !admitted || !super::owner_act::owner_live_at(state, set.act.owner) {
        state.checkpoint_policy.refused.insert(hash);
        return Ok(());
    }
    let frontier = state
        .checkpoint_policy
        .frontiers
        .entry(set.act.target)
        .or_default();
    let seen = std::mem::take(&mut frontier.live);
    let replaced = seen.keys().copied().collect();
    frontier.superseded.extend(seen);
    frontier.live.insert(
        hash,
        Arc::new(FrontierEdit {
            settings: SignedPolicyChoice {
                choice: set.choice.clone(),
                at: entry.ts,
            },
            machine: set.machine,
            key,
            replaced,
            narrow_only,
            marks,
            restriction_only,
            disputed: false,
        }),
    );
    Ok(())
}

fn choice_of<'f>(
    frontier: &'f ChoiceFrontier,
    hash: &AuthorityEntryHash,
) -> Option<&'f Arc<FrontierEdit<SignedPolicyChoice>>> {
    frontier
        .live
        .get(hash)
        .or_else(|| frontier.superseded.get(hash))
}

/// Full strength on this install: not disputed, counted here at its
/// parents, landed in full, and its removal race passes now
/// ([`Standing::owner_act_race`]).
fn counts_here(
    standing: &Standing<'_>,
    hash: &AuthorityEntryHash,
    choice: &FrontierEdit<SignedPolicyChoice>,
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
fn ancestors(frontier: &ChoiceFrontier, hash: &AuthorityEntryHash) -> BTreeSet<AuthorityEntryHash> {
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
fn standing_heads(
    standing: &Standing<'_>,
    frontier: &ChoiceFrontier,
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

/// Policy hook (CALLS "mesh PR2c choice in force"): the choice in force and
/// the counted live choices in conflict. When the standing heads agree, the
/// first of them is in force. When they differ, they conflict, and the
/// newest choices every one of them descends from are judged the same way,
/// until they agree or none is left (the posture's policy then holds).
fn in_force(
    standing: &Standing<'_>,
    frontier: &ChoiceFrontier,
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

fn head_of(frontier: &ChoiceFrontier, hash: &AuthorityEntryHash) -> Option<CheckpointPolicyHead> {
    choice_of(frontier, hash).map(|choice| CheckpointPolicyHead {
        act: *hash,
        machine: choice.machine,
        choice: choice.settings.choice.clone(),
        at: choice.settings.at,
    })
}

/// The fold's view of the vault's choices, under this install's pin and
/// holds.
pub(super) fn folded_checkpoint_policy(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedCheckpointPolicy {
    let mut folded = FoldedCheckpointPolicy {
        refused: state.checkpoint_policy.refused.clone(),
        ..FoldedCheckpointPolicy::default()
    };
    let Some(frontier) = state.checkpoint_policy.frontiers.values().next() else {
        return folded;
    };
    let standing = Standing::new(state, pin, counted);
    let (act, conflict) = in_force(&standing, frontier);
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
    folded
}

/// The choices that never count at full strength on this install: each one
/// valid without effect, and each live or replaced choice it does not count.
pub(super) fn held_checkpoint_choices(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
    out: &mut BTreeSet<AuthorityEntryHash>,
) {
    out.extend(state.checkpoint_policy.refused.iter().copied());
    let standing = Standing::new(state, pin, counted);
    for frontier in state.checkpoint_policy.frontiers.values() {
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
pub(super) fn live_choices_by(
    fold: &AuthorityFold,
    machine: EntityId,
) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
    fold.checkpoint_policy
        .live
        .values()
        .filter(move |head| head.machine == machine)
        .map(|head| head.act)
}
