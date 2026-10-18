//! Folds the owner's signed grant travel choices (OF-491, FIX 2998): the
//! born-with text one federation grant's windows carry to another vault.
//!
//! Per grant the fold keeps world privacy's multi-value register over the
//! authority DAG ([`super::world_strength`]): a choice supersedes exactly the
//! live choices its parents carry, concurrent choices stay side by side, and
//! the effective choice is their meet, the fields every live choice names
//! (DEC-0005: concurrent stricter wins, an explicit reapply widens). A clear
//! is a choice of no field, kept as a head like any other. No choice yet is
//! no head at all, never an empty head the first choice would meet.
//!
//! The owner's say-so counts from wherever he is authenticated as the owner
//! (OWNER RULING 10-19 00:5x), so any live physical machine of the vault may
//! sign a choice, in any role ([`super::owner_act_signer_admits`], the one
//! carrier rule every owner act shares). A choice whose
//! machine is no longer admitted counts at full strength only if the revision
//! that took it away had seen it (its profile's `seen_world_edits`);
//! otherwise, as a raced world edit does, it counts as its meet with every
//! choice it replaced, down to no choice, which sends nothing. Validity is
//! pin-free, the same on every install; this install's counting only
//! narrows. A grant has no world, so no world-holding standing applies.
//!
//! Choices are main-log entries, so every machine the owner admits folds
//! them. The fold reads the log alone.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::share_travel::{BornWithField, GrantTravel, TravelChoice};

use super::machine_standing::{InstallCounted, Standing, StandingView};
use super::world_strength::{FrontierEdit, WorldFrontier};
use super::*;

/// What one signed choice states: the fields it lets travel (none for a
/// clear), and its advisory time, shown as when the owner set it and never
/// judged.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct SignedChoice {
    fields: BTreeSet<BornWithField>,
    at: u64,
}

/// One grant's choices: the live ones, and every one a later choice replaced.
pub(super) type GrantFrontier = WorldFrontier<SignedChoice>;

/// One grant's folded travel choice, as this install counts it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedGrantTravel {
    /// Each live choice and the machine that signed it.
    pub(crate) live: BTreeMap<AuthorityEntryHash, EntityId>,
    /// The fields every live choice lets travel, judged under this install's
    /// pin and holds; empty sends none.
    pub(crate) effective: BTreeSet<BornWithField>,
    /// The latest advisory time among the live choices, for display only.
    pub(crate) set_at: u64,
}

impl FoldedGrantTravel {
    /// The effective choice as the door and the export read it: none when
    /// no field travels, a clear or a meet of disjoint choices alike.
    pub(crate) fn choice(&self) -> Option<GrantTravel> {
        (!self.effective.is_empty()).then(|| GrantTravel {
            travel: TravelChoice {
                born_with: self.effective.clone(),
            },
            set_at: self.set_at,
        })
    }
}

impl AuthorityFold {
    /// `grant`'s signed choices; `None` when no signed choice names it.
    pub(crate) fn signed_grant_travel(&self, grant: EntityId) -> Option<&FoldedGrantTravel> {
        self.grant_travel.get(&grant)
    }
}

/// The `GrantTravelSet` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster check:
/// its signer is a machine's install key, never a roster key. Some chain of
/// the machine must name the key; a choice signed while the machine was not
/// admitted ([`super::owner_act_signer_admits`], pin-free) is valid and without
/// effect, so it never stalls what descends from it. The grant row need not
/// have arrived first: its liveness is the writer's and the read's, never
/// the fold's. `pin` and `counted` only weaken a choice this install does
/// not count.
pub(super) fn apply_grant_travel(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    set: &GrantTravelSet,
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
    // The act names the grant's live choices its parents carry (mesh PR1b):
    // the choice the owner saw, so it supersedes exactly those.
    let live = state
        .grant_travel
        .get(&set.grant)
        .into_iter()
        .flat_map(|frontier| frontier.live.keys().copied());
    if set.act.seen != grant_travel_revision(live) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(set.machine, &key, roster);
    let marks = standing.live_signing_chains(set.machine, signer);
    let narrow_only = !standing.admits_owner_act_signer(set.machine, &key, StandingView::Install);
    drop(standing);
    // A carrier the one rule does not admit, or an owner the act's parents
    // hold removed (mesh contract §4), carries a valid choice without effect.
    if !admitted || !super::owner_act::owner_live_at(state, set.act.owner) {
        state.refused_grant_travel.insert(hash);
        return Ok(());
    }
    let frontier = state.grant_travel.entry(set.grant).or_default();
    let seen = std::mem::take(&mut frontier.live);
    let replaced = seen.keys().copied().collect();
    frontier.superseded.extend(seen);
    frontier.live.insert(
        hash,
        Arc::new(FrontierEdit {
            settings: SignedChoice {
                fields: set
                    .choice
                    .as_ref()
                    .map(|choice| choice.born_with.clone())
                    .unwrap_or_default(),
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

/// Full strength on this install: not disputed, counted here at its
/// parents, landed in full, and its race passes now
/// ([`Standing::owner_act_race`]).
fn counts_here(
    standing: &Standing<'_>,
    hash: &AuthorityEntryHash,
    choice: &FrontierEdit<SignedChoice>,
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

/// The meet of every live choice's contribution to `frontier` on this
/// install. A live choice contributes its own fields at full strength;
/// otherwise the meet of its fields and of every choice it replaced, each
/// judged the same way, down to full-strength choices or no choice, which
/// lets nothing travel. Each choice is walked once, iteratively, as
/// `world_meet` walks a world's edits.
fn grant_meet(standing: &Standing<'_>, frontier: &GrantFrontier) -> BTreeSet<BornWithField> {
    let Some(first) = frontier.live.values().next() else {
        return BTreeSet::new();
    };
    let mut meet = first.settings.fields.clone();
    let mut visited = BTreeSet::new();
    let mut pending = Vec::new();
    for (hash, choice) in &frontier.live {
        meet.retain(|field| choice.settings.fields.contains(field));
        if visited.insert(*hash) && !counts_here(standing, hash, choice) {
            pending.push(choice.as_ref());
        }
    }
    while let Some(next) = pending.pop() {
        if meet.is_empty() {
            break;
        }
        if next.replaced.is_empty() || next.disputed {
            meet.clear();
            break;
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
            meet.retain(|field| prior.settings.fields.contains(field));
            if !counts_here(standing, replaced, prior) {
                pending.push(prior.as_ref());
            }
        }
    }
    meet
}

/// The fold's view of every grant a signed choice names, under this
/// install's pin and holds.
pub(super) fn folded_grants(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> BTreeMap<EntityId, FoldedGrantTravel> {
    let standing = Standing::new(state, pin, counted);
    state
        .grant_travel
        .iter()
        .map(|(grant, frontier)| {
            let folded = FoldedGrantTravel {
                live: frontier
                    .live
                    .iter()
                    .map(|(hash, edit)| (*hash, edit.machine))
                    .collect(),
                effective: grant_meet(&standing, frontier),
                set_at: frontier
                    .live
                    .values()
                    .map(|edit| edit.settings.at)
                    .max()
                    .unwrap_or(0),
            };
            (*grant, folded)
        })
        .collect()
}

/// The choices that never count at full strength on this install: each one
/// valid without effect, and each live or replaced choice this install reads
/// as narrowing only.
pub(super) fn held_grant_choices(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
    out: &mut BTreeSet<AuthorityEntryHash>,
) {
    out.extend(state.refused_grant_travel.iter().copied());
    let standing = Standing::new(state, pin, counted);
    for frontier in state.grant_travel.values() {
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

/// Bounds each grant's effective choice by `bound`'s, the fold with no vouch
/// (`install_fold::NoVouch`): a grant no choice reaches there lets nothing
/// travel here, unless only choices after a settled handoff stand in it
/// (`fresh`).
pub(super) fn cap_grants(
    grants: &mut BTreeMap<EntityId, FoldedGrantTravel>,
    bound: &BTreeMap<EntityId, FoldedGrantTravel>,
    fresh: &BTreeSet<EntityId>,
) {
    let named: BTreeSet<EntityId> = grants.keys().chain(bound.keys()).copied().collect();
    for grant in named.difference(fresh) {
        let allowed = bound.get(grant).map(|folded| &folded.effective);
        grants
            .entry(*grant)
            .or_default()
            .effective
            .retain(|field| allowed.is_some_and(|allowed| allowed.contains(field)));
    }
}

/// The live choices `machine` signed, for its next profile revision's
/// acknowledged set ([`super::world_privacy::live_edits_by`]).
pub(super) fn live_choices_by(
    fold: &AuthorityFold,
    machine: EntityId,
) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
    fold.grant_travel
        .values()
        .flat_map(|grant| grant.live.iter())
        .filter(move |(_, signer)| **signer == machine)
        .map(|(hash, _)| *hash)
}
