//! Each world's settings-edit frontier and the strength of its edits (world
//! privacy P2, re-cut for the mesh: contract §3-§4).
//!
//! An edit carries the owner's act ([`OwnerAct`]). It is valid when some
//! chain of its machine names the key that signed it, and it has effect when
//! the one carrier rule admits that machine ([`super::owner_act_signer_admits`]):
//! any live profile of the vault, in any role, on every replica, before and
//! after the owner anchor. No "yours" mark and no world holding is an author
//! test (owner ruling 10-19: "it doesn't matter where you said yes, if you
//! said so"). A live edit counts at full strength while its carrier's removal
//! race passes ([`Standing::owner_act_race`]); otherwise it contributes the
//! meet of its settings and of every edit it replaced, each judged the same
//! way, so a chain of raced widens never widens. This install reads the world
//! with its own floors and holds, which only weaken.
//!
//! The frontier is generic over what an edit states, so a grant's signed
//! travel choices keep the same register ([`super::grant_travel`], FIX
//! 2998), judged by the same carrier rule.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_standing::{InstallCounted, Mark, Standing, StandingView};
use super::world_privacy::PrivacyMeet;
use super::*;

/// One accepted edit of a world, or of what else an edit states (`S`).
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct FrontierEdit<S = WorldPrivacy> {
    pub(super) settings: S,
    pub(super) machine: EntityId,
    /// The install key that signed it.
    pub(super) key: [u8; 32],
    /// The live edits at the edit's parents, which it replaced.
    pub(super) replaced: BTreeSet<AuthorityEntryHash>,
    /// This install did not admit the carrier, with its holds and staleness
    /// and the edit's key, at the edit's parents.
    pub(super) narrow_only: bool,
    /// Each chain that admitted the machine under the edit's key at its
    /// parents, with the mark the edit was signed under there.
    pub(super) marks: BTreeMap<MachineAdmitter, Mark>,
    /// A later row of its signer reached this replica first, so it landed as
    /// restriction only: it never counts at full strength (Astra #1430).
    pub(super) restriction_only: bool,
    /// Two copies of it disagreed on its marks, past or what it replaced: it
    /// never counts at full strength and it meets the default as well (Sol
    /// P2 round 11).
    pub(super) disputed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct WorldFrontier<S = WorldPrivacy> {
    /// The edits no later edit of the world has seen.
    pub(super) live: BTreeMap<AuthorityEntryHash, Arc<FrontierEdit<S>>>,
    /// Every edit a later edit replaced, kept so an edit that only narrows
    /// is judged against what it replaced.
    pub(super) superseded: BTreeMap<AuthorityEntryHash, Arc<FrontierEdit<S>>>,
}

impl<S: Clone + PartialEq> FrontierEdit<S> {
    /// One edit folded twice (past a floor on one replica's pass, or crossed
    /// on another) keeps what both copies grant: either copy's restriction,
    /// what either replaced, the marks and past both saw, and no full
    /// strength when they disagree on anything else. Order-free (Sol P2
    /// rounds 10-11).
    fn meet(left: &Arc<Self>, right: &Arc<Self>) -> Arc<Self> {
        if Arc::ptr_eq(left, right) || left == right {
            return Arc::clone(left);
        }
        let marks = left
            .marks
            .iter()
            .filter_map(|(admitter, mark)| {
                right.marks.get(admitter).map(|other| {
                    (
                        *admitter,
                        Mark {
                            entry: mark.entry.min(other.entry),
                            prior: Arc::new(
                                mark.prior.intersection(&other.prior).copied().collect(),
                            ),
                        },
                    )
                })
            })
            .collect();
        Arc::new(Self {
            settings: left.settings.clone(),
            machine: left.machine,
            key: left.key,
            replaced: left.replaced.union(&right.replaced).copied().collect(),
            narrow_only: left.narrow_only || right.narrow_only,
            marks,
            restriction_only: left.restriction_only || right.restriction_only,
            disputed: left.disputed
                || right.disputed
                || left.marks != right.marks
                || left.replaced != right.replaced,
        })
    }
}

fn meet_copy<S: Clone + PartialEq>(
    edits: &mut BTreeMap<AuthorityEntryHash, Arc<FrontierEdit<S>>>,
    hash: AuthorityEntryHash,
    edit: &Arc<FrontierEdit<S>>,
) {
    edits
        .entry(hash)
        .and_modify(|held| *held = FrontierEdit::meet(held, edit))
        .or_insert_with(|| Arc::clone(edit));
}

/// Joins two frontiers: an edit superseded on either side is superseded,
/// and two copies of one edit meet.
pub(super) fn merge_world_frontiers<S: Clone + PartialEq + Default>(
    merged: &mut BTreeMap<EntityId, WorldFrontier<S>>,
    right: &BTreeMap<EntityId, WorldFrontier<S>>,
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

/// Full strength under `view`: the edit's carrier removal race passes there
/// now ([`Standing::owner_act_race`]), on every replica alike, whatever the
/// carrier's role and whoever pins which anchor. In the install view an edit
/// that landed as restriction only past a sequence floor never counts at
/// full strength (Astra #1430), nor does one this install did not admit at
/// its parents, nor any acknowledged by a held chain. Validity follows the
/// roster view, as a replica with no floor reads it, so a floor never grants
/// a later edit standing (Sol P2 round 10, F1).
pub(super) fn full_strength(
    standing: &Standing<'_>,
    hash: &AuthorityEntryHash,
    edit: &FrontierEdit,
    view: StandingView,
) -> bool {
    let counted_then = match view {
        StandingView::Under(_) => true,
        StandingView::Install => !(edit.narrow_only || edit.restriction_only),
    };
    !edit.disputed
        && counted_then
        && standing.owner_act_race(edit.machine, hash, &edit.key, &edit.marks, view)
}

#[cfg(test)]
thread_local! {
    /// The edits [`world_meet`] visited on this thread: contract §4's cost
    /// oracle.
    pub(super) static WORLD_MEET_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The machine ids the meets copied on this thread: the same oracle for
    /// the one-machine picks a read accumulates (Sol S2-R3 S3-F3).
    pub(super) static WORLD_MEET_COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The meet of every live edit's contribution to `world` under `view`. A
/// live edit contributes its own settings at full strength; otherwise the
/// meet of its settings and of every edit it replaced, each judged the same
/// way, down to full-strength edits or the default. The meet is idempotent,
/// so the edits the live ones share are walked once: one evaluation is
/// linear in the world's edits however many live edits share an ancestry
/// (Sol S2-R2 S2-F4, Astra A2-F3). Iterative, so a long chain of offline
/// edits cannot exhaust the stack.
pub(super) fn world_meet(
    standing: &Standing<'_>,
    world: EntityId,
    view: StandingView,
) -> PrivacyMeet {
    let default = || PrivacyMeet::of(&WorldPrivacy::default());
    let Some(frontier) = standing.state().worlds.get(&world) else {
        return default();
    };
    let Some(first) = frontier.live.values().next() else {
        return default();
    };
    let mut meet = PrivacyMeet::of(&first.settings);
    let mut visited = BTreeSet::new();
    let mut pending = Vec::new();
    for (hash, edit) in &frontier.live {
        #[cfg(test)]
        WORLD_MEET_VISITS.with(|visits| visits.set(visits.get() + 1));
        meet.meet_with(&PrivacyMeet::of(&edit.settings));
        if visited.insert(*hash) && !full_strength(standing, hash, edit, view) {
            pending.push(edit.as_ref());
        }
    }
    while let Some(next) = pending.pop() {
        if next.replaced.is_empty() || next.disputed {
            meet.meet_with(&default());
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
            #[cfg(test)]
            WORLD_MEET_VISITS.with(|visits| visits.set(visits.get() + 1));
            meet.meet_with(&PrivacyMeet::of(&prior.settings));
            if !full_strength(standing, replaced, prior, view) {
                pending.push(prior.as_ref());
            }
        }
    }
    meet
}

/// `read_X(world)`: the read an install trusting exactly `T(admitter)`
/// computes, pin-free: which machines hold the world, for holder execution
/// and diagnostics, never who may edit it. Where two copies of one of its
/// edits disagreed, the world reads nowhere, as under a conflicted vault root
/// (Sol P2 round 12, F1).
pub(super) fn read_under(
    standing: &Standing<'_>,
    world: EntityId,
    admitter: MachineAdmitter,
) -> EffectiveRead {
    let disputed = standing.state().worlds.get(&world).is_some_and(|frontier| {
        frontier
            .live
            .values()
            .chain(frontier.superseded.values())
            .any(|edit| edit.disputed)
    });
    if disputed {
        return EffectiveWorldPrivacy::unknowable().read;
    }
    world_meet(standing, world, StandingView::Under(admitter))
        .effective()
        .read
}

/// The `WorldPrivacy` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster check:
/// its signer is the carrier's install key, never a roster key (FIX 2222: the
/// host root acts as nobody). Some chain of the carrier must name the key; an
/// edit carried while the carrier was not admitted
/// ([`super::owner_act_signer_admits`], pin-free) is valid and without
/// effect, so it never stalls what descends from it. Validity is pin-free,
/// the same on every install, before and after the owner anchor. `pin` and
/// `counted` only weaken an edit this install does not count.
pub(super) fn apply_world_privacy(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    edit: &WorldPrivacyEdit,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() || edit.world == crate::claim::base_world_id() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    let AuthorityKey::Ed25519(key) = signer else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    let key = *key;
    let standing = Standing::new(state, pin, counted);
    if !standing.names_key(edit.machine, &key) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    // Integrity: a one-machine pick names a machine this vault admits. That
    // it is one marked "yours" is the owner's recipient choice, which the
    // writer checks; readers then follow `world_readable_on`.
    if let ReadLocation::OneMachine(target) = edit.settings.read
        && !standing.is_admitted(target)
    {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(edit.machine, &key, roster);
    let marks = standing.live_signing_chains(edit.machine, signer);
    let narrow_only = !standing.admits_owner_act_signer(edit.machine, &key, StandingView::Install);
    drop(standing);
    // An owner the edit's parents hold removed carries no say-so (mesh
    // contract §4): valid, without effect.
    if !admitted || !super::owner_act::owner_live_at(state, edit.act.owner) {
        state.refused_world_edits.insert(hash);
        return Ok(());
    }
    // An agent's act stands only as a tighten or an equal change against the
    // settings at its `seen` (FIX 4480): a widen by an agent is irreversible
    // in effect, and only a holder's own yes writes one. Valid, without
    // effect, so it never stalls what descends from it. Its Grant row is no
    // authority-log row, so the fold trusts the carrier for it (contract §4).
    if matches!(edit.act.by, ActBy::Agent { .. }) && !agent_edit_narrows(state, edit) {
        state.refused_world_edits.insert(hash);
        return Ok(());
    }
    let frontier = state.worlds.entry(edit.world).or_default();
    let seen = std::mem::take(&mut frontier.live);
    let replaced = seen.keys().copied().collect();
    frontier.superseded.extend(seen);
    frontier.live.insert(
        hash,
        Arc::new(FrontierEdit {
            settings: edit.settings.clone(),
            machine: edit.machine,
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

/// Whether an agent's edit narrows or keeps every live edit at its parents,
/// decided on the revision it names: its `seen` must be the world's revision
/// there, the settings an agent's surface showed it, else nothing tells what
/// it narrowed.
fn agent_edit_narrows(state: &FoldState, edit: &WorldPrivacyEdit) -> bool {
    if edit.act.seen != super::world_privacy::policy_revision(state, edit.world).0 {
        return false;
    }
    let heads = state
        .worlds
        .get(&edit.world)
        .into_iter()
        .flat_map(|frontier| frontier.live.values())
        .map(|live| &live.settings);
    privacy_direction(heads, &edit.settings) != PrivacyDirection::Widen
}
