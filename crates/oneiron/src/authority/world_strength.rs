//! Each world's settings-edit frontier and the strength of its edits, judged
//! under one trust set at a time (world privacy P2, ported onto P6b's machine
//! chains, contract §4).
//!
//! An edit is valid when, for some chain that admits its machine under the
//! key that signed it, it has standing in the read that chain's admitter X
//! gives (`read_X`), the same on every install. A live edit counts at full
//! strength under `T(X)` only if its machine was mine there with that key at
//! its parents and the race rule passes there now; otherwise it contributes
//! the meet of its settings and of every edit it replaced, each judged the
//! same way, so a chain of raced widens never widens. This install reads the
//! world under `T(pin)` with its own holds, which only weaken.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_standing::{InstallCounted, Mark, Standing, StandingView, TrustedAt};
use super::world_privacy::{PrivacyMeet, edit_standing};
use super::*;

/// One accepted edit of a world.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct FrontierEdit {
    settings: WorldPrivacy,
    pub(super) machine: EntityId,
    /// The install key that signed it.
    key: [u8; 32],
    /// The live edits at the edit's parents, which it replaced.
    replaced: BTreeSet<AuthorityEntryHash>,
    /// This install did not count the machine, under `T(pin)` with the edit's
    /// key, at the edit's parents.
    narrow_only: bool,
    /// Each chain that admitted the machine under the edit's key at its
    /// parents, with the mark the edit was signed under there.
    marks: BTreeMap<MachineAdmitter, Mark>,
    /// Under which trust sets the machine was mine with the edit's key at its
    /// parents.
    trusted_at: TrustedAt,
    /// A later row of its signer reached this replica first, so it landed as
    /// restriction only: it never counts at full strength (Astra #1430).
    restriction_only: bool,
    /// Two copies of it disagreed on its marks, past, trust or what it
    /// replaced: it never counts at full strength, it meets the default as
    /// well (Sol P2 round 11), and no machine may edit its world.
    disputed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct WorldFrontier {
    /// The edits no later edit of the world has seen.
    pub(super) live: BTreeMap<AuthorityEntryHash, Arc<FrontierEdit>>,
    /// Every edit a later edit replaced, kept so an edit that only narrows
    /// is judged against what it replaced.
    pub(super) superseded: BTreeMap<AuthorityEntryHash, Arc<FrontierEdit>>,
}

impl FrontierEdit {
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
            trusted_at: left.trusted_at.meet(&right.trusted_at),
            restriction_only: left.restriction_only || right.restriction_only,
            disputed: left.disputed
                || right.disputed
                || left.marks != right.marks
                || left.trusted_at != right.trusted_at
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

/// Full strength under `view`'s trust set: the edit's machine was mine there
/// with the edit's key at its parents, and the race rule passes there now
/// ([`Standing::race`]). A head that still says "yours" took nothing away:
/// when it stops standing for another reason (its signer found in a host's
/// custody) it acknowledges no edit (Sol P2 round 3, F2). In the install view
/// an edit that landed as restriction only past a sequence floor never counts
/// at full strength (Astra #1430), nor does one this install did not count at
/// its parents, nor any acknowledged by a held chain. Validity follows the
/// roster view, as a replica with no floor reads it, so a floor never grants
/// a later edit standing (Sol P2 round 10, F1).
pub(super) fn full_strength(
    standing: &Standing<'_>,
    hash: &AuthorityEntryHash,
    edit: &FrontierEdit,
    view: StandingView,
) -> bool {
    let trusted_then = match view {
        StandingView::Under(admitter) => edit.trusted_at.under(&admitter),
        StandingView::Install => !(edit.narrow_only || edit.restriction_only),
    };
    !edit.disputed
        && trusted_then
        && standing.race(edit.machine, hash, &edit.key, &edit.marks, view)
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
/// computes, pin-free, which decides who may edit `world` there. Where two
/// copies of one of its edits disagreed, each copy's view could admit a
/// different editor, and the narrower meet of both can admit one neither copy
/// did: no machine may edit it, as under a conflicted vault root (Sol P2
/// round 12, F1).
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
/// its signer is a machine's install key, never a roster key. Validity and
/// standing are pin-free, so every install keeps the same edits: some chain
/// that admits the machine under the signing key must give it standing in
/// its admitter's read. `pin` and `counted` only weaken an edit this install
/// does not count.
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
    let marks = standing.signing_chains(edit.machine, signer);
    if marks.is_empty() {
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
        && !standing.is_admitted(target)
    {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    // Well signed but from a machine that cannot edit this world under any
    // of its signing chains: valid and without effect, so it never stalls
    // what descends from it.
    let may_edit = marks.keys().any(|admitter| {
        let is_mine = |id| standing.is_mine(id, StandingView::Under(*admitter));
        edit_standing(
            &read_under(&standing, edit.world, *admitter),
            edit.machine,
            is_mine,
            is_mine,
        )
        .is_some()
    });
    let narrow_only = standing.counted_key(edit.machine) != Some(key);
    let trusted_at = standing.trusted_at(edit.machine, &key);
    drop(standing);
    if !may_edit {
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
            trusted_at,
            restriction_only,
            disputed: false,
        }),
    );
    Ok(())
}
