//! An agent's world privacy edit judged by its Grant (FIX 11426, contract
//! §4). The fold trusts the carrier for it, as for an agent's setting or
//! export act: its Grant is no authority-log row. So the projection keeps,
//! for each world with a live agent edit, the world's edits and whether each
//! counts at full strength, as the fold judged them. A view whose rows hold
//! some of those edits' Grants refused
//! ([`super::carried_act::grant_refused_agent_acts`]) reads the world with
//! exactly those edits without effect, whichever of the world's agent edits
//! they are (FIX 22381). An edit's strength rests on its machine's standing,
//! never on the world's other edits, so the kept verdicts hold for every
//! such set. The fold state itself stays the log's: nothing here changes
//! what a later generation resumes from.

use std::collections::{BTreeMap, BTreeSet};

use super::machine_standing::{InstallCounted, Standing, StandingView};
use super::world_privacy::judged_world;
use super::world_strength::full_strength;
use super::*;
use crate::entity_id::EntityId;

/// What a view reads for refused agent world edits: each live agent edit's
/// world, and each such world's edits as the fold judged them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct AgentWorldUndo {
    each: BTreeMap<AuthorityEntryHash, EntityId>,
    worlds: BTreeMap<EntityId, JudgedFrontier>,
}

/// One world's edits, live and superseded, with each edit's strength under
/// every view a folded world reads ([`judged_world`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct JudgedFrontier {
    frontier: WorldFrontier,
    /// This install's own trust, under which `local_read` is judged.
    local: MachineAdmitter,
    strength: BTreeMap<AuthorityEntryHash, EditStrength>,
}

/// Whether one edit counts at full strength under this install's view,
/// under the roster, and under this install's own trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct EditStrength {
    install: bool,
    roster: bool,
    local: bool,
}

impl EditStrength {
    fn under(self, view: StandingView, local: MachineAdmitter) -> bool {
        match view {
            StandingView::Install => self.install,
            StandingView::Under(MachineAdmitter::Roster) => self.roster,
            StandingView::Under(admitter) if admitter == local => self.local,
            // No folded world reads another admitter's view.
            StandingView::Under(_) => false,
        }
    }
}

impl AgentWorldUndo {
    pub(super) fn is_empty(&self) -> bool {
        self.each.is_empty()
    }

    /// Each world of `state` with a live agent edit, every one of its edits
    /// judged under `pin` and `counted` as the fold's own worlds are.
    pub(super) fn of(
        state: &FoldState,
        pin: Option<&PinnedRoot>,
        counted: InstallCounted<'_>,
    ) -> Self {
        let standing = Standing::new(state, pin, counted);
        let local = standing.local();
        let mut undo = Self::default();
        for (world, frontier) in &state.worlds {
            let agent: Vec<AuthorityEntryHash> = frontier
                .live
                .keys()
                .filter(|hash| state.agent_carried_acts.contains_key(*hash))
                .copied()
                .collect();
            if agent.is_empty() {
                continue;
            }
            undo.each
                .extend(agent.into_iter().map(|hash| (hash, *world)));
            let strength = frontier
                .live
                .iter()
                .chain(frontier.superseded.iter())
                .map(|(hash, edit)| {
                    let under = |view| full_strength(&standing, hash, edit, view);
                    let strength = EditStrength {
                        install: under(StandingView::Install),
                        roster: under(StandingView::Under(MachineAdmitter::Roster)),
                        local: under(StandingView::Under(local)),
                    };
                    (*hash, strength)
                })
                .collect();
            undo.worlds.insert(
                *world,
                JudgedFrontier {
                    frontier: frontier.clone(),
                    local,
                    strength,
                },
            );
        }
        undo
    }

    /// `fold` with each of `refused` that is a live agent world edit
    /// without effect: its world read with exactly the refused ones of its
    /// edits undone, and the edit listed among the refused world edits.
    pub(super) fn hold_back(fold: &mut AuthorityFold, refused: &[AuthorityEntryHash]) {
        let mut by_world: BTreeMap<EntityId, BTreeSet<AuthorityEntryHash>> = BTreeMap::new();
        for hash in refused {
            if let Some(world) = fold.agent_world_undo.each.get(hash) {
                by_world.entry(*world).or_default().insert(*hash);
            }
        }
        for (world, hashes) in by_world {
            let Some(judged) = fold.agent_world_undo.worlds.get(&world) else {
                continue;
            };
            let read = judged.read_without(&hashes);
            fold.worlds.insert(world, read);
            fold.refused_world_edits.extend(hashes);
        }
    }
}

impl JudgedFrontier {
    /// The world with each of `refused` without effect: each leaves the live
    /// set, and an edit one of them replaced that no other edit of the world
    /// replaced is live again. Every edit keeps the strength the fold judged.
    fn read_without(&self, refused: &BTreeSet<AuthorityEntryHash>) -> FoldedWorld {
        let mut frontier = self.frontier.clone();
        let mut restored = BTreeSet::new();
        for hash in refused {
            if let Some(edit) = frontier.live.remove(hash) {
                restored.extend(edit.replaced.iter().copied());
            }
        }
        let still_replaced: BTreeSet<_> = frontier
            .live
            .values()
            .chain(frontier.superseded.values())
            .flat_map(|edit| edit.replaced.iter().copied())
            .collect();
        for hash in restored.difference(&still_replaced) {
            if let Some(edit) = frontier.superseded.remove(hash) {
                frontier.live.insert(*hash, edit);
            }
        }
        judged_world(&frontier, self.local, |hash, _, view| {
            self.strength
                .get(hash)
                .is_some_and(|strength| strength.under(view, self.local))
        })
    }
}
