//! An agent's world privacy edit judged by its Grant (FIX 11426, contract
//! §4). The fold trusts the carrier for it, as for an agent's setting or
//! export act: its Grant is no authority-log row. So the projection keeps,
//! for each world an agent edited, the world's edits and whether each
//! counts at full strength, as the fold judged them. A view whose rows hold
//! some of those edits' Grants refused
//! ([`super::carried_act::grant_refused_agent_acts`]) reads the world with
//! exactly those edits without effect, whichever of the world's agent edits
//! they are, live or superseded (FIX 22381). An edit's strength rests on its
//! machine's standing, never on the world's other edits, so the kept
//! verdicts hold for every such set. The fold state itself stays the log's:
//! nothing here changes what a later generation resumes from.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::machine_standing::{InstallCounted, Standing, StandingView};
use super::world_privacy::judged_world;
use super::world_strength::{FrontierEdit, full_strength};
use super::*;
use crate::entity_id::EntityId;

/// What a view reads for refused agent world edits: each agent edit's
/// world, live or superseded, and each such world's edits as the fold judged
/// them.
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

    /// Each world of `state` an agent edit reached, live or superseded,
    /// every one of its edits judged under `pin` and `counted` as the fold's
    /// own worlds are.
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
                .chain(frontier.superseded.keys())
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

    /// `fold` with each of `refused` that is an agent world edit, live or
    /// superseded, without effect: its world read with exactly the refused
    /// ones of its edits undone, and the edit listed among the refused world
    /// edits.
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
    /// The world with each of `refused` without effect, as if it had never
    /// been folded. Each leaves the world, live or superseded. An edit that
    /// replaced one replaces, in its place, the nearest edits below it that
    /// are not refused, so an edit that only narrows is still judged against
    /// what it replaced. An edit a live refused edit replaced, directly or
    /// through refused edits alone, is live again when no remaining edit
    /// replaces it. Every remaining edit keeps the strength the fold judged.
    fn read_without(&self, refused: &BTreeSet<AuthorityEntryHash>) -> FoldedWorld {
        let mut frontier = self.frontier.clone();
        let mut removed = BTreeMap::new();
        let mut heads = Vec::new();
        for hash in refused {
            if let Some(edit) = frontier.live.remove(hash) {
                heads.push(*hash);
                removed.insert(*hash, edit);
            } else if let Some(edit) = frontier.superseded.remove(hash) {
                removed.insert(*hash, edit);
            }
        }
        // The edits a removed edit replaced, through removed edits: the
        // nearest ones that remain.
        let remaining_below = |hash: &AuthorityEntryHash| -> BTreeSet<AuthorityEntryHash> {
            let mut below = BTreeSet::new();
            let mut visited = BTreeSet::from([*hash]);
            let mut pending = vec![*hash];
            while let Some(next) = pending.pop() {
                let Some(edit) = removed.get(&next) else {
                    continue;
                };
                for replaced in &edit.replaced {
                    if !removed.contains_key(replaced) {
                        below.insert(*replaced);
                    } else if visited.insert(*replaced) {
                        pending.push(*replaced);
                    }
                }
            }
            below
        };
        for edits in [&mut frontier.live, &mut frontier.superseded] {
            for edit in edits.values_mut() {
                if !edit.replaced.iter().any(|hash| removed.contains_key(hash)) {
                    continue;
                }
                let replaced = edit
                    .replaced
                    .iter()
                    .flat_map(|hash| {
                        if removed.contains_key(hash) {
                            remaining_below(hash)
                        } else {
                            BTreeSet::from([*hash])
                        }
                    })
                    .collect();
                let spliced = Arc::new(replacing(edit, replaced));
                *edit = spliced;
            }
        }
        let restored: BTreeSet<_> = heads.iter().flat_map(remaining_below).collect();
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

/// `edit` with `replaced` in place of the edits it named.
fn replacing(edit: &FrontierEdit, replaced: BTreeSet<AuthorityEntryHash>) -> FrontierEdit {
    FrontierEdit {
        settings: edit.settings.clone(),
        machine: edit.machine,
        key: edit.key,
        replaced,
        narrow_only: edit.narrow_only,
        marks: edit.marks.clone(),
        restriction_only: edit.restriction_only,
        disputed: edit.disputed,
    }
}
