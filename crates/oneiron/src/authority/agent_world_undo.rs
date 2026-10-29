//! An agent's world privacy edit judged by its Grant (FIX 11426, contract
//! §4). The fold trusts the carrier for it, as for an agent's setting or
//! export act: its Grant is no authority-log row. So the projection keeps,
//! for each live agent edit, its world as this install reads it had that
//! edit no effect, and a view whose rows hold the edit's Grant refused
//! ([`super::carried_act::grant_refused_agent_acts`]) reads that world
//! instead. The fold state itself stays the log's: nothing here changes
//! what a later generation resumes from.

use std::collections::{BTreeMap, BTreeSet};

use super::machine_standing::{InstallCounted, Standing};
use super::world_privacy::folded_world;
use super::*;
use crate::entity_id::EntityId;

/// What a view reads for refused agent world edits: for each live agent
/// edit, its world without it; for a world with several, that world
/// without any of them as well.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct AgentWorldUndo {
    each: BTreeMap<AuthorityEntryHash, (EntityId, FoldedWorld)>,
    every: BTreeMap<EntityId, FoldedWorld>,
}

impl AgentWorldUndo {
    pub(super) fn is_empty(&self) -> bool {
        self.each.is_empty()
    }

    /// The undo of each live agent edit of `state`'s worlds, judged under
    /// `pin` and `counted` as the fold's own worlds are. Each frontier is
    /// put back as it was before the next is read.
    pub(super) fn of(
        state: &mut FoldState,
        pin: Option<&PinnedRoot>,
        counted: InstallCounted<'_>,
    ) -> Self {
        let mut by_world: BTreeMap<EntityId, Vec<AuthorityEntryHash>> = BTreeMap::new();
        for (world, frontier) in &state.worlds {
            for hash in frontier.live.keys() {
                if state.agent_carried_acts.contains_key(hash) {
                    by_world.entry(*world).or_default().push(*hash);
                }
            }
        }
        let mut undo = Self::default();
        for (world, edits) in by_world {
            for hash in &edits {
                let read = undone_world(state, world, std::slice::from_ref(hash), pin, counted);
                undo.each.insert(*hash, (world, read));
            }
            if edits.len() > 1 {
                let read = undone_world(state, world, &edits, pin, counted);
                undo.every.insert(world, read);
            }
        }
        undo
    }

    /// `fold` with each of `refused` that is a live agent world edit
    /// without effect: its world read as the undo gives it, and the edit
    /// listed among the refused world edits. Where some, but not all, of a
    /// world's several live agent edits are refused, no undo was kept: the
    /// world stays as folded, and that is logged.
    pub(super) fn hold_back(fold: &mut AuthorityFold, refused: &[AuthorityEntryHash]) {
        let mut by_world: BTreeMap<EntityId, BTreeSet<AuthorityEntryHash>> = BTreeMap::new();
        for hash in refused {
            if let Some((world, _)) = fold.agent_world_undo.each.get(hash) {
                by_world.entry(*world).or_default().insert(*hash);
            }
        }
        for (world, hashes) in by_world {
            let live_agent = fold
                .agent_world_undo
                .each
                .iter()
                .filter(|(_, (of, _))| *of == world)
                .count();
            let read = match hashes.iter().next() {
                Some(hash) if hashes.len() == 1 => fold
                    .agent_world_undo
                    .each
                    .get(hash)
                    .map(|(_, read)| read.clone()),
                _ if hashes.len() == live_agent => fold.agent_world_undo.every.get(&world).cloned(),
                _ => None,
            };
            let Some(read) = read else {
                tracing::warn!(
                    world = %world.to_hex(),
                    "some of a world's agent privacy edits hold a refused Grant and some do not; \
                     the world reads as folded"
                );
                continue;
            };
            fold.worlds.insert(world, read);
            fold.refused_world_edits.extend(hashes);
        }
    }
}

/// `world` as `state` reads it with each of `edits` without effect: each
/// leaves the live set, and an edit it replaced that no other edit of the
/// world replaced is live again. `state` is as it was on return.
fn undone_world(
    state: &mut FoldState,
    world: EntityId,
    edits: &[AuthorityEntryHash],
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedWorld {
    let kept = state.worlds.get(&world).cloned().unwrap_or_default();
    let mut frontier = kept.clone();
    let mut restored = BTreeSet::new();
    for hash in edits {
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
    state.worlds.insert(world, frontier);
    let read = {
        let standing = Standing::new(state, pin, counted);
        let empty = WorldFrontier::default();
        let frontier = standing.state().worlds.get(&world).unwrap_or(&empty);
        folded_world(&standing, world, frontier)
    };
    state.worlds.insert(world, kept);
    read
}
