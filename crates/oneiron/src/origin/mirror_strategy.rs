//! Core half of `origin::mirror_strategy`: its store-layer items live in `oneiron_store::origin::mirror_strategy` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::mirror_strategy::*;

use super::mirror::{OriginMirrorSetup, OriginMirrorState};
use crate::entity_id::EntityId;

/// What a setup of the served repository `repo` writes on its state row
/// beside the row it replaces, from `previous`: the setup it replaces and that
/// row. The strategy is the setup's. The revision moves only when the
/// strategy does. The generation is a fresh id for a new mirror and whenever
/// the URL, user, custody record or served name moves, so a mirror cleared
/// and set again never takes a generation an earlier request could name.
pub(super) fn configured_strategy(
    previous: Option<(&OriginMirrorSetup, &OriginMirrorState)>,
    repo: &str,
    setup: &OriginMirrorSetup,
) -> ConfiguredStrategy {
    let Some((prior, state)) = previous else {
        return ConfiguredStrategy {
            strategy: setup.sync_strategy,
            revision: 1,
            generation: Some(EntityId::now()),
        };
    };
    let revision = if setup.sync_strategy == prior.sync_strategy {
        state.strategy_revision
    } else {
        state.strategy_revision.saturating_add(1)
    };
    let moved = state.repo != repo
        || prior.url != setup.url
        || prior.user != setup.user
        || prior.secret_ref != setup.secret_ref;
    let generation = if moved {
        Some(EntityId::now())
    } else {
        state.target_generation
    };
    ConfiguredStrategy {
        strategy: setup.sync_strategy,
        revision,
        generation,
    }
}
