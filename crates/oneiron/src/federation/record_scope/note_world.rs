//! A NOTE's world (FIX-LIST 9433): where its live `InWorld` edges place it,
//! read again at every read. Its birth stamp's world is a write-time
//! snapshot, never read authority; every other axis of its position (facet,
//! sensitivity, band, audience) stays stamped at birth.
//!
//! A NOTE may sit in several worlds. A door that reads under world ceilings
//! holds it at one world it is in that they all hold, base reality first
//! ([`held_at`]). The one position every other door reads
//! ([`NoteWorlds::axis`]) never admits more than that, and a NOTE also in
//! base reality stays where a base read finds it today.

use super::{Scope, ScopeAxis, ScopeId};
use crate::EntityId;
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::ENTITY_TYPE_NOTE;
use crate::store::ManifestDbs;
use std::collections::BTreeSet;

/// Where a NOTE's world is read from (CALLS `FIX 9433 NOTE_WORLD_SOURCE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoteWorldSource {
    /// Its outgoing `InWorld` edges, live, at every read; its stamp's world
    /// only snapshots them at the write.
    LiveInWorldEdgeOnRead,
}

const NOTE_WORLD_SOURCE: NoteWorldSource = NoteWorldSource::LiveInWorldEdgeOnRead;

/// How a door holds a NOTE in several worlds (CALLS `FIX 9433
/// NOTE_MULTI_WORLD_POSITION`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultiWorldPosition {
    /// At any world it is in: a ceiling that holds one of them holds it.
    AnyMatchingWorld,
}

const NOTE_MULTI_WORLD_POSITION: MultiWorldPosition = MultiWorldPosition::AnyMatchingWorld;

/// Where a NOTE whose edges do not read sits (CALLS `FIX 9433
/// NOTE_WORLD_LOOKUP_FAULT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorldLookupFault {
    /// In no single world, with a warning that names nothing: no ceiling
    /// that narrows worlds holds it, base reality's included.
    NoSingleWorldAndWarn,
}

const NOTE_WORLD_LOOKUP_FAULT: WorldLookupFault = WorldLookupFault::NoSingleWorldAndWarn;

/// Where a NOTE sits by its live `InWorld` edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NoteWorlds {
    /// The distinct worlds its edges name, base reality as the base world;
    /// a NOTE with no edge is in base reality alone.
    In(BTreeSet<ScopeId>),
    /// Its edges did not read (`NOTE_WORLD_LOOKUP_FAULT`).
    NoSingleWorld,
}

/// The worlds the NOTE `id` sits in, read in `txn` on `store`. A fault never
/// reads as base reality: it is no single world.
pub(crate) fn note_worlds_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> NoteWorlds {
    let edge = match NOTE_WORLD_SOURCE {
        NoteWorldSource::LiveInWorldEdgeOnRead => EdgeKind::InWorld,
    };
    let read = store
        .port_edges(txn, &id, EdgeDirection::Out, Some(edge), None)
        .and_then(|rows| {
            rows.map(|row| row.map(|row| ScopeId(row.target)))
                .collect::<Result<BTreeSet<_>>>()
        });
    match read {
        Ok(worlds) if worlds.is_empty() => {
            NoteWorlds::In(BTreeSet::from([ScopeId(crate::claim::base_world_id())]))
        }
        Ok(worlds) => NoteWorlds::In(worlds),
        Err(error) => match NOTE_WORLD_LOOKUP_FAULT {
            WorldLookupFault::NoSingleWorldAndWarn => {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "a NOTE's InWorld edges did not read; it sits in no single world \
                     (FIX-LIST 9433)"
                );
                NoteWorlds::NoSingleWorld
            }
        },
    }
}

impl NoteWorlds {
    /// The one world `ceiling` holds it at (`NOTE_MULTI_WORLD_POSITION`):
    /// base reality when it is in base and the ceiling holds base, else the
    /// first world it is in that the ceiling holds; `None` where `ceiling`
    /// leaves worlds whole, holds none of them, or it is in no single world.
    fn held(&self, ceiling: &ScopeAxis<ScopeId>) -> Option<ScopeId> {
        let (Self::In(worlds), ScopeAxis::Some(_)) = (self, ceiling) else {
            return None;
        };
        match NOTE_MULTI_WORLD_POSITION {
            MultiWorldPosition::AnyMatchingWorld => {
                let base = ScopeId(crate::claim::base_world_id());
                let held = |world: &&ScopeId| ceiling.contains(world);
                worlds
                    .get(&base)
                    .filter(held)
                    .or_else(|| worlds.iter().find(held))
                    .copied()
            }
        }
    }

    /// The world axis of its one position, which every door that does not
    /// hold it at a ceiling reads: its one world; base reality when base is
    /// among several, so a base read keeps it; its worlds when base is not,
    /// held only by a ceiling that holds them all; every world when it is in
    /// no single one, held only by a ceiling that leaves worlds whole.
    pub(crate) fn axis(&self) -> ScopeAxis<ScopeId> {
        let base = ScopeId(crate::claim::base_world_id());
        match self {
            Self::In(worlds) if worlds.contains(&base) => ScopeAxis::Some(BTreeSet::from([base])),
            Self::In(worlds) => ScopeAxis::Some(worlds.clone()),
            Self::NoSingleWorld => ScopeAxis::All,
        }
    }

    /// The world axis a door reading under the world ceiling `ceiling`
    /// holds it at: the one world the ceiling holds it at, else
    /// [`Self::axis`].
    pub(crate) fn axis_at(&self, ceiling: &ScopeAxis<ScopeId>) -> ScopeAxis<ScopeId> {
        self.held(ceiling).map_or_else(
            || self.axis(),
            |world| ScopeAxis::Some(BTreeSet::from([world])),
        )
    }

    /// Its one world as `record_world_in` reports it (`Some(None)` for base
    /// reality); `None` where it is in no single world.
    pub(crate) fn world(&self) -> Option<Option<EntityId>> {
        match self.axis() {
            ScopeAxis::Some(worlds) if worlds.len() == 1 => {
                worlds.first().map(|world| reported(*world))
            }
            _ => None,
        }
    }

    /// Its world as a read under the world ceiling `ceiling` places it: the
    /// one world the ceiling holds it at, else [`Self::world`].
    pub(crate) fn world_at(&self, ceiling: &ScopeAxis<ScopeId>) -> Option<Option<EntityId>> {
        self.held(ceiling)
            .map_or_else(|| self.world(), |world| Some(reported(world)))
    }
}

/// `world` as a world read reports it: base reality is `None`.
fn reported(world: ScopeId) -> Option<EntityId> {
    Some(world.0).filter(|world| *world != crate::claim::base_world_id())
}

/// `scope`, the position the stored row `id` of `kind` is stamped or derived
/// at, with a NOTE's world read from its live edges ([`NoteWorlds::axis`]).
/// Any other row keeps `scope`.
pub(crate) fn note_position(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    mut scope: Scope,
) -> Scope {
    if kind == ENTITY_TYPE_NOTE {
        scope.worlds = note_worlds_in(store, txn, id).axis();
    }
    scope
}

/// `record`, the position of the stored row `id` of `kind`, as a door that
/// reads under every Scope in `ceilings` holds it: a NOTE at one world of its
/// live edges they all hold, base reality first (`NOTE_MULTI_WORLD_POSITION`).
/// Any other row, and a NOTE under ceilings that leave worlds whole, keep
/// `record`.
pub(crate) fn held_at(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    record: &Scope,
    ceilings: &[&Scope],
) -> Scope {
    let mut held = record.clone();
    let ceiling = ceilings
        .iter()
        .fold(ScopeAxis::All, |worlds, scope| worlds.meet(&scope.worlds));
    if kind == ENTITY_TYPE_NOTE && !matches!(ceiling, ScopeAxis::All) {
        held.worlds = note_worlds_in(store, txn, id).axis_at(&ceiling);
    }
    held
}

/// [`super::record_world_in`] for a read under the world ceiling of
/// `ceiling`: a NOTE at one of its worlds the ceiling holds
/// ([`NoteWorlds::world_at`]); any other row where `record_world_in` places
/// it.
pub(crate) fn record_world_held_at(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
    ceiling: &Scope,
) -> Result<Option<Option<EntityId>>> {
    if kind != ENTITY_TYPE_NOTE {
        return super::record_world_in(store, txn, id, kind, data);
    }
    Ok(note_worlds_in(store, txn, id).world_at(&ceiling.worlds))
}

/// [`super::admits`] at a scoped door, `door` its selector, slip and
/// channel: the row held where the door holds it ([`held_at`]).
pub(super) fn admits_at(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    scope: &Scope,
    door: [&Scope; 3],
    verb: &str,
) -> bool {
    let [selector, slip, channel] = door;
    let held = held_at(store, txn, id, kind, scope, &door);
    super::admits(&held, selector, slip, channel, verb)
}

/// Whether a NOTE's later put, derived at `proposed`, keeps the position its
/// stamp holds, `prior`: every axis but its world, which its live edges give
/// at every read and its stamp only snapshots (`NOTE_WORLD_SOURCE`).
pub(super) fn live_world_kept(kind: u8, prior: &Scope, proposed: &Scope) -> bool {
    kind == ENTITY_TYPE_NOTE
        && match NOTE_WORLD_SOURCE {
            NoteWorldSource::LiveInWorldEdgeOnRead => {
                Scope {
                    worlds: proposed.worlds.clone(),
                    ..prior.clone()
                } == *proposed
            }
        }
}
