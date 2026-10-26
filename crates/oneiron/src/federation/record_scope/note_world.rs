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

use super::{MachineHistoryScope, Scope, ScopeAxis, ScopeId};
use crate::EntityId;
use crate::batch::EntityMetadataHeader;
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
    /// Its world witness under `ceiling` (`NOTE_MULTI_WORLD_POSITION`): base
    /// reality when it is in base and the ceiling holds base, else the
    /// smallest world it is in that the ceiling holds; `None` where `ceiling`
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

    /// The world axis of its one position, which a door that does not hold
    /// it at a ceiling reads: its one world; base reality when base is among
    /// several, so a base read keeps it; its worlds when base is not, held
    /// only by a ceiling that holds them all; every world when it is in no
    /// single one, held only by a ceiling that leaves worlds whole.
    pub(crate) fn axis(&self) -> ScopeAxis<ScopeId> {
        let base = ScopeId(crate::claim::base_world_id());
        match self {
            Self::In(worlds) if worlds.contains(&base) => ScopeAxis::Some(BTreeSet::from([base])),
            Self::In(worlds) => ScopeAxis::Some(worlds.clone()),
            Self::NoSingleWorld => ScopeAxis::All,
        }
    }

    /// Every world it is in, for a door that holds it per ceiling with
    /// [`any_world_at`]; every world when it is in no single one.
    fn every(&self) -> ScopeAxis<ScopeId> {
        match self {
            Self::In(worlds) => ScopeAxis::Some(worlds.clone()),
            Self::NoSingleWorld => ScopeAxis::All,
        }
    }

    /// The world axis a door reading under the world ceiling `ceiling`
    /// holds it at: its witness there, else [`Self::axis`].
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

    /// Whether a read under every world ceiling in `ceilings` reads it at
    /// all: a NOTE in base reality, alone or among others, always, as a base
    /// NOTE is read today, so gaining a world never loses it a reader; one
    /// only in other worlds where the ceilings leave worlds whole or hold one
    /// of them (`NOTE_MULTI_WORLD_POSITION`); one in no single world only
    /// where they leave worlds whole (`NOTE_WORLD_LOOKUP_FAULT`).
    pub(crate) fn readable_at(&self, ceilings: &[&ScopeAxis<ScopeId>]) -> bool {
        let base = ScopeId(crate::claim::base_world_id());
        let ceiling = met(ceilings);
        match self {
            Self::In(worlds) if worlds.contains(&base) => true,
            _ if matches!(ceiling, ScopeAxis::All) => true,
            _ => self.held(&ceiling).is_some(),
        }
    }
}

/// The worlds a run's read ledger notes for the stored row `id` of `kind`,
/// with body `data`, base reality by its own id: a NOTE in base reality as
/// base, as before FIX-LIST 9433; one only in other worlds as every world it
/// is in; any other row where [`super::record_world_in`] places it. `None`
/// where the row proves no world, a NOTE whose edges did not read among them.
pub(crate) fn served_worlds_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<Option<BTreeSet<EntityId>>> {
    let base = ScopeId(crate::claim::base_world_id());
    if kind != ENTITY_TYPE_NOTE {
        return Ok(super::record_world_in(store, txn, id, kind, data)?
            .map(|world| BTreeSet::from([world.unwrap_or(base.0)])));
    }
    Ok(match note_worlds_in(store, txn, id) {
        NoteWorlds::In(worlds) if worlds.contains(&base) => Some(BTreeSet::from([base.0])),
        NoteWorlds::In(worlds) => Some(worlds.into_iter().map(|world| world.0).collect()),
        NoteWorlds::NoSingleWorld => None,
    })
}

/// `world` as a world read reports it: base reality is `None`.
fn reported(world: ScopeId) -> Option<EntityId> {
    Some(world.0).filter(|world| *world != crate::claim::base_world_id())
}

/// The world axes in `ceilings`, met: every world where there is none.
fn met(ceilings: &[&ScopeAxis<ScopeId>]) -> ScopeAxis<ScopeId> {
    ceilings
        .iter()
        .fold(ScopeAxis::All, |worlds, ceiling| worlds.meet(ceiling))
}

/// A world-only Scope over `worlds`, every other axis whole.
fn world_scope(worlds: ScopeAxis<ScopeId>) -> Scope {
    Scope {
        worlds,
        ..Scope::top()
    }
}

/// The live worlds of the stored row `id` of `kind` when it is a NOTE.
pub(crate) fn note_worlds_of(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Option<NoteWorlds> {
    (kind == ENTITY_TYPE_NOTE).then(|| note_worlds_in(store, txn, id))
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

/// [`note_position`] carrying every world a NOTE is in, for a door that
/// holds it under each of its ceilings with [`any_world_at`].
pub(crate) fn every_world_position(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    mut scope: Scope,
) -> Scope {
    if kind == ENTITY_TYPE_NOTE {
        scope.worlds = note_worlds_in(store, txn, id).every();
    }
    scope
}

/// `record`, an [`every_world_position`], as a door whose world ceiling is
/// `ceiling` holds it: a NOTE in several worlds at its witness there. A
/// position in one world, every world or none keeps `record`; so does one
/// the ceiling holds no world of, which the door then refuses as before.
pub(crate) fn any_world_at(record: &Scope, ceiling: &ScopeAxis<ScopeId>) -> Scope {
    let mut held = record.clone();
    if let ScopeAxis::Some(worlds) = &record.worlds
        && worlds.len() > 1
        && let Some(world) = NoteWorlds::In(worlds.clone()).held(ceiling)
    {
        held.worlds = ScopeAxis::Some(BTreeSet::from([world]));
    }
    held
}

/// `record` as a door reading under every world ceiling in `ceilings` holds
/// a NOTE whose live worlds are `worlds`: at its witness under them all,
/// base reality first (`NOTE_MULTI_WORLD_POSITION`). No `worlds` (any other
/// row), and ceilings that leave worlds whole, keep `record`.
pub(crate) fn position_at(
    record: &Scope,
    worlds: Option<&NoteWorlds>,
    ceilings: &[&ScopeAxis<ScopeId>],
) -> Scope {
    let mut held = record.clone();
    let ceiling = met(ceilings);
    if let Some(worlds) = worlds
        && !matches!(ceiling, ScopeAxis::All)
    {
        held.worlds = worlds.axis_at(&ceiling);
    }
    held
}

/// [`position_at`] for the stored row `id` of `kind`, a NOTE's live worlds
/// read in `txn` on `store`.
pub(crate) fn held_at(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    record: &Scope,
    ceilings: &[&ScopeAxis<ScopeId>],
) -> Scope {
    if matches!(met(ceilings), ScopeAxis::All) {
        return record.clone();
    }
    let worlds = note_worlds_of(store, txn, id, kind);
    position_at(record, worlds.as_ref(), ceilings)
}

/// [`super::scope_for_blob`] of the stored row `raw` of `id`, held as a door
/// reading under every world ceiling in `ceilings` holds it ([`held_at`]).
pub(crate) fn blob_scope_held_at(
    store: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    ceilings: &[&ScopeAxis<ScopeId>],
) -> Result<Option<Scope>> {
    let kind = EntityMetadataHeader::parse(raw)
        .ok_or(crate::error::Error::CorruptedIndex("record header"))?
        .entity_type;
    Ok(super::scope_for_blob(store, txn, id, raw)?
        .map(|scope| held_at(store, txn, id, kind, &scope, ceilings)))
}

/// [`super::scope_for_blob`] of the stored row `raw` of `id` as an
/// [`every_world_position`].
pub(crate) fn blob_scope_every_world(
    store: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<Option<Scope>> {
    let kind = EntityMetadataHeader::parse(raw)
        .ok_or(crate::error::Error::CorruptedIndex("record header"))?
        .entity_type;
    Ok(super::scope_for_blob(store, txn, id, raw)?
        .map(|scope| every_world_position(store, txn, id, kind, scope)))
}

/// The world-only position of the stored row `id` of `kind`, with body
/// `data`, as a read under the world ceiling of `ceiling` holds it: a NOTE at
/// its witness there, else its one position; any other row where
/// [`super::record_world_in`] places it. `None` where the row proves no world.
pub(crate) fn world_record_held_at(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
    ceiling: &Scope,
) -> Result<Option<Scope>> {
    if kind == ENTITY_TYPE_NOTE {
        let worlds = note_worlds_in(store, txn, id).axis_at(&ceiling.worlds);
        return Ok(Some(world_scope(worlds)));
    }
    let base = crate::claim::base_world_id();
    Ok(
        super::record_world_in(store, txn, id, kind, data)?.map(|world| {
            world_scope(ScopeAxis::Some(BTreeSet::from([ScopeId(
                world.unwrap_or(base),
            )])))
        }),
    )
}

/// [`super::record_world_in`] for a read that holds a world where `holds`
/// says so: a NOTE at its first world `holds` admits, base reality first,
/// else its one world ([`NoteWorlds::world`]). With no `holds`, a NOTE is
/// classified as base reality, as before FIX-LIST 9433 (a stale-world
/// exclusion or partition that no reader's world ceiling binds); its live
/// worlds bind at the row doors.
pub(crate) fn record_world_where(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
    holds: Option<&dyn Fn(Option<EntityId>) -> bool>,
) -> Result<Option<Option<EntityId>>> {
    if kind != ENTITY_TYPE_NOTE {
        return super::record_world_in(store, txn, id, kind, data);
    }
    let Some(holds) = holds else {
        return Ok(Some(None));
    };
    let worlds = note_worlds_in(store, txn, id);
    let NoteWorlds::In(set) = &worlds else {
        return Ok(None);
    };
    let base = ScopeId(crate::claim::base_world_id());
    let mut ordered = set
        .get(&base)
        .into_iter()
        .chain(set.iter().filter(|world| **world != base));
    Ok(ordered
        .find(|world| holds(reported(**world)))
        .map(|world| reported(*world))
        .or_else(|| worlds.world()))
}

/// A NOTE source's one position as an answer resting on it records it: its
/// witness under every world ceiling in `ceilings`; base reality, as before
/// FIX-LIST 9433, where they leave worlds whole or hold none of its worlds
/// (its read gate keeps such a source out first). Any other row keeps
/// `scope`.
pub(crate) fn source_position(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    mut scope: Scope,
    ceilings: &[&ScopeAxis<ScopeId>],
) -> Scope {
    if kind == ENTITY_TYPE_NOTE {
        let base = ScopeId(crate::claim::base_world_id());
        let world = note_worlds_in(store, txn, id)
            .held(&met(ceilings))
            .unwrap_or(base);
        scope.worlds = ScopeAxis::Some(BTreeSet::from([world]));
    }
    scope
}

/// The worlds a sync selector's `world` reads, as a ceiling: every world,
/// base reality alone, or base reality and its one world.
#[cfg(feature = "sync")]
pub(crate) fn selector_world_axis(world: crate::sync::SyncSelectorWorld) -> ScopeAxis<ScopeId> {
    let base = ScopeId(crate::claim::base_world_id());
    match world {
        crate::sync::SyncSelectorWorld::All => ScopeAxis::All,
        crate::sync::SyncSelectorWorld::Base => ScopeAxis::Some(BTreeSet::from([base])),
        crate::sync::SyncSelectorWorld::World(world) => {
            ScopeAxis::Some(BTreeSet::from([base, ScopeId(world.entity_id())]))
        }
    }
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
    let ceilings = [&selector.worlds, &slip.worlds, &channel.worlds];
    let held = held_at(store, txn, id, kind, scope, &ceilings);
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

impl crate::Vault {
    /// Whether the NOTE `id` sits in `world` now, by any of its live
    /// `InWorld` edges, as a door holding it under the one-world ceiling
    /// `{world}` places it (FIX 10373). An edge-less NOTE sits in base reality
    /// alone; one whose edges do not read sits in no world.
    ///
    /// # Errors
    ///
    /// Returns the store's error when its read transaction does not open.
    pub fn note_in_world(&self, id: &EntityId, world: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(match note_worlds_in(&self.store, &txn, *id) {
            NoteWorlds::In(worlds) => worlds.contains(&ScopeId(world)),
            NoteWorlds::NoSingleWorld => false,
        })
    }
}
