//! Routing and world-edge planning of admitted rows.
//! The entry point is `Routes::plan`.
//! Owned by `super`.

use std::collections::{BTreeMap, BTreeSet};

use loro::LoroDoc;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSubject, validate_claim_body_and_decode};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD};
use crate::sync::loro_support::{map_for_each_value_bytes, map_get_bytes, map_insert_bytes};
use crate::sync::types::WindowKey;

/// Where each row of an update the federation door admits lands (FIX 3497).
///
/// A guest's CLAIM lands in a foreign WORLD copy, never in the sender's world
/// or base here (ARCH-0043): its world is rewritten to the foreign id its
/// source vault and the sender's world derive, and window residence keeps a
/// CLAIM in its world's window. An update in one of the sender's WORLD
/// windows therefore lands whole in that world's foreign window. In a base
/// window only its base CLAIMs move, each to its month's window of the
/// sender's base copy, with each edge whose world endpoint is such a CLAIM
/// or a foreign-world CLAIM this vault stores; every other row stays in the
/// update's own window, part 0, which imports first. A guest CLAIM a MACHINE
/// proof binds is withheld whole with every edge naming it
/// ([`crate::federation::guest_claim_withheld`]). An admission with no guest
/// source, member content among them, routes nothing.
///
/// A WORLD row the guest sends lands under its foreign id, the one its CLAIMs
/// in that world now name, in the window it came in (FIX 3657). The target of
/// an InWorld or SetIn edge is a WORLD by the edge's kind (ARCH-0022), so it
/// names that foreign id even before its WORLD row arrives, and so does the
/// target of the edge a CLAIM is about (FIX 3891). A source names it only
/// once its WORLD row is proven. A target the same update carries as a row of
/// another kind refuses that edge, or that CLAIM, alone. An edge whose two
/// endpoints are proven to sit in two different worlds, one of them foreign,
/// is quarantined alone ([`contains_cross_world_edge`], FIX 3660, FIX 3893).
#[cfg(feature = "sync")]
pub(super) struct Routes<'a> {
    /// The window each part imports into, part 0 first.
    pub(super) keys: Vec<WindowKey>,
    /// The source vault a guest's pact names.
    guest: Option<&'a [u8; 32]>,
    /// The part each moved CLAIM lands in.
    claims: BTreeMap<EntityId, usize>,
    /// The guest CLAIMs withheld whole, and those a WORLD target the update
    /// carries as another kind refuses (FIX 3891).
    withheld: BTreeSet<EntityId>,
    /// The part each moved edge lands in, by its key; `None` drops it.
    edges: BTreeMap<String, Option<usize>>,
    /// The guest's WORLDs that land under foreign ids here, by the sender's
    /// id (FIX 3657).
    pub(super) worlds: BTreeMap<EntityId, EntityId>,
    /// The key each edge naming one of those WORLDs lands under, by its own.
    rekeyed: BTreeMap<String, String>,
}

/// A guest's update as its rows are copied: the source vault its pact names
/// and the WORLDs that land under foreign ids here ([`Routes::worlds`]).
#[cfg(feature = "sync")]
#[derive(Clone, Copy)]
pub(super) struct GuestCopy<'a> {
    pub(super) source: &'a [u8; 32],
    pub(super) worlds: &'a BTreeMap<EntityId, EntityId>,
}

#[cfg(feature = "sync")]
impl<'a> Routes<'a> {
    /// One part, in the update's own window, that rewrites nothing.
    pub(super) fn unrouted(key: &WindowKey) -> Self {
        Self {
            keys: vec![key.clone()],
            guest: None,
            claims: BTreeMap::new(),
            withheld: BTreeSet::new(),
            edges: BTreeMap::new(),
            worlds: BTreeMap::new(),
            rekeyed: BTreeMap::new(),
        }
    }

    /// The routes of a guest's update from the source vault `guest`. Each
    /// withheld CLAIM, each contained cross-world edge, and each edge or
    /// CLAIM whose WORLD target the update carries as another kind is
    /// recorded in `terminal`. A row or edge whose bytes do not read routes
    /// to part 0, where admission refuses it.
    pub(super) fn plan(
        vault: &Vault,
        key: &WindowKey,
        remote: &LoroDoc,
        guest: &'a [u8; 32],
        terminal: &mut crate::sync::quarantine::TerminalRejectionBatch,
    ) -> Result<Self> {
        let own = match key.world() {
            Some(world) => WindowKey::for_month_world(
                key,
                crate::federation::foreign_world_for(guest, world)?.entity_id(),
            ),
            None => key.clone(),
        };
        let mut routes = Self {
            keys: vec![own],
            guest: Some(guest),
            ..Self::unrouted(key)
        };
        let mut placed = Placement::new(guest);
        let mut moved = Vec::new();
        // The kind of each row the update carries, its WORLD rows among them.
        // Only these say an edge's WORLD target is no WORLD (FIX 3891).
        let carried = carried_kinds(&remote.get_map("entities"));
        let carried_worlds = carried
            .iter()
            .filter(|(_, kind)| **kind == ENTITY_TYPE_WORLD)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        // The ids an InWorld or SetIn edge, or a CLAIM about one, names as
        // its source, which may be WORLDs, and as its target, which its kind
        // types a WORLD (FIX 3891).
        let mut named = BTreeSet::new();
        let mut typed_world_targets = BTreeSet::new();
        map_for_each_value_bytes(&remote.get_map("entities"), |raw, blob| {
            let (Some(blob), Ok(id)) = (blob, EntityId::from_hex(raw)) else {
                return;
            };
            let Some(header) = EntityMetadataHeader::parse(blob) else {
                return;
            };
            if id.to_hex() != raw || header.entity_type != ENTITY_TYPE_CLAIM {
                return;
            }
            let Ok(body) =
                validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)
            else {
                return;
            };
            if let Some(refusal) = crate::federation::guest_claim_withheld(&body) {
                terminal.push(
                    crate::sync::quarantine::QuarantineContainer::Entities,
                    raw,
                    &refusal,
                    blob,
                );
                routes.withheld.insert(id);
                return;
            }
            if let Some([source, target]) = world_edge_subject(&body.subject) {
                if carried_as_non_world(&carried, target) {
                    terminal.push(
                        crate::sync::quarantine::QuarantineContainer::Entities,
                        raw,
                        &typed_world_target_refusal(),
                        blob,
                    );
                    routes.withheld.insert(id);
                    return;
                }
                named.insert(source);
                typed_world_targets.insert(target);
            }
            placed.claims.insert(id, body.world);
            if key.world().is_none() && body.world.is_none() {
                moved.push((id, header.learned_at));
            }
        });
        if !moved.is_empty() {
            let base = placed.foreign_of(None)?;
            for (id, learned_at) in moved {
                let part = routes.part(WindowKey::for_world(learned_at, base));
                routes.claims.insert(id, part);
            }
        }
        let remote_edges = remote.get_map("edges");
        let mut edges = Vec::new();
        map_for_each_value_bytes(&remote_edges, |raw, value| {
            let Some((src, kind, tgt)) = super::super::bridge::parse_edge_key(raw) else {
                return;
            };
            // An edge naming a withheld CLAIM is dropped below, and names
            // nothing.
            if is_world_edge(kind)
                && !routes.withheld.contains(&src)
                && !routes.withheld.contains(&tgt)
            {
                if carried_as_non_world(&carried, tgt) {
                    terminal.push(
                        crate::sync::quarantine::QuarantineContainer::Edges,
                        raw,
                        &typed_world_target_refusal(),
                        value.unwrap_or_default(),
                    );
                    routes.edges.insert(raw.to_owned(), None);
                    return;
                }
                named.insert(src);
                typed_world_targets.insert(tgt);
            }
            edges.push((raw.to_owned(), (src, kind, tgt)));
        });
        routes.rename_worlds(vault, guest, carried_worlds, typed_world_targets, named)?;
        for (raw, (src, kind, tgt)) in edges {
            if routes.withheld.contains(&src) || routes.withheld.contains(&tgt) {
                routes.edges.insert(raw, None);
                continue;
            }
            let src_world = placed.proven_world(vault, src)?;
            let tgt_world = match src_world {
                Some(_) => placed.proven_world(vault, tgt)?,
                None => None,
            };
            if contains_cross_world_edge(src_world, tgt_world) {
                terminal.push(
                    crate::sync::quarantine::QuarantineContainer::Edges,
                    &raw,
                    &cross_world_edge_refusal(),
                    &map_get_bytes(&remote_edges, &raw).unwrap_or_default(),
                );
                routes.edges.insert(raw, None);
                continue;
            }
            routes.rekey(&raw, (src, kind, tgt));
            if key.world().is_some() {
                continue;
            }
            // A world edge rides its world endpoint's window, the source's
            // first (`edge_belongs_to_window`): a moved CLAIM's, or a foreign
            // WORLD's this vault stores the endpoint in.
            for end in [src, tgt] {
                let moved = routes.claims.get(&end).copied();
                let part = match moved {
                    Some(part) => Some(part),
                    None => placed
                        .stored_window(vault, end)?
                        .filter(|window| {
                            window
                                .world()
                                .is_some_and(crate::entity_id::is_foreign_world_id_range)
                        })
                        .map(|window| routes.part(window)),
                };
                if let Some(part) = part {
                    routes.edges.insert(raw, Some(part));
                    break;
                }
            }
        }
        Ok(routes)
    }

    /// Names the guest's WORLDs that land under foreign ids here (FIX 3657,
    /// FIX 3891): each `carried` WORLD row; each id in `typed_world_targets`,
    /// the target an InWorld or SetIn edge, or a CLAIM about one, names,
    /// which the edge's kind types a WORLD (ARCH-0022) before its row
    /// arrives; and each other `named` id whose foreign copy this vault
    /// already stores as a WORLD row, which only that WORLD's earlier copy
    /// from `guest` puts there. Any other id keeps its own, PERSON and CLAIM
    /// sources among them.
    fn rename_worlds(
        &mut self,
        vault: &Vault,
        guest: &[u8; 32],
        carried: Vec<EntityId>,
        typed_world_targets: BTreeSet<EntityId>,
        named: BTreeSet<EntityId>,
    ) -> Result<()> {
        for id in carried {
            let here = crate::federation::foreign_world_for(guest, id)?.entity_id();
            self.worlds.insert(id, here);
        }
        for id in typed_world_targets {
            self.worlds.insert(
                id,
                crate::federation::foreign_world_for(guest, id)?.entity_id(),
            );
        }
        for id in named {
            if self.worlds.contains_key(&id) {
                continue;
            }
            let here = crate::federation::foreign_world_for(guest, id)?.entity_id();
            let stored = vault.get_raw_unsealed(&here)?;
            if stored
                .as_deref()
                .and_then(EntityMetadataHeader::parse)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_WORLD)
            {
                self.worlds.insert(id, here);
            }
        }
        Ok(())
    }

    /// Lands the edge keyed `raw` under the key its renamed WORLD endpoints
    /// name, when it is an InWorld or SetIn edge naming one (FIX 3657).
    fn rekey(&mut self, raw: &str, (src, kind, tgt): (EntityId, EdgeKind, EntityId)) {
        if !is_world_edge(kind) {
            return;
        }
        let here = |id: EntityId| self.worlds.get(&id).copied().unwrap_or(id);
        let (to_src, to_tgt) = (here(src), here(tgt));
        if (to_src, to_tgt) != (src, tgt) {
            let key = super::super::bridge::format_edge_key(&to_src, kind, &to_tgt);
            self.rekeyed.insert(raw.to_owned(), key);
        }
    }

    /// The guest's update as its rows are copied; `None` with no guest
    /// source.
    pub(super) fn guest_copy(&self) -> Option<GuestCopy<'_>> {
        self.guest.map(|source| GuestCopy {
            source,
            worlds: &self.worlds,
        })
    }

    /// The part landing in `window`, a new one when none does yet.
    fn part(&mut self, window: WindowKey) -> usize {
        match self.keys.iter().position(|key| *key == window) {
            Some(part) => part,
            None => {
                self.keys.push(window);
                self.keys.len() - 1
            }
        }
    }

    /// The part the entity keyed `raw` lands in; `None` withholds it.
    pub(super) fn entity_part(&self, raw: &str) -> Option<usize> {
        match EntityId::from_hex(raw) {
            Ok(id) if id.to_hex() == raw => {
                (!self.withheld.contains(&id)).then(|| self.claims.get(&id).copied().unwrap_or(0))
            }
            _ => Some(0),
        }
    }

    /// The edges `part` copies, when they are not the whole update's, each
    /// under the key it lands under.
    pub(super) fn edges_of(&self, remote: &LoroDoc, part: usize) -> Result<Option<LoroDoc>> {
        if self.withheld.is_empty()
            && self.edges.is_empty()
            && self.rekeyed.is_empty()
            && self.keys.len() == 1
        {
            return Ok(None);
        }
        let routed = LoroDoc::new();
        let edges = routed.get_map("edges");
        let mut result = Ok(());
        map_for_each_value_bytes(&remote.get_map("edges"), |raw, value| {
            if result.is_ok()
                && self.edges.get(raw).copied().unwrap_or(Some(0)) == Some(part)
                && let Some(value) = value
            {
                let key = self.rekeyed.get(raw).map_or(raw, String::as_str);
                result = map_insert_bytes(&edges, key, value);
            }
        });
        result.map(|()| Some(routed))
    }
}

/// Where the endpoints of a guest's edges sit here once its CLAIMs land in
/// their foreign WORLDs (FIX 3660): a carried CLAIM in the foreign WORLD its
/// sender's world maps to, any other in the world this vault stores it in,
/// a foreign WORLD or one of its own (FIX 3893). Each is read once.
#[cfg(feature = "sync")]
struct Placement<'a> {
    guest: &'a [u8; 32],
    /// Each carried CLAIM the update does not withhold, with its world as
    /// the sender names it.
    claims: BTreeMap<EntityId, Option<EntityId>>,
    /// Each sender world's foreign WORLD, once derived.
    foreign: BTreeMap<Option<EntityId>, EntityId>,
    /// Each stored row's world window, once read.
    stored: BTreeMap<EntityId, Option<WindowKey>>,
}

#[cfg(feature = "sync")]
impl<'a> Placement<'a> {
    const fn new(guest: &'a [u8; 32]) -> Self {
        Self {
            guest,
            claims: BTreeMap::new(),
            foreign: BTreeMap::new(),
            stored: BTreeMap::new(),
        }
    }

    /// The foreign WORLD the guest CLAIM in the sender's `world` lands in.
    fn foreign_of(&mut self, world: Option<EntityId>) -> Result<EntityId> {
        if let Some(here) = self.foreign.get(&world) {
            return Ok(*here);
        }
        let here = crate::federation::guest_claim_world(self.guest, world)?.entity_id();
        self.foreign.insert(world, here);
        Ok(here)
    }

    /// The world `id` is proven to sit in here, a foreign WORLD or one of
    /// this vault's own (FIX 3893); `None` when it sits in none, or nothing
    /// here proves where it sits.
    fn proven_world(&mut self, vault: &Vault, id: EntityId) -> Result<Option<EntityId>> {
        if let Some(world) = self.claims.get(&id).copied() {
            return self.foreign_of(world).map(Some);
        }
        Ok(self
            .stored_window(vault, id)?
            .and_then(|window| window.world()))
    }

    /// The window a CLAIM this vault stores in a world resides in.
    fn stored_window(&mut self, vault: &Vault, id: EntityId) -> Result<Option<WindowKey>> {
        if let Some(window) = self.stored.get(&id) {
            return Ok(window.clone());
        }
        let window = stored_world_window(vault, &id)?;
        self.stored.insert(id, window.clone());
        Ok(window)
    }
}

/// Whether an edge of `kind` places its endpoints in a world, one of them a
/// WORLD.
#[cfg(feature = "sync")]
const fn is_world_edge(kind: EdgeKind) -> bool {
    matches!(kind, EdgeKind::InWorld | EdgeKind::SetIn)
}

/// The endpoints of the InWorld or SetIn edge a CLAIM is about.
#[cfg(feature = "sync")]
const fn world_edge_subject(subject: &ClaimSubject) -> Option<[EntityId; 2]> {
    match *subject {
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } if is_world_edge(kind) => Some([source, target]),
        _ => None,
    }
}

/// The kind of each row `entities` carries, by its canonical hex id.
#[cfg(feature = "sync")]
fn carried_kinds(entities: &loro::LoroMap) -> BTreeMap<EntityId, u8> {
    let mut kinds = BTreeMap::new();
    map_for_each_value_bytes(entities, |raw, blob| {
        if let (Some(header), Ok(id)) = (
            blob.and_then(EntityMetadataHeader::parse),
            EntityId::from_hex(raw),
        ) && id.to_hex() == raw
        {
            kinds.insert(id, header.entity_type);
        }
    });
    kinds
}

/// Whether the update carries `target`, the target of an InWorld or SetIn
/// edge, as a row of another kind than WORLD (FIX 3891). Only the update's
/// own rows say so: a row this vault stores at the sender's id is not the
/// sender's.
#[cfg(feature = "sync")]
fn carried_as_non_world(carried: &BTreeMap<EntityId, u8>, target: EntityId) -> bool {
    carried
        .get(&target)
        .is_some_and(|kind| *kind != ENTITY_TYPE_WORLD)
}

/// A guest CLAIM about an InWorld or SetIn edge names the edge by the ids
/// its copy lands under (FIX 3657).
#[cfg(feature = "sync")]
pub(super) fn rename_world_edge_subject(
    subject: &mut ClaimSubject,
    worlds: &BTreeMap<EntityId, EntityId>,
) {
    if let ClaimSubject::Edge {
        source,
        kind,
        target,
    } = subject
        && is_world_edge(*kind)
    {
        for end in [source, target] {
            if let Some(here) = worlds.get(&*end) {
                *end = *here;
            }
        }
    }
}

/// The policy hook for a guest's edge whose endpoints are proven to sit in
/// two different worlds here, at least one of them a foreign WORLD (FIX 3660,
/// FIX 3893; CALLS "FIX 3660 cross-world edge containment" and "FIX 3893
/// foreign/local edge containment"). Such an edge fits no window
/// (`edge_worlds_match`), and the Engine keeps it refused (CALLS "FIX 3497
/// base-window guest split"): a guest's join into one of this vault's own
/// worlds stays refused. Given the world each endpoint is proven to sit in,
/// this says whether the refusal stops at the edge: it is quarantined
/// terminally before it enters the copied doc, so the rows and edges beside
/// it still land, rather than left in its part for window residence to
/// refuse the part whole. An endpoint nothing proves (`None`) is never taken
/// as base or as any world, and an edge between two of this vault's own
/// worlds is left as it was.
#[cfg(feature = "sync")]
fn contains_cross_world_edge(src: Option<EntityId>, tgt: Option<EntityId>) -> bool {
    matches!((src, tgt), (Some(src), Some(tgt)) if src != tgt
        && (crate::entity_id::is_foreign_world_id_range(src)
            || crate::entity_id::is_foreign_world_id_range(tgt)))
}

/// The refusal a contained cross-world edge is quarantined under: the one
/// window residence gives it (`check_edge_residence`).
#[cfg(feature = "sync")]
fn cross_world_edge_refusal() -> Error {
    Error::InvalidConfig("edge outside window residence".into())
}

/// The refusal an InWorld or SetIn edge, or a guest CLAIM about one, is
/// quarantined under when the same update carries its target as a row of
/// another kind than WORLD (FIX 3891).
#[cfg(feature = "sync")]
fn typed_world_target_refusal() -> Error {
    Error::InvalidConfig("world edge target is not a WORLD".into())
}

/// The window a CLAIM this vault stores in a world, a foreign WORLD or one
/// of its own, resides in; `None` for a base row or a row it does not store.
#[cfg(feature = "sync")]
fn stored_world_window(vault: &Vault, id: &EntityId) -> Result<Option<WindowKey>> {
    let Some(raw) = vault.get_raw_unsealed(id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    Ok(crate::sync::types::entity_world(&raw)
        .ok()
        .flatten()
        .map(|world| WindowKey::for_world(header.learned_at, world)))
}
