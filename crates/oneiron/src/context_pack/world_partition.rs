//! Federated multi-world partitioning and staleness annotation
//! (ARCH-0004 / ARCH-0022 / ONE-1411).

use crate::ports::EntityStoreRead;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use heed::RoTxn;

use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD};
use crate::store::StoreRead;

use super::types::ContextEntity;

pub(super) fn resolve_edge_short_ids(
    results: &mut [ContextEntity],
    neighbors: &mut [ContextEntity],
) {
    let mut index = HashMap::<EntityId, String>::new();
    for entity in results.iter().chain(neighbors.iter()) {
        index.insert(entity.id, entity.short_id.clone());
    }

    for entity in results.iter_mut().chain(neighbors.iter_mut()) {
        let Some(edges) = entity.edges.as_mut() else {
            continue;
        };

        for edge in edges.iter_mut() {
            if let Some(short_id) = index.get(&edge.target) {
                edge.target_short_id = Some(short_id.clone());
            }
        }
    }
}

/// ARCH-0004 / ARCH-0022 world partitioning for an `All`-scope pack, run once
/// over the rows it emits (FIX 9759): reorders `results` so rows are grouped
/// by world — the base section (claims with no `world` key plus every other
/// base-reality record) first, then one section per non-base world, which
/// also holds a TASK born there (sections ordered by their highest-scoring
/// row; score order preserved within a section). Non-base claims stay at most
/// `floor(non_base_fraction × unique claims results and neighbors emit)`
/// (`pipeline::non_base_claim_cap`), keeping every base claim. The non-base
/// claims kept are the critical ones first, then the rest, each in rank
/// order: results by score, then neighbors in walk order (FIX 9760). Returns
/// the critical claims the share left out, and the non-base claims it kept.
///
/// When no non-base row survives, `results` are left flat in score order.
pub(super) fn partition_pack_claims(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    results: &mut Vec<ContextEntity>,
    neighbors: &mut Vec<ContextEntity>,
    non_base_fraction: f32,
    claim_bodies: &HashMap<EntityId, ClaimBody>,
) -> Result<(Vec<EntityId>, BTreeSet<EntityId>)> {
    let mut result_worlds = Vec::with_capacity(results.len());
    for entity in results.iter() {
        result_worlds.push(entity_world(store, rtxn, entity, claim_bodies)?);
    }
    let mut neighbor_worlds = Vec::with_capacity(neighbors.len());
    for entity in neighbors.iter() {
        neighbor_worlds.push(entity_world(store, rtxn, entity, claim_bodies)?);
    }

    // Only CLAIMs share, each counted once; other records do not count.
    let mut base_claims = HashSet::new();
    let mut non_base_claims: Vec<(EntityId, bool)> = Vec::new();
    let mut seen_non_base = HashSet::new();
    for (entity, world) in results
        .iter()
        .zip(&result_worlds)
        .chain(neighbors.iter().zip(&neighbor_worlds))
    {
        if entity.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        if world.is_none() {
            base_claims.insert(entity.id);
        } else if seen_non_base.insert(entity.id) {
            non_base_claims.push((entity.id, entity.critical));
        }
    }
    let non_base_cap = crate::pipeline::non_base_claim_cap(
        base_claims.len(),
        non_base_claims.len(),
        non_base_fraction,
    );
    let mut kept_claims = BTreeSet::new();
    for critical_pass in [true, false] {
        for (id, critical) in &non_base_claims {
            if *critical == critical_pass && kept_claims.len() < non_base_cap {
                kept_claims.insert(*id);
            }
        }
    }
    let dropped_critical: Vec<EntityId> = non_base_claims
        .iter()
        .filter(|(id, critical)| *critical && !kept_claims.contains(id))
        .map(|(id, _)| *id)
        .collect();
    let emitted = |entity: &ContextEntity, world: &Option<EntityId>| {
        entity.entity_type != ENTITY_TYPE_CLAIM
            || world.is_none()
            || kept_claims.contains(&entity.id)
    };

    let mut kept_neighbors = Vec::with_capacity(neighbors.len());
    for (entity, world) in neighbors.drain(..).zip(&neighbor_worlds) {
        if emitted(&entity, world) {
            kept_neighbors.push(entity);
        }
    }
    *neighbors = kept_neighbors;

    let mut base: Vec<ContextEntity> = Vec::with_capacity(results.len());
    let mut non_base: Vec<(EntityId, ContextEntity)> = Vec::new();
    for (entity, world) in results.drain(..).zip(result_worlds) {
        if !emitted(&entity, &world) {
            continue;
        }
        match world {
            None => base.push(entity),
            Some(world) => non_base.push((world, entity)),
        }
    }

    // No fictional / dream row survived — leave the pack flat (score order).
    if non_base.is_empty() {
        *results = base;
        return Ok((dropped_critical, kept_claims));
    }

    // Group survivors by world; sections ordered by first (highest-score)
    // appearance, score order preserved within each section.
    let mut world_order: Vec<EntityId> = Vec::new();
    let mut groups: HashMap<EntityId, Vec<ContextEntity>> = HashMap::new();
    for (world, entity) in non_base {
        if !groups.contains_key(&world) {
            world_order.push(world);
        }
        groups.entry(world).or_default().push(entity);
    }

    let mut out = base;
    for world in world_order {
        if let Some(section) = groups.remove(&world) {
            out.extend(section);
        }
    }
    *results = out;
    Ok((dropped_critical, kept_claims))
}

/// Hydrated-field key carrying the ONE-1411 stale-federation marker.
///
/// A dedicated key rather than a rewrite of an existing one: the marker is
/// ADDITIVE, so every field a stale-world row already carried still reads back
/// exactly as it did before its pact died.
///
/// Designed in canon (eiri/context, ARCH-0004, eiri-arch-0016); unwired as of
/// 2026-08-19 — needs wiring/design completion.
pub const WORLD_STALE_FIELD: &str = "world_stale";

/// Appends the ONE-1411 stale marker to every surfaced stale-world row.
///
/// Applies to the two ways a world reaches a pack: a world-scoped CLAIM, and
/// the WORLD entity itself — the row that heads its section. The caller owns
/// the stamp set so results and neighbors are marked from ONE read per pack.
pub(super) fn annotate_stale_federated_worlds(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    stale: &BTreeMap<EntityId, crate::federation::WorldStaleStamp>,
    results: &mut [ContextEntity],
    claim_bodies: &HashMap<EntityId, ClaimBody>,
) -> Result<()> {
    if stale.is_empty() {
        return Ok(());
    }

    for entity in results.iter_mut() {
        let world = if entity.entity_type == ENTITY_TYPE_WORLD {
            Some(entity.id)
        } else {
            entity_world(store, rtxn, entity, claim_bodies)?
        };
        let Some(stamp) = world.and_then(|world| stale.get(&world)) else {
            continue;
        };
        // Unhydrated packs carry no field map at all; there is nothing to
        // append to, and inventing one would change the pack's shape.
        let Some(fields) = entity.fields.as_mut() else {
            continue;
        };
        fields.insert(
            WORLD_STALE_FIELD.to_owned(),
            serde_json::Value::String(crate::federation::world_stale_marker(*stamp)),
        );
    }
    Ok(())
}

/// Reads a hydrated result's world for partitioning: `None` for base reality
/// and `Some(world_id)` for a world-scoped claim or a TASK born in that world
/// (see [`record_world_by_id`]). The `world` key was structurally validated
/// to a 16-byte id at write time.
///
/// Every result CLAIM passed the pipeline D19 gate, so its body is already in
/// `claim_bodies`: reuse that decode instead of a second MessagePack pass,
/// keeping the claim body decoded ONCE per result for gate + projection +
/// world grouping (D19 AC 9). The raw-read fallback only covers a defensive
/// cache miss.
fn entity_world(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    entity: &ContextEntity,
    claim_bodies: &HashMap<EntityId, ClaimBody>,
) -> Result<Option<EntityId>> {
    if entity.entity_type == ENTITY_TYPE_CLAIM
        && let Some(body) = claim_bodies.get(&entity.id)
    {
        return Ok(body.world);
    }
    record_world_by_id(store, rtxn, &entity.id)
}

/// Reads a row's world straight off the stored row, by id, by the rule every
/// world check reads (`record_scope::record_world_in`).
///
/// The door for paths holding neither a hydrated row nor a decoded body: edge
/// expansion sees bare targets. A claim names its own world and a TASK or its
/// authority fact the world it was born in. Every other record, an absent
/// row, a claim body with no `world` key, and a TASK that cannot prove its
/// world are base reality (`None`): no check here limits a pack to a world,
/// so an unknown world is never a stale one. A claim body that fails to
/// decode fails closed, exactly as the pipeline's world filter does.
pub(super) fn record_world_by_id(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(raw) = store.port_entity_record(rtxn, id)? else {
        return Ok(None);
    };
    if raw.entity_type != ENTITY_TYPE_CLAIM {
        // A NOTE keeps base reality here; its live worlds bind at the row
        // doors (FIX-LIST 9433).
        return Ok(
            crate::federation::record_scope::note_world::record_world_where(
                store,
                rtxn,
                *id,
                raw.entity_type,
                &raw.body,
                None,
            )?
            .flatten(),
        );
    }
    if raw.body.is_empty() {
        return Ok(None);
    }
    crate::claim::decode_claim_body(&raw.body, true).map(|body| body.world)
}
