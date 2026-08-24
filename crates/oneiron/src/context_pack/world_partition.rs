//! Federated multi-world partitioning and staleness annotation
//! (ARCH-0004 / ARCH-0022 / ONE-1411).

use std::collections::{BTreeMap, HashMap};

use heed::RoTxn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD};
use crate::store::Store;

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

/// ARCH-0004 / ARCH-0022 world partitioning for an `All`-scope pack: reorders
/// `results` so claims are grouped by world — the base section (claims with no
/// `world` key plus every non-claim entity) first, then one section per
/// non-base world (sections ordered by their highest-scoring claim; score
/// order preserved within a section). A per-non-base-world cap drops the
/// lowest-scoring fiction so non-base worlds occupy at most `non_base_fraction`
/// of the claim budget (every CLAIM in the pack), keeping all base claims.
///
/// When no non-base claim survives, `results` are left flat in score order.
pub(super) fn partition_results_by_world(
    store: &Store,
    rtxn: &RoTxn<'_>,
    results: &mut Vec<ContextEntity>,
    non_base_fraction: f32,
    claim_bodies: &HashMap<EntityId, ClaimBody>,
) -> Result<()> {
    let mut base: Vec<ContextEntity> = Vec::with_capacity(results.len());
    let mut non_base: Vec<(EntityId, ContextEntity)> = Vec::new();

    for entity in results.drain(..) {
        match entity_world(store, rtxn, &entity, claim_bodies)? {
            None => base.push(entity),
            Some(world) => non_base.push((world, entity)),
        }
    }

    // No fictional / dream claim survived — leave the pack flat (score order).
    if non_base.is_empty() {
        *results = base;
        return Ok(());
    }

    // Claim budget = every CLAIM in the pack (base claims + non-base claims);
    // non-claim base entities do not count. Non-base worlds share at most
    // `non_base_fraction` of it.
    let base_claim_count = base
        .iter()
        .filter(|entity| entity.entity_type == ENTITY_TYPE_CLAIM)
        .count();
    let claim_budget = base_claim_count + non_base.len();
    let non_base_cap = ((claim_budget as f32) * non_base_fraction).floor().max(0.0) as usize;

    // `non_base` is in score order (results arrive score-sorted). Keep the top
    // `non_base_cap` by score and drop the rest so fiction cannot crowd base
    // reality out.
    non_base.truncate(non_base_cap);

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
    Ok(())
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
    store: &Store,
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
/// (a non-claim entity, or a claim with no `world` key) and `Some(world_id)`
/// for a world-scoped claim. The `world` key was structurally validated to a
/// 16-byte id at write time.
///
/// Every result CLAIM passed the pipeline D19 gate, so its body is already in
/// `claim_bodies`: reuse that decode instead of a second MessagePack pass,
/// keeping the claim body decoded ONCE per result for gate + projection +
/// world grouping (D19 AC 9). The raw-read fallback only covers a defensive
/// cache miss.
fn entity_world(
    store: &Store,
    rtxn: &RoTxn<'_>,
    entity: &ContextEntity,
    claim_bodies: &HashMap<EntityId, ClaimBody>,
) -> Result<Option<EntityId>> {
    if entity.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    if let Some(body) = claim_bodies.get(&entity.id) {
        return Ok(body.world);
    }
    claim_world_by_id(store, rtxn, &entity.id)
}

/// Reads a claim's world straight off the stored row, by id.
///
/// The door for paths holding neither a hydrated row nor a decoded body: edge
/// expansion sees bare targets. Non-claims, absent rows, and bodies with no
/// `world` key are base reality (`None`); a claim body that fails to decode
/// fails closed, exactly as the pipeline's world filter does.
pub(super) fn claim_world_by_id(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM || raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }
    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(|body| body.world)
}
