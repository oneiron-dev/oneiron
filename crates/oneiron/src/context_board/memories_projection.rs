//! MEMORIES projection with source labels, world fences, and one shared render budget.

use super::memories::{
    CompanionAssembly, MEMORIES_SECTION_VERSION_V4, MemoriesBudget, MemoriesSection, MemoryRow,
    MemorySlot, MemorySource, MemoryTier,
};
use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::context_pack::{ContextEntity, ContextPack};
use crate::disclosure::DisclosureAssembly;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};

/// Builds the MEMORIES section from an already assembled pack.
///
/// Rows are sorted by slot, source, descending score, and entity id before slot
/// budgets are applied. That order is independent of `HashMap` iteration and
/// remains stable when retrieval returns equal-score rows.
///
/// The HTTP board uses this same projection and shared frame renderer.
#[must_use]
pub fn project_memories_section(
    pack: &ContextPack,
    budget: MemoriesBudget,
    companion: Option<CompanionAssembly>,
    disclosure: Option<DisclosureAssembly>,
) -> MemoriesSection {
    let mut rows = Vec::with_capacity(pack.results.len() + pack.neighbors.len());
    rows.extend(
        pack.results
            .iter()
            .filter(|entity| {
                !matches!(
                    entity.entity_type,
                    crate::registry::ENTITY_TYPE_SKILL | crate::registry::ENTITY_TYPE_AGENT_DEF
                )
            })
            .map(|entity| memory_row(entity, MemorySource::Result)),
    );
    rows.extend(
        pack.neighbors
            .iter()
            .filter(|entity| {
                !matches!(
                    entity.entity_type,
                    crate::registry::ENTITY_TYPE_SKILL | crate::registry::ENTITY_TYPE_AGENT_DEF
                )
            })
            .map(|entity| memory_row(entity, MemorySource::Neighbor)),
    );

    finish_projection(rows, budget, companion, disclosure)
}

pub(super) fn finish_projection(
    mut rows: Vec<MemoryRow>,
    budget: MemoriesBudget,
    companion: Option<CompanionAssembly>,
    disclosure: Option<DisclosureAssembly>,
) -> MemoriesSection {
    rows.sort_by(memory_row_order);

    let mut used = MemoriesBudget::default();
    let mut filtered = Vec::with_capacity(rows.len());
    for mut row in rows {
        if row.tier != MemoryTier::Pinned
            && (used.get(row.slot) >= budget.get(row.slot)
                || budget.shared_total.is_some_and(|cap| filtered.len() >= cap))
        {
            continue;
        }
        used.increment(row.slot);
        row.row_index = filtered.len();
        filtered.push(row);
    }

    filtered.sort_by(|a, b| {
        foreign_row(a)
            .cmp(&foreign_row(b))
            .then_with(|| a.world.cmp(&b.world))
            .then_with(|| memory_row_order(a, b))
    });
    for (index, row) in filtered.iter_mut().enumerate() {
        row.row_index = index;
    }
    MemoriesSection {
        version: MEMORIES_SECTION_VERSION_V4.to_owned(),
        budget,
        rows: filtered,
        companion,
        disclosure,
    }
}

fn memory_row(entity: &ContextEntity, source: MemorySource) -> MemoryRow {
    MemoryRow {
        row_index: 0,
        slot: memory_slot(entity.entity_type),
        source,
        id: entity.id.to_hex(),
        short_id: entity.short_id.clone(),
        content_hash: format!("{:02x}", entity.content_hash),
        entity_type: entity.entity_type,
        asset_ref: memory_asset_ref(entity.entity_type, &entity.short_id, entity.content_hash),
        score: entity.score,
        claim_source: (entity.entity_type == ENTITY_TYPE_CLAIM)
            .then(|| {
                entity
                    .fields
                    .as_ref()
                    .and_then(|fields| fields.get("src"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(crate::claim::ClaimSource::parse)
            })
            .flatten(),
        world: (entity.entity_type == ENTITY_TYPE_CLAIM)
            .then(|| {
                entity
                    .fields
                    .as_ref()
                    .and_then(|fields| fields.get("world"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .flatten()
            .or_else(|| {
                entity.edges.as_ref().and_then(|edges| {
                    edges
                        .iter()
                        .find(|edge| edge.kind == crate::edge::EdgeKind::InWorld)
                        .map(|edge| edge.target.to_hex())
                })
            }),
        tier: MemoryTier::Snippet,
        snippet: None,
    }
}

pub(super) fn memory_asset_ref(
    entity_type: u8,
    short_id: &str,
    content_hash: u8,
) -> Option<String> {
    matches!(entity_type, ENTITY_TYPE_ASSET | ENTITY_TYPE_ASSET_TEXT)
        .then(|| format!("{short_id}:{content_hash:02x}"))
}

pub(super) fn memory_slot(entity_type: u8) -> MemorySlot {
    match entity_type {
        ENTITY_TYPE_CLAIM => MemorySlot::Claims,
        ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE => MemorySlot::Turns,
        ENTITY_TYPE_SUMMARY => MemorySlot::Summaries,
        ENTITY_TYPE_FACET => MemorySlot::Facets,
        ENTITY_TYPE_COMPANION_REGISTER => MemorySlot::Companions,
        _ => MemorySlot::Other,
    }
}

fn memory_row_order(left: &MemoryRow, right: &MemoryRow) -> std::cmp::Ordering {
    (left.tier != MemoryTier::Pinned)
        .cmp(&(right.tier != MemoryTier::Pinned))
        .then_with(|| left.slot.sort_rank().cmp(&right.slot.sort_rank()))
        .then_with(|| left.source.sort_rank().cmp(&right.source.sort_rank()))
        .then_with(|| right.score.total_cmp(&left.score))
        .then_with(|| left.id.cmp(&right.id))
}

pub(super) fn foreign_row(row: &MemoryRow) -> bool {
    row.world
        .as_deref()
        .and_then(|world| crate::EntityId::from_hex(world).ok())
        .is_some_and(crate::entity_id::is_foreign_world_id_range)
}

impl crate::Vault {
    /// Hydrates provenance for already-authorized retrieval results. Pinned
    /// inputs must also come from the caller's authorized read projection.
    pub fn project_memories_section(
        &self,
        pack: &ContextPack,
        budget: MemoriesBudget,
        companion: Option<CompanionAssembly>,
        disclosure: Option<DisclosureAssembly>,
        pinned: &std::collections::BTreeSet<crate::EntityId>,
    ) -> crate::error::Result<MemoriesSection> {
        let mut rows = Vec::new();
        for (entities, source) in [
            (&pack.results, MemorySource::Result),
            (&pack.neighbors, MemorySource::Neighbor),
        ] {
            for entity in entities {
                let mut row = memory_row(entity, source);
                // These bytes and labels belong to the already-authorized
                // snapshot and its engine-issued ref. A new vault read could
                // substitute a changed private claim after the read gate.
                if entity.entity_type == ENTITY_TYPE_CLAIM
                    && let Some(value) = entity.fields.as_ref().and_then(|fields| fields.get("val"))
                {
                    let mut value = value.clone();
                    crate::batch::export::redact_credentials(&mut value);
                    row.snippet = Some(value.to_string());
                }
                row.tier = if pinned.contains(&entity.id) {
                    MemoryTier::Pinned
                } else if foreign_row(&row) {
                    MemoryTier::IndexOnly
                } else {
                    MemoryTier::Snippet
                };
                if foreign_row(&row) {
                    row.snippet = None;
                }
                rows.push(row);
            }
        }
        Ok(finish_projection(rows, budget, companion, disclosure))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_entity_fields_cannot_claim_provenance_or_foreign_authority() {
        let fields = std::collections::HashMap::from([
            ("src".into(), serde_json::json!("user_stated")),
            (
                "world".into(),
                serde_json::json!(crate::test_util::entity(0xF1).to_hex()),
            ),
        ]);
        let entity = ContextEntity {
            id: crate::test_util::entity(0x61),
            short_id: "pe1".into(),
            content_hash: 0,
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            score: 1.0,
            fields: Some(fields),
            edges: None,
            vector: None,
        };
        let row = memory_row(&entity, MemorySource::Result);
        assert_eq!(row.claim_source, None);
        assert_eq!(row.world, None);
    }
    #[test]
    fn shared_world_budget_keeps_pins_and_sheds_snippets() {
        let row = |n: u8, tier| MemoryRow {
            row_index: 0,
            slot: MemorySlot::Claims,
            source: MemorySource::Result,
            id: crate::test_util::entity(n).to_hex(),
            short_id: format!("cl{n}"),
            content_hash: "aa".into(),
            entity_type: ENTITY_TYPE_CLAIM,
            asset_ref: None,
            score: 1.0,
            claim_source: Some(crate::claim::ClaimSource::UserStated),
            world: Some(crate::test_util::entity(n).to_hex()),
            tier,
            snippet: Some("safe".into()),
        };
        let rows = vec![
            row(1, MemoryTier::Snippet),
            row(2, MemoryTier::Snippet),
            row(3, MemoryTier::Pinned),
        ];
        let section = finish_projection(
            rows.clone(),
            MemoriesBudget::new(10, 0, 0, 0, 0, 0).with_shared_total(2),
            None,
            None,
        );
        assert_eq!(section.rows.len(), 2);
        assert!(
            section
                .rows
                .iter()
                .any(|row| row.tier == MemoryTier::Pinned)
        );
        let pinned = finish_projection(
            rows,
            MemoriesBudget::default().with_shared_total(0),
            None,
            None,
        );
        assert_eq!(pinned.rows.len(), 1);
        assert_eq!(pinned.rows[0].tier, MemoryTier::Pinned);
    }
    #[test]
    fn memories_render_the_authorized_snapshot_without_refetching_claim_bytes() -> crate::Result<()>
    {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let mut pack = vault.context_pack().run()?;
        pack.results = vec![ContextEntity {
            id: crate::test_util::entity(0x71),
            short_id: "cl1".into(),
            content_hash: 0xab,
            entity_type: ENTITY_TYPE_CLAIM,
            score: 1.0,
            edges: None,
            vector: None,
            fields: Some(std::collections::HashMap::from([
                ("src".into(), serde_json::json!("user_stated")),
                ("val".into(), serde_json::json!("authorized snapshot")),
            ])),
        }];
        // The authorized packet can outlive a rewrite/deletion. It must never
        // combine its old short-ref hash with a new unguarded body read.
        let section = vault.project_memories_section(
            &pack,
            MemoriesBudget::new(1, 0, 0, 0, 0, 0),
            None,
            None,
            &std::collections::BTreeSet::new(),
        )?;
        assert_eq!(
            section.rows[0].claim_source,
            Some(crate::claim::ClaimSource::UserStated)
        );
        assert_eq!(
            section.rows[0].snippet.as_deref(),
            Some("\"authorized snapshot\"")
        );
        assert_eq!(section.rows[0].content_hash, "ab");
        Ok(())
    }
}
