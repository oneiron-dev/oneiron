//! MEMORIES projection over a finished context pack — "what retrieval PULLED" (ARCH-0067 §1). Unwired since 2026-08-19. Step two: per-world PINNED / snippet / index-only tiers under the one shared memories budget (§1 MEMORIES row l.42, §3 shape rules l.170).

use super::memories::{
    CompanionAssembly, MEMORIES_SECTION_VERSION_V4, MemoriesBudget, MemoriesSection, MemoryRow,
    MemorySlot, MemorySource,
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
/// Designed in canon (eiri/context, ARCH-0004, eiri-arch-0016); unwired as of
/// 2026-08-19 — needs wiring/design completion.
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
            .map(|entity| memory_row(entity, MemorySource::Result)),
    );
    rows.extend(
        pack.neighbors
            .iter()
            .map(|entity| memory_row(entity, MemorySource::Neighbor)),
    );

    rows.sort_by(memory_row_order);

    let mut used = MemoriesBudget::default();
    let mut filtered = Vec::with_capacity(rows.len());
    for mut row in rows {
        if used.get(row.slot) >= budget.get(row.slot) {
            continue;
        }
        used.increment(row.slot);
        row.row_index = filtered.len();
        filtered.push(row);
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
    }
}

fn memory_asset_ref(entity_type: u8, short_id: &str, content_hash: u8) -> Option<String> {
    matches!(entity_type, ENTITY_TYPE_ASSET | ENTITY_TYPE_ASSET_TEXT)
        .then(|| format!("{short_id}:{content_hash:02x}"))
}

fn memory_slot(entity_type: u8) -> MemorySlot {
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
    left.slot
        .sort_rank()
        .cmp(&right.slot.sort_rank())
        .then_with(|| left.source.sort_rank().cmp(&right.source.sort_rank()))
        .then_with(|| right.score.total_cmp(&left.score))
        .then_with(|| left.id.cmp(&right.id))
}
