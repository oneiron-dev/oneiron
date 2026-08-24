//! Memory-board view assembled from a finished context pack.
//!
//! Designed in canon (eiri/context, ARCH-0004, eiri-arch-0016); unwired as of
//! 2026-08-19 — needs wiring/design completion.

use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::disclosure::DisclosureAssembly;
use crate::eiri::{
    EIRI_CONTEXT_VERSION_V4, EiriCompanionAssembly, EiriMemoryBoard, EiriMemoryBoardBudget,
    EiriMemoryBoardRow, EiriMemoryBoardSlot, EiriMemoryBoardSource,
};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};

use super::types::{ContextEntity, ContextPack};

/// Builds the Eiri Context v4 memory board from an already assembled pack.
///
/// Rows are sorted by slot, source, descending score, and entity id before slot
/// budgets are applied. That order is independent of `HashMap` iteration and
/// remains stable when retrieval returns equal-score rows.
///
/// Designed in canon (eiri/context, ARCH-0004, eiri-arch-0016); unwired as of
/// 2026-08-19 — needs wiring/design completion.
#[must_use]
pub fn assemble_eiri_memory_board(
    pack: &ContextPack,
    budget: EiriMemoryBoardBudget,
    companion: Option<EiriCompanionAssembly>,
    disclosure: Option<DisclosureAssembly>,
) -> EiriMemoryBoard {
    let mut rows = Vec::with_capacity(pack.results.len() + pack.neighbors.len());
    rows.extend(
        pack.results
            .iter()
            .map(|entity| eiri_memory_board_row(entity, EiriMemoryBoardSource::Result)),
    );
    rows.extend(
        pack.neighbors
            .iter()
            .map(|entity| eiri_memory_board_row(entity, EiriMemoryBoardSource::Neighbor)),
    );

    rows.sort_by(eiri_memory_board_row_order);

    let mut used = EiriMemoryBoardBudget::default();
    let mut filtered = Vec::with_capacity(rows.len());
    for mut row in rows {
        if used.get(row.slot) >= budget.get(row.slot) {
            continue;
        }
        used.increment(row.slot);
        row.row_index = filtered.len();
        filtered.push(row);
    }

    EiriMemoryBoard {
        version: EIRI_CONTEXT_VERSION_V4.to_owned(),
        budget,
        rows: filtered,
        companion,
        disclosure,
    }
}

fn eiri_memory_board_row(
    entity: &ContextEntity,
    source: EiriMemoryBoardSource,
) -> EiriMemoryBoardRow {
    EiriMemoryBoardRow {
        row_index: 0,
        slot: eiri_memory_board_slot(entity.entity_type),
        source,
        id: entity.id.to_hex(),
        short_id: entity.short_id.clone(),
        content_hash: format!("{:02x}", entity.content_hash),
        entity_type: entity.entity_type,
        asset_ref: eiri_memory_board_asset_ref(
            entity.entity_type,
            &entity.short_id,
            entity.content_hash,
        ),
        score: entity.score,
    }
}

fn eiri_memory_board_asset_ref(
    entity_type: u8,
    short_id: &str,
    content_hash: u8,
) -> Option<String> {
    matches!(entity_type, ENTITY_TYPE_ASSET | ENTITY_TYPE_ASSET_TEXT)
        .then(|| format!("{short_id}:{content_hash:02x}"))
}

fn eiri_memory_board_slot(entity_type: u8) -> EiriMemoryBoardSlot {
    match entity_type {
        ENTITY_TYPE_CLAIM => EiriMemoryBoardSlot::Claims,
        ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE => EiriMemoryBoardSlot::Turns,
        ENTITY_TYPE_SUMMARY => EiriMemoryBoardSlot::Summaries,
        ENTITY_TYPE_FACET => EiriMemoryBoardSlot::Facets,
        ENTITY_TYPE_COMPANION_REGISTER => EiriMemoryBoardSlot::Companions,
        _ => EiriMemoryBoardSlot::Other,
    }
}

fn eiri_memory_board_row_order(
    left: &EiriMemoryBoardRow,
    right: &EiriMemoryBoardRow,
) -> std::cmp::Ordering {
    left.slot
        .sort_rank()
        .cmp(&right.slot.sort_rank())
        .then_with(|| left.source.sort_rank().cmp(&right.source.sort_rank()))
        .then_with(|| right.score.total_cmp(&left.score))
        .then_with(|| left.id.cmp(&right.id))
}
