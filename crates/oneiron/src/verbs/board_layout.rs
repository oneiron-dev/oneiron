//! The doors of the agent's own board layout (BOARD-LAYOUT = A, owner
//! 2026-11-03): `self.board.layout` reads it, and `self.board.fold`,
//! `self.board.unfold`, `self.board.size`, `self.board.filter` and
//! `self.board.replace` stage one pending batch the next turn applies. The
//! layout is the handle's own: the engine keys it by the handle's actor,
//! never by a field naming someone else.
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::context_board::{BoardLayout, SectionFilter, SectionFold, is_section_key};
use crate::memory::{Memory, MemoryError, MemoryResult};

pub use crate::context_board::BoardLayoutState;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::board_layout::{
    BoardFilterRequest, BoardFoldRequest, BoardReplaceRequest, BoardSectionRequest,
    BoardSizeRequest,
};

fn section_key(section: &str) -> MemoryResult<String> {
    let key = section.trim().to_ascii_lowercase();
    if is_section_key(&key) {
        Ok(key)
    } else {
        Err(MemoryError::bad_request(format!(
            "{section:?} is not a board section key"
        )))
    }
}

/// `self.board.layout`: the bound actor's board layout, live and pending.
pub fn board_layout_reply(
    memory: &Memory<'_>,
    _input: &super::EmptyRequest,
) -> MemoryResult<BoardLayoutState> {
    memory.board_layout()
}

/// `self.board.fold`: stages one section's fold, with its note and kept
/// rows. Folding a folded section again restarts its count of changes.
pub fn board_fold_reply(
    memory: &Memory<'_>,
    input: &BoardFoldRequest,
) -> MemoryResult<BoardLayoutState> {
    let key = section_key(&input.section)?;
    let mut keep = input.keep.clone();
    keep.sort_unstable();
    keep.dedup();
    let note = input.note.clone().filter(|note| !note.trim().is_empty());
    memory.stage_board_layout(|layout| {
        layout.edit(&key, |section| {
            section.fold = Some(SectionFold {
                note,
                keep,
                baseline: None,
                section_baselines: std::collections::BTreeMap::new(),
            });
        });
        Ok(())
    })
}

/// `self.board.unfold`: stages one section's unfold. Unfolding a section
/// that is not folded stages nothing new.
pub fn board_unfold_reply(
    memory: &Memory<'_>,
    input: &BoardSectionRequest,
) -> MemoryResult<BoardLayoutState> {
    let key = section_key(&input.section)?;
    memory.stage_board_layout(|layout| {
        layout.edit(&key, |section| section.fold = None);
        Ok(())
    })
}

/// `self.board.size`: stages one section's share of the board cap.
pub fn board_size_reply(
    memory: &Memory<'_>,
    input: &BoardSizeRequest,
) -> MemoryResult<BoardLayoutState> {
    let key = section_key(&input.section)?;
    let share = input.share_pct;
    memory.stage_board_layout(|layout| {
        layout.edit(&key, |section| section.share_pct = share);
        Ok(())
    })
}

/// `self.board.filter`: stages which rows one section shows.
pub fn board_filter_reply(
    memory: &Memory<'_>,
    input: &BoardFilterRequest,
) -> MemoryResult<BoardLayoutState> {
    let key = section_key(&input.section)?;
    let filter = input
        .filter
        .clone()
        .filter(|filter| filter.who.is_some() || !filter.status.is_empty());
    memory.stage_board_layout(|layout| {
        layout.edit(&key, |section| section.filter = filter);
        Ok(())
    })
}

/// `self.board.replace`: stages the whole layout of the next batch. A fold
/// the new layout carries over unchanged keeps its count of changes.
pub fn board_replace_reply(
    memory: &Memory<'_>,
    input: &BoardReplaceRequest,
) -> MemoryResult<BoardLayoutState> {
    let mut next = input.layout.clone();
    memory.stage_board_layout(|layout| {
        for (key, section) in &mut next.sections {
            let prior = layout.fold(key).cloned();
            if let Some(fold) = &mut section.fold {
                let prior =
                    prior.filter(|prior| prior.note == fold.note && prior.keep == fold.keep);
                fold.section_baselines = prior
                    .as_ref()
                    .map(|prior| prior.section_baselines.clone())
                    .unwrap_or_default();
                fold.baseline = prior.and_then(|prior| prior.baseline);
            }
        }
        *layout = next;
        Ok(())
    })
}
