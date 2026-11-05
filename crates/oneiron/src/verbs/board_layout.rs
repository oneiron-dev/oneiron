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

/// `self.board.fold`'s input: the section to fold, the agent's note on its
/// fold line, and the rows it keeps open under the line.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardFoldRequest {
    /// The section's layout key: `tasks`, `memories`, `worlds`, `skills`,
    /// `room`, `inbox`, `scratchpad`, `readers`, `packs`, or a plugin
    /// section's first name word, lower case.
    pub section: String,
    /// The agent's own note on the fold line, at most
    /// [`crate::context_board::BOARD_FOLD_NOTE_MAX_BYTES`] bytes.
    #[serde(default)]
    pub note: Option<String>,
    /// Row ids kept open under the fold line, at most
    /// [`crate::context_board::BOARD_FOLD_KEEP_MAX`].
    #[serde(default)]
    pub keep: Vec<EntityId>,
}

/// One section a layout verb names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardSectionRequest {
    /// The section's layout key, as [`BoardFoldRequest::section`].
    pub section: String,
}

/// `self.board.size`'s input: one section's share of the board cap.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardSizeRequest {
    /// The section's layout key, as [`BoardFoldRequest::section`].
    pub section: String,
    /// The percent of the board cap the section may fill, 0-100; absent or
    /// `null` gives the section back to the engine's own sizing. All shares
    /// together stay within 100.
    #[serde(default)]
    pub share_pct: Option<u8>,
}

/// `self.board.filter`'s input: which rows one section shows.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardFilterRequest {
    /// The section's layout key, as [`BoardFoldRequest::section`].
    pub section: String,
    /// The rows the section shows; absent or `null` shows every row.
    #[serde(default)]
    pub filter: Option<SectionFilter>,
}

/// `self.board.replace`'s input: the whole layout of the next batch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoardReplaceRequest {
    /// Every section the next batch lays out; a section it leaves out
    /// renders as the engine lays it out.
    pub layout: BoardLayout,
}

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
