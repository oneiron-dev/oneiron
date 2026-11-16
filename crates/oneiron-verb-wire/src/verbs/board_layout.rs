//! Moved from `crates/oneiron/src/verbs/board_layout.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::context_board::layout::BoardLayout;
use crate::context_board::layout::SectionFilter;
pub use crate::context_board::layout_store::BoardLayoutState;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
    /// [`crate::context_board::layout::BOARD_FOLD_NOTE_MAX_BYTES`] bytes.
    #[serde(default)]
    pub note: Option<String>,
    /// Row ids kept open under the fold line, at most
    /// [`crate::context_board::layout::BOARD_FOLD_KEEP_MAX`].
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
