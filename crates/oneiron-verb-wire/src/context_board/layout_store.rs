//! Moved from `crates/oneiron/src/context_board/layout_store.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::context_board::layout::BoardLayout;
use serde::Deserialize;
use serde::Serialize;

/// One actor's board layout: what renders now, and the batch the next turn
/// applies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BoardLayoutState {
    /// The actor's own layout its board renders under now.
    pub live: BoardLayout,
    /// The batch the next turn applies; absent when none is staged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<BoardLayout>,
    /// The owner's override sections for this actor (every agent's, with
    /// this agent's own laid over them), which win over the actor's own.
    #[serde(default, skip_serializing_if = "is_empty_layout")]
    pub owner_override: BoardLayout,
}

pub fn is_empty_layout(layout: &BoardLayout) -> bool {
    layout.sections.is_empty()
}
