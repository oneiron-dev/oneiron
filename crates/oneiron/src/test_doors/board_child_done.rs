//! Doors for `tests/board_child_done_producer.rs` (census L2-38), as the base
//! behaves: no write stages a child's end, so the pass has nothing to send.

use crate::context_board::BoardStreamRegistry;
use crate::{Result, Vault};

/// The base has no child-end producer: nothing to take, nothing sent.
pub fn publish_children_done(_vault: &Vault, _registry: &mut BoardStreamRegistry) -> Result<()> {
    Ok(())
}
