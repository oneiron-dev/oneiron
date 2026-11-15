//! Doors for `tests/board_child_done_producer.rs` (census L2-38): the serve
//! board publisher's child-end pass, run inline over an engine registry.

use crate::context_board::{BoardStreamRegistry, ChildDone};
use crate::{Result, Vault};

/// The pass each commit starts: take the staged child ends and send each to
/// its spawner's subscribed connections.
pub fn publish_children_done(vault: &Vault, registry: &mut BoardStreamRegistry) -> Result<()> {
    let done = ChildDone::take_all(vault)?;
    registry.publish_children_done(done);
    Ok(())
}
