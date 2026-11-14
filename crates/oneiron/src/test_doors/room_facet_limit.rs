//! Door for `tests/room_of_unheld_project_reads_bottom.rs` (L7-39 guard): the
//! facets a room limits its reads to, as a room turn's ceiling, a named-room
//! read and the frozen bound read them.

use crate::error::Result;
use crate::federation::{ScopeAxis, ScopeId};
use crate::{EntityId, Vault};

/// The facet limit `room` puts on every read through it now.
pub fn room_facet_axis(vault: &Vault, room: EntityId) -> Result<ScopeAxis<ScopeId>> {
    let txn = vault.store.env.read_txn()?;
    crate::context_board::room_facets_axis_in(vault, &txn, room)
}
