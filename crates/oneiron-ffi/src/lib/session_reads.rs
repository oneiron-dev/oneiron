//! The content reads a bound [`OneironVault`] makes inside the off-record
//! session it names (FIX 8603): the room's overlay over base while the room
//! is live and its caller is in it, through the engine's one raw adapter
//! (`Memory::raw_*`), as its writes go. A handle that names no session reads
//! base through the bare vault, as before.

use oneiron::{EdgeInfo, EdgeKind, EntityId, Memory};

use super::parse::{engine, memory_result};
use super::types::{OneironStatus, OneironVault};

impl OneironVault {
    /// The bound caller's memory surface when it names a session; `None`
    /// reads through the bare vault.
    fn session_memory(&self) -> Option<Memory<'_>> {
        self.binding
            .as_ref()
            .filter(|binding| binding.session.is_some())
            .and_then(|_| self.bound_memory())
    }

    /// `id`'s body, as `Vault::get` reads it.
    pub(super) fn entity_body(&self, id: &EntityId) -> Result<Option<Vec<u8>>, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_get_entity(id)),
            None => engine(self.vault.get(id)),
        }
    }

    /// `id`'s stored type byte.
    pub(super) fn entity_type_of(&self, id: &EntityId) -> Result<Option<u8>, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_entity_type(id)),
            None => engine(self.vault.get_entity_type(id)),
        }
    }

    /// Whether `id` is stored.
    pub(super) fn entity_stored(&self, id: &EntityId) -> Result<bool, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_entity_exists(id)),
            None => engine(self.vault.entity_exists(id)),
        }
    }

    /// `id`'s outbound edges, or its inbound ones.
    pub(super) fn edges_of(
        &self,
        id: &EntityId,
        outbound: bool,
    ) -> Result<Vec<EdgeInfo>, OneironStatus> {
        match (self.session_memory(), outbound) {
            (Some(memory), true) => memory_result(memory.raw_edges_out(id)),
            (Some(memory), false) => memory_result(memory.raw_edges_in(id)),
            (None, true) => engine(self.vault.edges_out(id)),
            (None, false) => engine(self.vault.edges_in(id)),
        }
    }

    /// `id`'s outbound edge peers of `kind`, or its inbound ones, filtered
    /// by the peer's type.
    pub(super) fn peers_of(
        &self,
        id: &EntityId,
        kind: EdgeKind,
        peer: Option<u8>,
        outbound: bool,
    ) -> Result<Vec<EntityId>, OneironStatus> {
        match (self.session_memory(), outbound) {
            (Some(memory), true) => memory_result(memory.raw_targets(id, kind, peer)),
            (Some(memory), false) => memory_result(memory.raw_sources(id, kind, peer)),
            (None, true) => engine(self.vault.targets(id, kind, peer)),
            (None, false) => engine(self.vault.sources(id, kind, peer)),
        }
    }
}
