//! The content reads a bound [`NapiVault`] makes inside the off-record
//! session it names (FIX 8119): the room's overlay over base while the room
//! is live and its caller is in it, through the engine's one raw adapter
//! (`Memory::raw_*`), as its writes go. A vault that names no session reads
//! base through the bare vault, as before.

use oneiron::{EdgeInfo, EdgeKind, EntityId, Memory};

use super::{NapiVault, to_napi_err};
use crate::facade::facade_error;

impl NapiVault {
    /// The bound caller's memory surface when it names a session; `None`
    /// reads through the bare vault.
    fn session_memory(&self) -> Option<Memory<'_>> {
        self.binding
            .as_ref()
            .filter(|binding| binding.session.is_some())
            .and_then(|_| self.bound_memory())
    }

    /// `id`'s body, as `Vault::get` reads it.
    pub(super) fn entity_body(&self, id: &EntityId) -> napi::Result<Option<Vec<u8>>> {
        match self.session_memory() {
            Some(memory) => memory.raw_get_entity(id).map_err(facade_error),
            None => self.vault.get(id).map_err(to_napi_err),
        }
    }

    /// `id`'s stored type byte.
    pub(super) fn entity_type_of(&self, id: &EntityId) -> napi::Result<Option<u8>> {
        match self.session_memory() {
            Some(memory) => memory.raw_entity_type(id).map_err(facade_error),
            None => self.vault.get_entity_type(id).map_err(to_napi_err),
        }
    }

    /// Whether `id` is stored.
    pub(super) fn entity_stored(&self, id: &EntityId) -> napi::Result<bool> {
        match self.session_memory() {
            Some(memory) => memory.raw_entity_exists(id).map_err(facade_error),
            None => self.vault.entity_exists(id).map_err(to_napi_err),
        }
    }

    /// `id`'s outbound edges, or its inbound ones.
    pub(super) fn edges_of(&self, id: &EntityId, outbound: bool) -> napi::Result<Vec<EdgeInfo>> {
        match (self.session_memory(), outbound) {
            (Some(memory), true) => memory.raw_edges_out(id).map_err(facade_error),
            (Some(memory), false) => memory.raw_edges_in(id).map_err(facade_error),
            (None, true) => self.vault.edges_out(id).map_err(to_napi_err),
            (None, false) => self.vault.edges_in(id).map_err(to_napi_err),
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
    ) -> napi::Result<Vec<EntityId>> {
        match (self.session_memory(), outbound) {
            (Some(memory), true) => memory.raw_targets(id, kind, peer).map_err(facade_error),
            (Some(memory), false) => memory.raw_sources(id, kind, peer).map_err(facade_error),
            (None, true) => self.vault.targets(id, kind, peer).map_err(to_napi_err),
            (None, false) => self.vault.sources(id, kind, peer).map_err(to_napi_err),
        }
    }
}
