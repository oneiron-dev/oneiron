//! The content reads a bound [`NapiVault`] makes inside the off-record
//! session it names (FIX 8119, 10759): the room's overlay over base while
//! the room is live and its caller is in it, through the engine's one raw
//! adapter (`Memory::raw_*`), as its writes go: rows, edges and peers, text
//! and vector search, a scoped query, a context pack, a type's ids and the
//! ChildOf walks. A vault that names no session reads base through the bare
//! vault, as before. Codebase snapshots read base alone: no room stages one.

use oneiron::{
    ContextPackBuilder, EdgeInfo, EdgeKind, EntityId, Memory, PipelineBuilder, ScoredEntity,
};

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

    /// `query`'s BM25 hits.
    pub(super) fn text_hits(&self, query: &str, limit: usize) -> napi::Result<Vec<ScoredEntity>> {
        match self.session_memory() {
            Some(memory) => memory.raw_search_text(query, limit).map_err(facade_error),
            None => self.vault.search_text(query, limit).map_err(to_napi_err),
        }
    }

    /// `query`'s nearest neighbours.
    pub(super) fn vector_hits(
        &self,
        query: &[f32],
        limit: usize,
    ) -> napi::Result<Vec<ScoredEntity>> {
        match self.session_memory() {
            Some(memory) => memory.raw_search_vector(query, limit).map_err(facade_error),
            None => self.vault.search_vector(query, limit).map_err(to_napi_err),
        }
    }

    /// The hits of the query `configure` builds.
    pub(super) fn query_hits(
        &self,
        configure: impl for<'b> Fn(PipelineBuilder<'b>) -> PipelineBuilder<'b>,
    ) -> napi::Result<Vec<ScoredEntity>> {
        match self.session_memory() {
            Some(memory) => memory.raw_query(configure).map_err(facade_error),
            None => configure(self.vault.query()).run().map_err(to_napi_err),
        }
    }

    /// The serialized context pack `configure` builds.
    pub(super) fn pack_bytes(
        &self,
        configure: impl for<'b> Fn(ContextPackBuilder<'b>) -> ContextPackBuilder<'b>,
    ) -> napi::Result<Vec<u8>> {
        match self.session_memory() {
            Some(memory) => memory.raw_context_pack(configure).map_err(facade_error),
            None => configure(self.vault.context_pack())
                .run_serialized()
                .map_err(to_napi_err),
        }
    }

    /// The ids stored with type byte `entity_type`.
    pub(super) fn ids_of_type(&self, entity_type: u8) -> napi::Result<Vec<EntityId>> {
        match self.session_memory() {
            Some(memory) => memory
                .raw_entities_by_type(entity_type)
                .map_err(facade_error),
            None => self
                .vault
                .entities_by_type(entity_type)
                .map_err(to_napi_err),
        }
    }

    /// `root`'s ChildOf descendants to `max_depth`, with their depths.
    pub(super) fn subtree_of(
        &self,
        root: &EntityId,
        max_depth: u32,
    ) -> napi::Result<Vec<(EntityId, u32)>> {
        match self.session_memory() {
            Some(memory) => memory.raw_subtree(root, max_depth).map_err(facade_error),
            None => self.vault.subtree(root, max_depth).map_err(to_napi_err),
        }
    }

    /// `node`'s ChildOf ancestors, nearest first.
    pub(super) fn ancestors_of(&self, node: &EntityId) -> napi::Result<Vec<EntityId>> {
        match self.session_memory() {
            Some(memory) => memory.raw_ancestors(node).map_err(facade_error),
            None => self.vault.ancestors(node).map_err(to_napi_err),
        }
    }

    /// Whether making `target` a parent of `node` would close a cycle.
    pub(super) fn cycle_through(&self, node: &EntityId, target: &EntityId) -> napi::Result<bool> {
        match self.session_memory() {
            Some(memory) => memory
                .raw_would_create_cycle(node, target)
                .map_err(facade_error),
            None => self
                .vault
                .would_create_cycle(node, target)
                .map_err(to_napi_err),
        }
    }
}
