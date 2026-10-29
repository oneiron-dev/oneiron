//! The content reads a bound [`OneironVault`] makes inside the off-record
//! session it names (FIX 8603, 10759): the room's overlay over base while
//! the room is live and its caller is in it, through the engine's one raw
//! adapter (`Memory::raw_*`), as its writes go: rows, edges and peers, text
//! and vector search, a context pack, a type's ids and the ChildOf walks. A
//! handle that names no session reads base through the bare vault, as
//! before.

use oneiron::{ContextPackBuilder, EdgeInfo, EdgeKind, EntityId, Memory, ScoredEntity};

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

    /// `query`'s BM25 hits.
    pub(super) fn text_hits(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ScoredEntity>, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_search_text(query, limit)),
            None => engine(self.vault.search_text(query, limit)),
        }
    }

    /// `query`'s nearest neighbours.
    pub(super) fn vector_hits(
        &self,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<ScoredEntity>, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_search_vector(query, limit)),
            None => engine(self.vault.search_vector(query, limit)),
        }
    }

    /// The serialized context pack `configure` builds.
    pub(super) fn pack_bytes(
        &self,
        configure: impl for<'b> Fn(ContextPackBuilder<'b>) -> ContextPackBuilder<'b>,
    ) -> Result<Vec<u8>, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_context_pack(configure)),
            None => engine(configure(self.vault.context_pack()).run_serialized()),
        }
    }

    /// The ids stored with type byte `entity_type`.
    pub(super) fn ids_of_type(&self, entity_type: u8) -> Result<Vec<EntityId>, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_entities_by_type(entity_type)),
            None => engine(self.vault.entities_by_type(entity_type)),
        }
    }

    /// `root`'s ChildOf descendants to `max_depth`, with their depths.
    pub(super) fn subtree_of(
        &self,
        root: &EntityId,
        max_depth: u32,
    ) -> Result<Vec<(EntityId, u32)>, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_subtree(root, max_depth)),
            None => engine(self.vault.subtree(root, max_depth)),
        }
    }

    /// `node`'s ChildOf ancestors, nearest first.
    pub(super) fn ancestors_of(&self, node: &EntityId) -> Result<Vec<EntityId>, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_ancestors(node)),
            None => engine(self.vault.ancestors(node)),
        }
    }

    /// Whether making `target` a parent of `node` would close a cycle.
    pub(super) fn cycle_through(
        &self,
        node: &EntityId,
        target: &EntityId,
    ) -> Result<bool, OneironStatus> {
        match self.session_memory() {
            Some(memory) => memory_result(memory.raw_would_create_cycle(node, target)),
            None => engine(self.vault.would_create_cycle(node, target)),
        }
    }
}
