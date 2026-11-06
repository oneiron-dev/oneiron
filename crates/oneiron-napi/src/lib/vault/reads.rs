//! The content reads a bound [`NapiVault`] makes inside the off-record
//! session it names (FIX 8119, 10759): the room's overlay over base while
//! the room is live and its caller is in it, through the engine's one raw
//! adapter (`Memory::raw_*`), as its writes go: rows, edges and peers, text
//! and vector search, a scoped query, a context pack, a type's ids and the
//! ChildOf walks. A selected READ proof uses the engine's scoped native
//! adapter in every reader, with the same session participant checks. Without
//! a proof the original session/base readers remain unchanged. Codebase
//! metadata is admitted through its actual CODE_ARTIFACT in the serving txn.
//! Snapshot metadata itself stays on base; no room stages a snapshot.

use oneiron::{
    ContextPackBuilder, EdgeInfo, EdgeKind, EntityId, Memory, PipelineBuilder, ScoredEntity,
};

use super::{NapiVault, to_napi_err};
use crate::facade::facade_error;

impl NapiVault {
    fn credential_read<T>(
        &self,
        proof: &oneiron::authority::VerifiedSlip,
        read: impl for<'a> Fn(&oneiron::claim::NativeRawRead<'a>) -> oneiron::error::Result<T>,
    ) -> napi::Result<T> {
        match self.bound_memory() {
            Some(memory) => memory
                .with_read_proof(proof)
                .with_credential_raw_read(read)
                .map_err(facade_error),
            None => self
                .vault
                .with_credential_raw_read(proof, read)
                .map_err(to_napi_err),
        }
    }

    pub(super) fn snapshot_for(
        &self,
        id: &EntityId,
    ) -> napi::Result<Option<oneiron::codebase::CodebaseSnapshot>> {
        match &self.read_proof {
            Some(proof) => self.credential_read(proof, |read| read.codebase_snapshot(id)),
            None => self.vault.get_codebase_snapshot(id).map_err(to_napi_err),
        }
    }

    pub(super) fn snapshots_for_repo(
        &self,
        repo_ref: &oneiron::RepoRef,
    ) -> napi::Result<Vec<EntityId>> {
        match &self.read_proof {
            Some(proof) => {
                self.credential_read(proof, |read| read.codebase_snapshots_by_repo_ref(repo_ref))
            }
            None => self
                .vault
                .codebase_snapshots_by_repo_ref(repo_ref)
                .map_err(to_napi_err),
        }
    }

    pub(super) fn snapshots_for_project(&self, project_id: &str) -> napi::Result<Vec<EntityId>> {
        match &self.read_proof {
            Some(proof) => self.credential_read(proof, |read| {
                read.codebase_snapshots_by_project_id(project_id)
            }),
            None => self
                .vault
                .codebase_snapshots_by_project_id(project_id)
                .map_err(to_napi_err),
        }
    }

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
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.entity_body(id));
        }
        match self.session_memory() {
            Some(memory) => memory.raw_get_entity(id).map_err(facade_error),
            None => self.vault.get(id).map_err(to_napi_err),
        }
    }

    /// `id`'s stored type byte.
    pub(super) fn entity_type_of(&self, id: &EntityId) -> napi::Result<Option<u8>> {
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.entity_type(id));
        }
        match self.session_memory() {
            Some(memory) => memory.raw_entity_type(id).map_err(facade_error),
            None => self.vault.get_entity_type(id).map_err(to_napi_err),
        }
    }

    /// Whether `id` is stored.
    pub(super) fn entity_stored(&self, id: &EntityId) -> napi::Result<bool> {
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.entity_exists(id));
        }
        match self.session_memory() {
            Some(memory) => memory.raw_entity_exists(id).map_err(facade_error),
            None => self.vault.entity_exists(id).map_err(to_napi_err),
        }
    }

    /// `id`'s outbound edges, or its inbound ones.
    pub(super) fn edges_of(&self, id: &EntityId, outbound: bool) -> napi::Result<Vec<EdgeInfo>> {
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.edges(id, outbound));
        }
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
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.peers(id, kind, peer, outbound));
        }
        match (self.session_memory(), outbound) {
            (Some(memory), true) => memory.raw_targets(id, kind, peer).map_err(facade_error),
            (Some(memory), false) => memory.raw_sources(id, kind, peer).map_err(facade_error),
            (None, true) => self.vault.targets(id, kind, peer).map_err(to_napi_err),
            (None, false) => self.vault.sources(id, kind, peer).map_err(to_napi_err),
        }
    }

    /// `query`'s BM25 hits.
    pub(super) fn text_hits(&self, query: &str, limit: usize) -> napi::Result<Vec<ScoredEntity>> {
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.search_text(query, limit));
        }
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
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.search_vector(query, limit));
        }
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
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.query(&configure));
        }
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
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.context_pack(&configure));
        }
        match self.session_memory() {
            Some(memory) => memory.raw_context_pack(configure).map_err(facade_error),
            None => configure(self.vault.context_pack())
                .run_serialized()
                .map_err(to_napi_err),
        }
    }

    /// The ids stored with type byte `entity_type`.
    pub(super) fn ids_of_type(&self, entity_type: u8) -> napi::Result<Vec<EntityId>> {
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.entities_by_type(entity_type));
        }
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
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.subtree(root, max_depth));
        }
        match self.session_memory() {
            Some(memory) => memory.raw_subtree(root, max_depth).map_err(facade_error),
            None => self.vault.subtree(root, max_depth).map_err(to_napi_err),
        }
    }

    /// `node`'s ChildOf ancestors, nearest first.
    pub(super) fn ancestors_of(&self, node: &EntityId) -> napi::Result<Vec<EntityId>> {
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.ancestors(node));
        }
        match self.session_memory() {
            Some(memory) => memory.raw_ancestors(node).map_err(facade_error),
            None => self.vault.ancestors(node).map_err(to_napi_err),
        }
    }

    /// Whether making `target` a parent of `node` would close a cycle.
    /// With a READ proof this queries only the admitted graph; false is
    /// not a global no-cycle assertion or permission to write.
    pub(super) fn cycle_through(&self, node: &EntityId, target: &EntityId) -> napi::Result<bool> {
        if let Some(proof) = &self.read_proof {
            return self.credential_read(proof, |read| read.would_create_cycle(node, target));
        }
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
