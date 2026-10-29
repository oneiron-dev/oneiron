//! The reads a bound raw handle makes inside its session's room beyond one
//! row and its edges (FIX 10759): text and vector search, a filtered query,
//! a context pack, a type's ids and the ChildOf walks. Each reads the room's
//! overlay ∪ base while the room is live and the caller is in it, and base
//! otherwise, as [`Memory::raw_get_entity`] does; base rows are always read.
//! A search or a builder run registers its retrieval run through the room's
//! route, so an off-record room's run row stays in the room.

use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::scan_check::{EngineScan, ScanCount};
use crate::vault::edges::{ancestors_in, subtree_in, would_create_cycle_in};
use crate::{ContextPackBuilder, PipelineBuilder, ScoredEntity};

impl Memory<'_> {
    /// [`crate::Vault::search_text`], over the room's overlay ∪ base while
    /// this surface's session is live, its run registered in the room.
    ///
    /// # Errors
    ///
    /// As [`crate::Vault::search_text`]; a stale route.
    pub fn raw_search_text(&self, query: &str, limit: usize) -> MemoryResult<Vec<ScoredEntity>> {
        let composed = self.raw_session_read(|session| {
            session.search_text_routed(&session.write_route()?, query, limit)
        })?;
        match composed {
            Some(hits) => Ok(hits),
            None => Ok(self.vault().search_text(query, limit)?),
        }
    }

    /// [`crate::Vault::search_vector`], the room's staged vectors scored
    /// beside base's while this surface's session is live, its run
    /// registered in the room.
    ///
    /// # Errors
    ///
    /// As [`crate::Vault::search_vector`]; a stale route.
    pub fn raw_search_vector(
        &self,
        query: &[f32],
        limit: usize,
    ) -> MemoryResult<Vec<ScoredEntity>> {
        let composed = self.raw_session_read(|session| {
            session.search_vector_routed(&session.write_route()?, query, limit)
        })?;
        match composed {
            Some(hits) => Ok(hits),
            None => Ok(self.vault().search_vector(query, limit)?),
        }
    }

    /// Runs the query `configure` builds on [`crate::Vault::query`]: over
    /// the room's overlay ∪ base, its run registered in the room, while
    /// this surface's session is live; over base otherwise. `configure` may
    /// run twice: again on base when the room goes during the run.
    ///
    /// # Errors
    ///
    /// As [`PipelineBuilder::run`]; a stale route.
    pub fn raw_query(
        &self,
        configure: impl for<'b> Fn(PipelineBuilder<'b>) -> PipelineBuilder<'b>,
    ) -> MemoryResult<Vec<ScoredEntity>> {
        let composed = self.raw_session_read(|session| {
            let route = session.write_route()?;
            let telemetry = session.retrieval_telemetry(&route)?;
            let view = session.read_view()?;
            let builder = self
                .vault()
                .query()
                .reading(view.read())
                .in_session(&telemetry);
            let hits = configure(builder).run()?;
            // The run read in snapshots of its own: a caller who left the
            // room during it hears that it left, never what it read.
            session.admit_participant()?;
            Ok(hits)
        })?;
        match composed {
            Some(hits) => Ok(hits),
            None => Ok(configure(self.vault().query()).run()?),
        }
    }

    /// Runs the context pack `configure` builds on
    /// [`crate::Vault::context_pack`] and serializes it: over the room's
    /// overlay ∪ base, its run registered and finalized in the room, while
    /// this surface's session is live; over base otherwise. `configure` may
    /// run twice: again on base when the room goes during the run.
    ///
    /// # Errors
    ///
    /// As [`ContextPackBuilder::run_serialized`]; a stale route.
    pub fn raw_context_pack(
        &self,
        configure: impl for<'b> Fn(ContextPackBuilder<'b>) -> ContextPackBuilder<'b>,
    ) -> MemoryResult<Vec<u8>> {
        let composed = self.raw_session_read(|session| {
            let route = session.write_route()?;
            let telemetry = session.retrieval_telemetry(&route)?;
            let view = session.read_view()?;
            let builder = self
                .vault()
                .context_pack()
                .reading(view.read())
                .in_session(&telemetry);
            let pack = configure(builder).run_serialized()?;
            session.admit_participant()?;
            Ok(pack)
        })?;
        match composed {
            Some(pack) => Ok(pack),
            None => Ok(configure(self.vault().context_pack()).run_serialized()?),
        }
    }

    /// [`crate::Vault::entities_by_type`], the room's rows of the type among
    /// them while this surface's session is live.
    ///
    /// # Errors
    ///
    /// As [`crate::Vault::entities_by_type`].
    pub fn raw_entities_by_type(&self, entity_type: u8) -> MemoryResult<Vec<EntityId>> {
        let composed = self.raw_composed_read(|_, view, txn| {
            let mut count = ScanCount::start(view, txn, EngineScan::TypeIndexRows, &[entity_type])?;
            let mut ids = Vec::new();
            for entry in view.port_entity_ids_by_type(txn, entity_type, None)? {
                count.row();
                ids.push(entry?);
            }
            count.defer(view);
            Ok(ids)
        })?;
        match composed {
            Some(ids) => Ok(ids),
            None => Ok(self.vault().entities_by_type(entity_type)?),
        }
    }

    /// [`crate::Vault::subtree`], walked over the room's ChildOf edges and
    /// base's while this surface's session is live.
    ///
    /// # Errors
    ///
    /// As [`crate::Vault::subtree`].
    pub fn raw_subtree(
        &self,
        root: &EntityId,
        max_depth: u32,
    ) -> MemoryResult<Vec<(EntityId, u32)>> {
        let composed =
            self.raw_composed_read(|_, view, txn| subtree_in(view, txn, root, max_depth))?;
        match composed {
            Some(entries) => Ok(entries),
            None => Ok(self.vault().subtree(root, max_depth)?),
        }
    }

    /// [`crate::Vault::ancestors`], walked over the room's ChildOf edges and
    /// base's while this surface's session is live.
    ///
    /// # Errors
    ///
    /// As [`crate::Vault::ancestors`].
    pub fn raw_ancestors(&self, node: &EntityId) -> MemoryResult<Vec<EntityId>> {
        let composed = self.raw_composed_read(|_, view, txn| ancestors_in(view, txn, node))?;
        match composed {
            Some(ids) => Ok(ids),
            None => Ok(self.vault().ancestors(node)?),
        }
    }

    /// [`crate::Vault::would_create_cycle`], walked over the room's ChildOf
    /// edges and base's while this surface's session is live.
    ///
    /// # Errors
    ///
    /// As [`crate::Vault::would_create_cycle`].
    pub fn raw_would_create_cycle(&self, node: &EntityId, target: &EntityId) -> MemoryResult<bool> {
        let composed =
            self.raw_composed_read(|_, view, txn| would_create_cycle_in(view, txn, node, target))?;
        match composed {
            Some(cycle) => Ok(cycle),
            None => Ok(self.vault().would_create_cycle(node, target)?),
        }
    }
}
