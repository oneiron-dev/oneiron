//! In-room vector retrieval over the composed union (FIX 10759): the
//! session sibling of `Vault::search_vector`, as `search_text_routed` is of
//! `Vault::search_text`. The room's staged vectors are scored beside base's
//! HNSW walk (`Vault::scoped_vector_search_quality_in_txn`), and the run
//! registers through the route the caller captured, so an off-record room's
//! run row stays in the room and goes when it closes.

use super::OffRecordSession;
use crate::ScoredEntity;
use crate::error::{Error, Result};
use crate::session_overlay::SessionWriteRoute;

impl OffRecordSession<'_> {
    /// Nearest neighbours of `query` by cosine similarity over this room's
    /// overlay ∪ base, its run registered through `route`. The query is
    /// checked as `Vault::search_vector` checks it: the vault's dimensions,
    /// or its `fast_dims` prefix, and finite components.
    ///
    /// # Errors
    ///
    /// A stale route, a caller off the room's roster, a query of the wrong
    /// width or with a non-finite component; storage errors.
    pub(crate) fn search_vector_routed(
        &self,
        route: &SessionWriteRoute,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        route.revalidate()?;
        let config = &self.vault.config;
        if query.len() != config.dimensions
            && config.fast_dims.map(usize::from) != Some(query.len())
        {
            return Err(Error::DimensionMismatch {
                expected: config.dimensions,
                got: query.len(),
            });
        }
        if let Some(error) = Error::invalid_vector_component(query) {
            return Err(error);
        }
        let started_at = self.vault.store.clock.now_recorded_at();
        let started = std::time::Instant::now();
        let view = self.read_view()?;
        let read = view.read();
        let scores = {
            let rtxn = self.vault.store.env.read_txn()?;
            self.participant_in_txn(&rtxn)?;
            self.vault.scoped_vector_search_quality_in_txn(
                &read,
                &rtxn,
                query,
                limit,
                false,
                (None, None),
            )?
        };
        self.register_search(
            route,
            crate::store::RetrievalSignal::Vector,
            scores,
            (started_at, started),
            limit,
            read.holds_room_rows(),
        )
    }
}
