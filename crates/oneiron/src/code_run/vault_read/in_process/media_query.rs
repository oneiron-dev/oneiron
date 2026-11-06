//! Native media-query execution and its host-supplied memory line.

use crate::pipeline::ScoredEntity;

use super::{
    EmbeddedMediaSeed, InProcessVaultReadAdapter, VaultReadMethod, VaultReadResult, engine_failure,
};

impl<'v> InProcessVaultReadAdapter<'v> {
    /// Use the host's memory line for native copies of these media queries.
    #[must_use]
    pub fn with_media_query_memory(
        mut self,
        memory: &'v crate::host_memory::MachineMemory,
    ) -> Self {
        self.media_memory = Some(memory);
        self
    }

    /// Host media seeds, the one-space preset's text-slot seed among them,
    /// are each one more ranked list beside the text and vector seeds, as on
    /// the accepted route's `run_core_query`. A query asked in an affect
    /// rides the seeded search, the one that takes it.
    pub(super) fn run_query(
        &self,
        query: Option<&str>,
        vector: Option<&[f32]>,
        media: &[EmbeddedMediaSeed],
        limit: usize,
        affect: Option<oneiron_contracts::affect::Vad>,
    ) -> VaultReadResult<crate::claim::ScopedReadResult<Vec<ScoredEntity>>> {
        let results = if media.is_empty() && affect.is_none() {
            match (query, vector) {
                (Some(query), Some(vector)) => self.scoped_read.search(query, vector, limit, None),
                (Some(query), None) => self.scoped_read.search_text(query, limit, None),
                (None, Some(vector)) => self.scoped_read.search_vector(vector, limit, None),
                (None, None) => self.scoped_read.read_receipt(None, 0).map(|receipt| {
                    crate::claim::ScopedReadResult {
                        value: Vec::new(),
                        receipt,
                    }
                }),
            }
        } else {
            let media: Vec<_> = media
                .iter()
                .map(|seed| {
                    (
                        seed.space.as_str(),
                        seed.kind,
                        seed.vector.as_slice(),
                        seed.kinds.as_slice(),
                    )
                })
                .collect();
            self.scoped_read.search_seeded(
                query,
                vector,
                &media,
                limit,
                None,
                affect,
                self.media_memory,
            )
        };
        results.map_err(|error| engine_failure(VaultReadMethod::Query, &error))
    }
}
