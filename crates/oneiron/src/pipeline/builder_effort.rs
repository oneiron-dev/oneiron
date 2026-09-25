//! Shared five-level stage selection for the raw pipeline and memory facade.
use super::PipelineBuilder;
use crate::entity_id::EntityId;
use crate::memory::Effort;
use crate::retrieval_depth::RetrievalDeadline;

impl<'a> PipelineBuilder<'a> {
    /// Checks the same monotonic deadline before optional retrieval stages.
    /// Inspect `deadline.was_cut_short()` after the terminal run for honest partial status.
    pub fn deadline(mut self, deadline: &'a RetrievalDeadline) -> Self {
        self.deadline = Some(deadline);
        self
    }
    pub(in crate::pipeline) fn deadline_reached(&self) -> bool {
        self.deadline
            .is_some_and(RetrievalDeadline::stop_before_stage)
    }
    /// Adds the graph and temporal stages for one canonical effort level.
    /// Dense/phonetic inputs and a prepared reranker remain explicit host inputs.
    /// Facade preflight requires a lease and reranker for paid tiers; raw builders
    /// may run this plan first to prepare its exact candidate snapshot.
    pub fn retrieval_effort(mut self, effort: Effort, seeds: &[EntityId]) -> Self {
        let now = self.temporal_now.unwrap_or_else(crate::unix_seconds_now);
        let limit = self.result_limit;
        // Respect a host-resolved interval. With no temporal hint, an exact
        // now anchor contributes no historical scan; the effort dial must not
        // turn every lexical query into "return the entire vault since birth".
        if self.temporal_search.is_none() {
            self = if effort == Effort::Max {
                self.search_temporal_bitemporal(
                    now,
                    now,
                    0,
                    now,
                    crate::pipeline::types::DEFAULT_SIGMA_SECS,
                    limit,
                )
            } else {
                self.search_temporal(now, now, limit)
            };
            if let Some(config) = self.temporal_search.as_mut() {
                config.effort_anchor = true;
            }
        }
        if effort != Effort::Light {
            self = self
                .search_ppr(seeds, 1)
                .boost_salience()
                .boost_confidence();
        }
        if effort.requires_rerank() {
            self = self.expand_ppr(seeds, effort.graph_depth());
        }
        self
    }
}
