//! Candidate narrowing passthrough to the existing retrieval pipeline.
use super::ContextPackBuilder;

impl<'a> ContextPackBuilder<'a> {
    /// Apply the same scoped retrieval floor to every candidate channel.
    pub(crate) fn authority_filter(mut self, filter: crate::gate::ResolvedRetrievalFilter) -> Self {
        self.pipeline = self.pipeline.authority_filter(filter);
        self
    }

    /// Assembles for a caller whose rows go to `destination`: no row a world
    /// withholds from one of its machines enters its retrieval or its edge
    /// walk (DEC-0005, mesh PR2b), so no count, reason or clamp sees one. It
    /// only narrows: each machine is a conjunct.
    pub(crate) fn for_destination(
        mut self,
        destination: &crate::settings::ReadDestination,
    ) -> Self {
        self.destination.meet(destination);
        self.pipeline = self.pipeline.for_destination(destination);
        self
    }

    pub(crate) fn filter_candidates(
        mut self,
        filter: &'a crate::pipeline::CandidateFilter<'a>,
    ) -> Self {
        self.pipeline = self.pipeline.filter_candidates(filter);
        self
    }

    /// Narrows to one facet, as the retrieval pipeline's own facet stage
    /// does (FIX 9961): a facet recall assembles and renders through the
    /// same builder as every other recall.
    pub(crate) fn facet(
        mut self,
        facet_id: &crate::EntityId,
        mode: crate::pipeline::FacetMode,
    ) -> Self {
        self.pipeline = self.pipeline.facet(facet_id, mode);
        self
    }
}
