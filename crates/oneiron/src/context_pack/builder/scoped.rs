//! Candidate narrowing passthrough to the existing retrieval pipeline.
use super::ContextPackBuilder;

impl<'a> ContextPackBuilder<'a> {
    pub(crate) fn authority_filter(mut self, filter: crate::gate::ResolvedRetrievalFilter) -> Self {
        self.pipeline = self.pipeline.authority_filter(filter);
        self
    }

    pub(crate) fn filter_candidates(
        mut self,
        filter: &'a crate::pipeline::CandidateFilter<'a>,
    ) -> Self {
        self.pipeline = self.pipeline.filter_candidates(filter);
        self
    }
}
