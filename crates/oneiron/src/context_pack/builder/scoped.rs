//! Candidate narrowing passthrough to the existing retrieval pipeline.
use super::ContextPackBuilder;

impl<'a> ContextPackBuilder<'a> {
    pub(crate) fn filter_candidates(
        mut self,
        filter: &'a crate::pipeline::CandidateFilter<'a>,
    ) -> Self {
        self.pipeline = self.pipeline.filter_candidates(filter);
        self
    }
}
