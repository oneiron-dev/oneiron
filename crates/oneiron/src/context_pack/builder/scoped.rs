//! Candidate narrowing passthrough to the existing retrieval pipeline.
use super::ContextPackBuilder;

impl<'a> ContextPackBuilder<'a> {
    /// Apply the same scoped retrieval floor to every candidate channel.
    pub(crate) fn authority_filter(mut self, filter: crate::gate::ResolvedRetrievalFilter) -> Self {
        self.pipeline = self.pipeline.authority_filter(filter);
        self
    }

    /// Assembles for a caller off this device: the claims the pack counts
    /// as suppressed leave out every one a device-local world keeps
    /// (DEC-0005), as its scoped filter leaves out the rows. It only narrows.
    pub(crate) fn caller_off_device(mut self, off_device: bool) -> Self {
        self.off_device |= off_device;
        self.pipeline = self.pipeline.caller_off_device(off_device);
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
