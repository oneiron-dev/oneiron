//! The residence page mode (FIX 8865): a home's paged residence search ranks
//! its text channel as deep as the device's whole request, past the channel's
//! candidate window, under the same scoring, scope and admission. Every other
//! run keeps the window.

use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::channels::scoped_text_channel_limit;

impl PipelineBuilder<'_> {
    /// Ranks the text channel as deep as the run's own limit asks, for a
    /// home's paged residence search alone.
    #[cfg(feature = "sync")]
    pub(crate) fn residence_page(mut self) -> Self {
        self.residence_page = true;
        self
    }

    /// How many rows the text channel fetches for `requested`: never past the
    /// candidate window, but in a residence page run the whole request.
    pub(super) fn text_channel_limit(&self, requested: usize) -> usize {
        if self.residence_page {
            requested
        } else {
            scoped_text_channel_limit(requested, self.result_limit())
        }
    }
}
