//! Typed weave publication and persisted correction reads for the bound reader.
use super::{ClaimReadStatus, ScopedReadReceipt, WeaveLinkCorrectionView, WeaveWrongLinkRequest};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryResult};
use serde::{Deserialize, Serialize};

/// A completed publication. Read its sections through `vault.weave.digest`
/// with `scheduled_for`; the trigger does not run the lens's model step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WeaveDigestRendered {
    pub scheduled_for: u64,
    pub rendered_at: u64,
    pub narrowing: ScopedReadReceipt,
}

impl Memory<'_> {
    /// Publish the bound reader's due period through the same live scoped
    /// lens. The engine rechecks the report and advances the schedule in
    /// the publication transaction. No due schedule means no write.
    pub fn weave_digest_render(
        &self,
        owner: Option<&AuthenticatedOwner>,
    ) -> MemoryResult<Option<WeaveDigestRendered>> {
        let reader = self.weave_reader(owner)?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(read
            .render_due_weave_digest(reader, self.vault().now_recorded_at())?
            .map(|stored| WeaveDigestRendered {
                scheduled_for: stored.scheduled_for,
                rendered_at: stored.rendered_at,
                narrowing: stored.report.receipt,
            }))
    }

    /// Read the actual persisted wrong labels, while the link still passes
    /// the caller's live report admission. Reading never changes the edge.
    pub fn weave_link_corrections(
        &self,
        request: &WeaveWrongLinkRequest,
    ) -> MemoryResult<Vec<WeaveLinkCorrectionView>> {
        let reader = self.weave_reader(None)?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(read
            .weave_link_corrections(reader, request.link()?)?
            .iter()
            .map(WeaveLinkCorrectionView::from_correction)
            .collect())
    }
}
