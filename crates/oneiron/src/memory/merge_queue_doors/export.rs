//! `vault.code.merge_queue.export_green` (FIX 6868, G2 PR3): the owner
//! exports the queue's current tested green through the unchanged reviewed
//! origin export.
//!
//! The engine resolves the sealed revision of the live green pointer under
//! the queue's repository writer, which it holds through the export, so the
//! green cannot move between them. The export's object store must be the
//! queue's. Every reason it holds is the queue's one named readiness (CALL
//! E), with its way out; nothing is approved, rebased, rechecked or retried
//! against a wider target. The export itself is `code_export_as` with the
//! engine-resolved revision: the same live-checkout redemption, served-store
//! check, origin authority and explicit ref and CAS.
use super::*;
use crate::memory::origin_doors::{CodeExportRequest, CodeExportResult};
use crate::merge_queue::{QueueExportHold, QueueExportHoldReason};
use crate::origin::smart_http::origin_repo_dir;

impl Memory<'_> {
    /// `vault.code.merge_queue.export_green`: the current green's sealed
    /// tested revision, promoted by its applied sources and exported to
    /// `ref_name` through the owner's live checkout. Owner only.
    pub fn merge_queue_export_green_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueGreenExportRequest,
    ) -> MemoryResult<CodeExportResult> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        queue.with_repository_writer(|| {
            let green = queue.green_revision()?.map_err(held_error)?;
            self.merge_queue_readable(green.revision_id())?;
            self.merge_queue_readable(green.revision().session_id)?;
            let served = GitWire::new(self.vault)?
                .repository_identity(&origin_repo_dir(self.vault, &input.served_repo)?)?;
            if served.as_hex() != green.store() {
                return Err(held_error(QueueExportHold::new(
                    QueueExportHoldReason::HeldStore,
                    "the served repository's object store is not the queue's",
                )));
            }
            queue.queue_export_readiness(&green)?.map_err(held_error)?;
            self.vault.promote_queue_code_revision(&green)?;
            self.code_export_as(
                owner,
                CodeExportRequest {
                    repo: input.served_repo,
                    checkout: input.checkout,
                    epoch: input.epoch,
                    revision: green.revision_id(),
                    ref_name: input.ref_name,
                    expected_old_oid: input.expected_old_oid,
                    endpoint: input.endpoint,
                },
            )
        })?
    }
}

/// A named hold as the door answers it: the reason's wire name and detail,
/// and its way out as the suggestion.
fn held_error(hold: QueueExportHold) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!(
            "export_green holds ({}): {}",
            hold.reason.as_str(),
            hold.detail
        ),
        &[hold.way_out.as_str()],
    )
}
