//! Core half of `origin::export_input`: its store-layer items live in `oneiron_store::origin::export_input` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::export_input::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::repo_provenance_trailer::REPO_PROVENANCE_TRAILER_KEY;
use crate::store::{
    code_commit_metadata::CodeCommitMetadata, code_promotion_gap::QueuePromotionGap,
    code_revision_record::CodeRevision,
};
use oneiron_contracts::claim::ClaimLifecycleStatus;

/// One loaded export revision: the persisted record, its canonical
/// authorship and message, its provenance, and the preview's named gaps
/// (always empty for [`ExportPromotion::Stored`]).
#[derive(Debug)]
pub(super) struct VerifiedEngineExport {
    pub(super) revision: CodeRevision,
    pub(super) metadata: CodeCommitMetadata,
    pub(super) provenance: EntityId,
    pub(super) gaps: Vec<ExportGap>,
}

impl Vault {
    /// The finalized revision `revision_id`, its promotion judged as
    /// `promotion` reads it, and its authorship, message and provenance.
    ///
    /// # Errors
    /// A missing or unfinalized revision, one with no canonical authorship
    /// or provenance, or a store failure; under
    /// [`ExportPromotion::Stored`] also a promotion gap, an inactive
    /// provenance or a gone author.
    pub(super) fn load_engine_export_revision(
        &self,
        revision_id: EntityId,
        promotion: ExportPromotion,
    ) -> Result<VerifiedEngineExport> {
        let revision = self
            .get_code_revision(&revision_id)?
            .ok_or(Error::EntityNotFound)?;
        // Recheck the complete fold trace, including the stored session frontier.
        if !self
            .code_revisions_for_session(&revision.session_id)?
            .contains(&revision)
        {
            return Err(Error::InvariantViolation(
                "engine export revision is not finalized",
            ));
        }
        let mut gaps = Vec::new();
        // Session membership authenticates history, not independent approval.
        // Recheck the immutable promotion receipt before creating any Git object.
        match promotion {
            ExportPromotion::Stored => self.require_code_revision_promotion(revision_id)?,
            ExportPromotion::Readiness => gaps.extend(self.export_promotion_readiness(&revision)?),
        }
        let metadata = revision
            .commit_metadata
            .clone()
            .ok_or(Error::InvariantViolation(
                "engine commit has no canonical authorship/message",
            ))?;
        let provenance = revision
            .provenance_claim_id
            .ok_or(Error::InvariantViolation(
                "engine commit export requires provenance",
            ))?;
        if self
            .get_claim(&provenance)?
            .is_none_or(|body| body.lifecycle != ClaimLifecycleStatus::Active)
        {
            match promotion {
                ExportPromotion::Stored => {
                    return Err(Error::InvariantViolation(
                        "engine commit export provenance is not active",
                    ));
                }
                ExportPromotion::Readiness => gaps.push(ExportGap::Provenance(provenance)),
            }
        }
        let readable = match &metadata.author {
            Some(author) => self.get_entity_type(author)?.is_some(),
            None => false,
        };
        if !readable {
            match promotion {
                ExportPromotion::Stored => return Err(Error::EntityNotFound),
                ExportPromotion::Readiness => gaps.push(ExportGap::Author(metadata.author)),
            }
        }
        Ok(VerifiedEngineExport {
            revision,
            metadata,
            provenance,
            gaps,
        })
    }

    /// Whether `revision` stands promoted, or could be now: its stored
    /// receipt judged again, else the queue's own read-only gap. A chain
    /// the queue can promote now is ready, as `export_green` promotes it
    /// before it exports. Nothing is written.
    fn export_promotion_readiness(&self, revision: &CodeRevision) -> Result<Option<ExportGap>> {
        let reason = match self.require_code_revision_promotion(revision.revision_id) {
            Ok(()) => return Ok(None),
            Err(Error::InvalidClaimBody(reason)) => reason,
            Err(error) => return Err(error),
        };
        if revision.tested_queue.is_none() {
            return Ok(Some(ExportGap::Unreviewed(reason.to_owned())));
        }
        Ok(self
            .queue_promotion_gap(revision.revision_id)?
            .map(|gap| match gap {
                QueuePromotionGap::UntouchedBytes(detail) => ExportGap::UntouchedBytes(detail),
                QueuePromotionGap::Unreviewed(detail) => ExportGap::Unreviewed(detail),
            }))
    }
}
