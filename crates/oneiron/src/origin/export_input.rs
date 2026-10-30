//! What an engine commit export stands on (FIX 6869, G4 PR3): the shared
//! load the exporter and the exact preview both read, so the preview can
//! never drift from the export's own eligibility.
//!
//! The load rechecks the finalized fold trace, the promotion, the canonical
//! authorship and message, the active provenance and the live author, in
//! the order the exporter always judged them. The exporter reads the
//! immutable stored promotion and refuses at the first gap, as before. The
//! preview reads readiness instead: the stored receipt when it holds, else
//! the queue's own read-only gap, and it names each gap rather than
//! refusing. Nothing here writes a promotion or any other row.
use crate::Vault;
use crate::claim::ClaimLifecycleStatus;
use crate::code_revision::{CodeCommitMetadata, CodeRevision, QueuePromotionGap};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::repo_mutation::REPO_PROVENANCE_TRAILER_KEY;

/// How a load judges the revision's promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExportPromotion {
    /// The export: the immutable stored receipt, judged again; a missing
    /// or differing one refuses.
    Stored,
    /// The preview: the stored receipt when it holds, otherwise whether
    /// the chain can be promoted now, read only. A gap is named.
    Readiness,
}

/// A source the preview's load found missing; the export refuses on each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ExportGap {
    /// The chain's root holds untouched bytes no reviewed import admits now.
    UntouchedBytes(String),
    /// A change lacks its admitted reviewed operation, or an ordinary
    /// revision its promotion.
    Unreviewed(String),
    /// The provenance claim is gone or no longer active.
    Provenance(EntityId),
    /// The author's record is gone; `None` when the author was erased
    /// before the seal (FIX 7348).
    Author(Option<EntityId>),
}

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

/// The exported commit's message: the canonical message with the
/// revision's provenance trailer, which the message must not supply itself.
///
/// # Errors
/// A message that already carries a provenance trailer.
pub(super) fn export_message(
    metadata: &CodeCommitMetadata,
    provenance: EntityId,
) -> Result<String> {
    if crate::repo_mutation::parse_repo_provenance_trailer(&metadata.message)?.is_some() {
        return Err(Error::InvariantViolation(
            "export message must not supply its own provenance trailer",
        ));
    }
    Ok(format!(
        "{}\n\n{REPO_PROVENANCE_TRAILER_KEY}: {}\n",
        metadata.message.trim_end(),
        provenance.to_hex()
    ))
}
