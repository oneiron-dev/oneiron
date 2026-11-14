//! Engine comment requests over the docedit organ's PowerPoint comment types.

pub use oneiron_docedit::pptx_comments::{
    PptxAnchorOutcome, PptxAuthor, PptxCommentAction, PptxCommentEffects, PptxCommentTarget,
    PptxDriftReason, PptxError, PptxInspection, PptxShapeIdentity, PptxSlideIdentity,
};

pub(super) type PatchResult<T> = std::result::Result<T, PptxError>;

#[doc(hidden)]
pub use oneiron_verb_wire::edit_roundtrip::pptx::package::PptxCommentPatch;

/// Keeps package refusals typed while retaining the existing vault error as a source.
#[derive(Debug, thiserror::Error)]
pub enum PptxProposalError {
    #[error(transparent)]
    Patch(#[from] PptxError),
    #[error(transparent)]
    Vault(#[from] crate::error::Error),
}
