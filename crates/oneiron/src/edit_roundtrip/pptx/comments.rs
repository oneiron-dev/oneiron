//! The engine door onto the docedit organ's modern-comment writer: engine
//! identities become Office GUIDs, and fresh slide creation IDs draw on
//! engine entropy.

use super::limits::PptxOperationalLimits;
use super::package::*;
use crate::entity_id::EntityId;
use oneiron_docedit::pptx_comments::{self, SlideMints};
use std::collections::BTreeSet;

/// Applies only modern-comment operations. It never edits slide content, repairs
/// identities, fetches relationships, or claims application-level validation.
/// An empty batch returns the exact original archive, including signatures.
pub fn comment_patch(
    base: &[u8],
    patches: &[PptxCommentPatch],
) -> Result<PptxCommentEffects, PptxError> {
    comment_patch_with_limits(base, patches, &PptxOperationalLimits::default())
}

pub(super) fn comment_patch_with_limits(
    base: &[u8],
    patches: &[PptxCommentPatch],
    limits: &PptxOperationalLimits,
) -> Result<PptxCommentEffects, PptxError> {
    patch_with_mints(base, patches, None, limits)
}

pub(super) fn patch_with_mints(
    base: &[u8],
    patches: &[PptxCommentPatch],
    mints: Option<&[(u64, u32)]>,
    limits: &PptxOperationalLimits,
) -> PatchResult<PptxCommentEffects> {
    if !limits.valid() {
        return Err(PptxError::InvalidPatch);
    }
    let edits: Vec<_> = patches.iter().map(PptxCommentPatch::edit).collect();
    let entropy = EntityId::now();
    let mints = match mints {
        Some(mints) => SlideMints::Replay(mints),
        None => SlideMints::Draw(entropy.as_bytes()),
    };
    pptx_comments::comment_patch(base, &edits, mints, &limits.codec())
}

/// IDs of exported root comments that explicitly have no resolved anchor.
/// The annotation sweep uses this actual-byte evidence to pin those threads.
#[cfg(test)]
pub(crate) fn unknown_anchor_threads(bytes: &[u8]) -> Result<BTreeSet<EntityId>, PptxError> {
    unknown_anchor_threads_with_limits(bytes, &PptxOperationalLimits::default())
}

pub(crate) fn unknown_anchor_threads_with_limits(
    bytes: &[u8],
    limits: &PptxOperationalLimits,
) -> Result<BTreeSet<EntityId>, PptxError> {
    Ok(
        pptx_comments::unknown_anchor_threads(bytes, &limits.codec())?
            .into_iter()
            .filter_map(|id| EntityId::from_bytes(id).ok())
            .collect(),
    )
}
