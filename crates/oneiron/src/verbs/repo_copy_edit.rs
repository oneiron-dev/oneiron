//! The owner's review and settlement of a retained document-copy edit
//! (FIX 13274, over #5025's `EntityDocument::repo_copy_edit_review_as` and
//! `settle_repo_copy_edit_as`; `docs/ops/repo-sync-settlement.md`).
//!
//! The review answers the held edit only under a live owner proof, which
//! the engine revalidates in the review's own read. The revision it answers
//! is a token the owner holds, never authority. Settlement takes the
//! revision the owner reviewed and the exact replacement text: it reads the
//! review again as the owner, refuses stale unless that revision is the
//! caller's, and hands the native setter the target-bound approval of that
//! revision and replacement. The setter checks the owner and the approval
//! again in its own writer. The answer is the committed DOCUMENT frame: a
//! local commit, not a delivery. `x:` evidence is neither read nor needed.

use base64::Engine as _;

use crate::consent::AuthenticatedOwner;
use crate::error::{ArtifactError, Error};
use crate::memory::{MemoryError, MemoryResult};
use crate::sync::documents::{EntityDocument, RepoCopyEditReview};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::repo_copy_edit::{
    RepoCopyEditReviewRequest, RepoCopyEditReviewView, RepoCopyEditSettleRequest,
    RepoCopyEditSettleView,
};

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_revision(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn view(review: &RepoCopyEditReview) -> RepoCopyEditReviewView {
    RepoCopyEditReviewView {
        source: review.source().to_hex(),
        cause: review.cause().as_str().to_owned(),
        submitted: review.submitted().to_owned(),
        revision: hex32(review.revision()),
    }
}

/// The held copy edit on `document`, reviewed as `owner` (the engine
/// revalidates the proof in the review's own read); `None` when no edit is
/// held there.
///
/// # Errors
/// The engine's owner, admission and storage refusals.
pub fn repo_copy_edit_review_as_owner(
    document: &EntityDocument,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Option<RepoCopyEditReviewView>> {
    Ok(document.repo_copy_edit_review_as(owner)?.as_ref().map(view))
}

/// Settles the held copy edit on `document` to `input.replacement` as
/// `owner`, under the revision the owner reviewed. Stale when no edit is
/// held now or its revision is not `input.revision`.
///
/// # Errors
/// `BAD_REQUEST` for a revision that is not 64 lowercase hex; the engine's
/// stale (`edit_proposal_stale`), owner, admission and storage refusals.
pub fn repo_copy_edit_settle_as_owner(
    document: &EntityDocument,
    owner: &AuthenticatedOwner,
    input: &RepoCopyEditSettleRequest,
) -> MemoryResult<RepoCopyEditSettleView> {
    let revision = parse_revision(&input.revision).ok_or_else(|| {
        MemoryError::bad_request("revision must be the 64 lowercase hex digits the review answered")
    })?;
    let Some(review) = document.repo_copy_edit_review_as(owner)? else {
        return Err(Error::Artifact(ArtifactError::EditProposalStale).into());
    };
    if review.revision() != &revision {
        return Err(Error::Artifact(ArtifactError::EditProposalStale).into());
    }
    let approval = review.approval_for(&input.replacement);
    let frame = document.settle_repo_copy_edit_as(owner, &approval, &input.replacement)?;
    Ok(RepoCopyEditSettleView {
        source: review.source().to_hex(),
        frame_base64: base64::engine::general_purpose::STANDARD.encode(frame),
    })
}
