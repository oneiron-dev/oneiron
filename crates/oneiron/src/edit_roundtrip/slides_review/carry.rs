//! Slide identities and carried judgments over a new head.
//! Entry: `carry_slide_judgments`.
//! SlideNow is defined here; slides_review forwards its crate-visible path.

use super::*;

/// One slide of a deck as a held review's split reads it: where it sits,
/// and what it shows.
pub(crate) struct SlideNow {
    /// Its 1-based number in the deck.
    pub(crate) slide: u64,
    pub(crate) part: String,
    pub(crate) sld_id: u32,
    pub(crate) creation_id: Option<u32>,
    /// The slide's normalized content with review metadata aside, then each
    /// other part it renders through: a comment written on it moves nothing.
    pub(crate) shows: [u8; 32],
}

impl SlideNow {
    /// Whether this is the slide a judgment's anchor names.
    pub(crate) fn is(&self, anchor: &SlideReviewAnchor) -> bool {
        self.part == anchor.slide_part && self.sld_id == anchor.sld_id
    }
}

/// Every slide of `bytes`, in deck order.
/// A resource refusal is the engine's error (FIX 10587), never an invalid deck.
pub(crate) fn deck_slides_now(bytes: &[u8], limits: Limits) -> Result<Vec<SlideNow>> {
    let inspection = inspect_pptx(bytes).map_err(|error| {
        crate::office_body::document_error(error.resource(), "held slide review deck")
    })?;
    let package = Package::open(bytes, limits, &crate::office_body::document_resources())
        .map_err(|error| {
            crate::office_body::document_error(error.resource(), "held slide review deck")
        })?;
    let view = DeckView::read(&package).map_err(|error| {
        crate::office_body::document_error(error.resource(), "held slide review deck view")
    })?;
    view.slides
        .iter()
        .zip(1u64..)
        .map(|(slide, number)| {
            let identity = inspection
                .slides
                .iter()
                .find(|identity| identity.part == slide.part)
                .ok_or_else(|| invalid("held slide review deck identity"))?;
            let mut shows = blake3::Hasher::new();
            shows.update(&identity.fingerprint);
            for dependency in slide
                .dependencies
                .iter()
                .filter(|dependency| dependency.part != slide.part)
            {
                shows.update(&(dependency.part.len() as u64).to_le_bytes());
                shows.update(dependency.part.as_bytes());
                shows.update(&dependency.hash);
            }
            Ok(SlideNow {
                slide: number,
                part: slide.part.clone(),
                sld_id: slide.sld_id,
                creation_id: slide.creation_id,
                shows: *shows.finalize().as_bytes(),
            })
        })
        .collect()
}

/// The untouched answers of a held slide review, carried onto a newer head
/// of the deck (ARCH-0075 §4): each comment is written again on its slide,
/// wherever that slide now sits, as one comment proposal on a copy of
/// `head`. Each answer keeps the revision it was judged against.
pub(crate) fn carry_slide_judgments(
    head: &[u8],
    head_version: u64,
    carried: Vec<(SlideJudgment, PptxCommentPatch)>,
    run_ref: &str,
    limits: Limits,
) -> Result<EditProposal> {
    let slides = deck_slides_now(head, limits)?;
    let mut rows = Vec::with_capacity(carried.len());
    let mut patches = Vec::with_capacity(carried.len());
    for (mut row, mut patch) in carried {
        let slide = slides
            .iter()
            .find(|slide| slide.is(&row.anchor))
            .ok_or_else(|| invalid("a carried slide is gone"))?;
        row.target.slide = slide.slide;
        patch.action = PptxCommentAction::Add {
            target: row.target.clone(),
            text: row.comment.clone(),
        };
        rows.push(row);
        patches.push(patch);
    }
    let mut proposal = run_comment_roundtrip(head, &patches, run_ref).map_err(|_| {
        Error::Artifact(crate::error::ArtifactError::EditRoundtripFailed(
            "the carried slide comments failed validation",
        ))
    })?;
    proposal.base_version = Some(head_version);
    proposal.manifest.slide_judgments = rows;
    verify_carried_judgments(&proposal)?;
    Ok(proposal)
}
