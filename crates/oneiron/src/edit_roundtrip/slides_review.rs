//! Typed slide review model and API seam.
//! Entry: `review_slides`.
//! run, verify, carry and doors own the forwarded behavior.
//!
//! Bounded typed review of slide/shape units into one retained comment proposal.
//!
//! Every unit is one call through the shared decide() ladder (ARCH-0076 §2).
//! The engine reads each unit's identity and text from the typed deck view; the
//! host supplies only the rendered image. Its ref (what it was rendered from or
//! the ASSET it is, its hash and size) sits in `state.media`, and its pixels ride
//! beside the state, through the host's decider, to a rung that reads images
//! (owner point 3). When no rung up to the ceiling reads one, the entry says so
//! and the call stands on the text. A Box or Point question asks the host's
//! presence question first (owner point 4); a located answer over a host-rendered
//! whole slide is kept in slide EMU beside its fractions. No provider output may
//! select the principal,
//! receipt, comment anchor, or settle authority. The existing PPTX writer owns
//! OOXML.

mod carry;
mod doors;
mod run;
mod verify;

use super::EditProposal;
use super::artifact_question::{UnitCall, UnitDecider};
use super::pptx::{
    PptxAuthor, PptxCommentAction, PptxCommentPatch, PptxCommentTarget, PptxError,
    PptxProposalError, PptxSlideIdentity, inspect_pptx, run_comment_roundtrip,
};
use crate::EntityId;
use crate::llm::decision::{
    AnswerContract, BandMode, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionMediaRef,
    DecisionQuestion, DecisionRung, EvidenceVersion, ImageRef, MAX_DECISION_STATE_BYTES, MediaCall,
    MediaServed, PairedReading, Reasoning, ReasoningCause, ResolvedMedia, Reversibility,
    SlideReviewLimits, StopCause, TypedDecision,
};
use crate::llm::image::ImageBytes;
use crate::retrieval_depth::RetrievalDeadline;
use crate::{Error, Result, Vault};
use oneiron_docedit::deck::{DeckView, ShapeView, SlideView, TemplateView};
use oneiron_docedit::retained_opc::{Limits, Package};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::{EditOp, OfficeFormat};
pub(crate) use carry::{SlideNow, carry_slide_judgments, deck_slides_now};
pub use run::review_slides;
pub(crate) use verify::{validate_judgment_rows, verify_carried_judgments, verify_judgments};

pub use crate::blob_artifact::slide_review::REVIEW_IMAGE;

/// One caller-approved unit and its rendered image. The renderer must have
/// rendered these exact `base` bytes; its identity is saved beside the deck
/// frontier, not treated as PowerPoint oracle evidence. The unit's text is
/// read from the deck, never supplied by the host.
#[derive(Debug, Clone)]
pub struct SlideReviewUnit {
    pub target: PptxCommentTarget,
    pub image: SlideReviewImage,
    pub renderer: String,
}

/// A unit's rendered image.
#[derive(Debug, Clone)]
pub enum SlideReviewImage {
    /// PNG or JPEG bytes the host rendered from the base deck, handed in with
    /// the call; empty when it has none. Its ref is the deck at its frontier.
    Rendered(Vec<u8>),
    /// A stored image, resolved through the asker's own lane under its
    /// [`REVIEW_IMAGE`] name; its ref is the ASSET at its hash.
    Stored(ResolvedMedia),
}

impl SlideReviewImage {
    fn len(&self) -> usize {
        match self {
            Self::Rendered(bytes)
            | Self::Stored(ResolvedMedia::Audio { bytes, .. })
            | Self::Stored(ResolvedMedia::Image {
                image: ImageBytes { bytes, .. },
                ..
            }) => bytes.len(),
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub(crate) use crate::blob_artifact::slide_review::review_copy_bytes;
pub use crate::blob_artifact::slide_review::{SlideRenderer, review_image_key};

#[doc(hidden)]
use oneiron_verb_wire::edit_roundtrip::slides_review::invalid;
#[doc(hidden)]
pub use oneiron_verb_wire::edit_roundtrip::slides_review::{
    ShapeReviewAnchor, SlideAbstention, SlideJudgment, SlideLocation, SlideReviewAnchor,
    SlideReviewLabels,
};

/// One head of an artifact as a slide review reads it (FIX 9624): see
/// [`Vault::slide_review_snapshot`].
pub(crate) struct SlideReviewSnapshot {
    pub(crate) version: u64,
    /// The version's own bytes, where the review's comments land.
    pub(crate) bytes: Vec<u8>,
    /// The rows those bytes were read from (FIX 5455).
    pub(crate) read_rows: Vec<EntityId>,
    /// A live body's deck at its head and the pin read before it: the deck
    /// the units' text is read from (FIX 12019).
    pub(crate) live: Option<(crate::office_body::LivePin, Vec<u8>)>,
}

impl SlideReviewSnapshot {
    /// The deck the units' text is read from: the live body's, else the
    /// version's own. A host draws the units' images from the same deck.
    pub(crate) fn shown_deck(&self) -> &[u8] {
        self.live.as_ref().map_or(&self.bytes, |(_, deck)| deck)
    }
}

#[derive(Debug, Clone)]
pub struct SlideReviewRun {
    /// `None` when no unit was answered; no empty or phantom write is settled.
    pub proposal: Option<EditProposal>,
    pub abstained: Vec<SlideAbstention>,
    pub refused: Vec<SlideUnitRefusal>,
    /// The rows the vault's own reads picked for the run (FIX 5455): the
    /// head version it reviews, as its version CLAIM and ASSET. A review of
    /// bytes its caller holds lists none.
    pub read_rows: Vec<EntityId>,
}

/// A selected unit the review will not ask as given. A shape unit offers its
/// slide unit when the slide itself can be judged; a judgment never moves to a
/// nearby shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlideUnitRefusal {
    pub target: PptxCommentTarget,
    pub reason: SlideUnitRefusalReason,
    pub offer: Option<PptxCommentTarget>,
    /// The live body the review read the unit on, when it read one
    /// (FIX 12051).
    pub judged_live: Option<crate::office_body::LivePin>,
}

pub use crate::blob_artifact::slide_review::SlideUnitRefusalReason;

/// The exact deck a review reads.
#[derive(Clone, Copy)]
pub struct SlideReviewBase<'a> {
    pub bytes: &'a [u8],
    pub version: Option<u64>,
    /// The artifact these bytes are a version of: each call's evidence id,
    /// pinned to the frontier on its receipt, and what a rendered image is of.
    pub artifact: EntityId,
    pub package_limits: Limits,
    /// The deck each unit's text is read from when it is not `bytes`: a live
    /// deck's projection at its head, which a wake renders the units' images
    /// from (FIX 11981, 12019). A unit is found there by its slide part and
    /// id; its comment still lands on `bytes`.
    pub shown: Option<&'a [u8]>,
}

/// One typed ask, whose principal and display configuration are fixed by the
/// caller, never by a provider result. The host brings the shared ladder.
#[derive(Clone, Copy)]
pub struct SlideReviewRequest<'a> {
    pub units: &'a [SlideReviewUnit],
    pub question: &'a DecisionQuestion,
    pub principal: EntityId,
    pub answered_by: EntityId,
    pub author: &'a PptxAuthor,
    pub dial: DecisionDial,
    /// Optional holder choice, narrowed against the owner dial.
    pub resident_dial: Option<DecisionDial>,
    /// Manifest-resolved limits; a vault call re-imposes its stored policy.
    pub limits: SlideReviewLimits,
    pub policy: &'a DecisionBandPolicy,
    pub reversibility: Reversibility,
    pub labels: &'a SlideReviewLabels,
    /// The host's decide() every unit goes through; the review keeps no rungs.
    pub decider: &'a dyn UnitDecider,
    /// Access-checked evidence beside the deck, such as the excerpt a claim cites.
    pub evidence: &'a [EntityId],
    /// Each unit call's anytime budget, from when it is asked.
    pub budget: Duration,
    /// The run's deadline: no call's clock runs past it.
    pub deadline: Instant,
    pub run_ref: &'a str,
    pub at: u64,
}

/// What the typed view gives one unit: its text, managed anchor and shape name.
struct UnitRead {
    text: String,
    anchor: SlideReviewAnchor,
    name: Option<String>,
}

/// A shape's paragraphs, one line each; `None` for a shape with no text body.
pub(super) fn shape_text(shape: &ShapeView) -> Option<String> {
    let body = shape.text.as_ref()?;
    Some(
        body.paragraphs
            .iter()
            .map(|paragraph| {
                paragraph
                    .runs
                    .iter()
                    .map(|run| run.text.as_str())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// The hash of the exact bytes a media entry names: an image's own, or an
/// audio clip's, which its ASSET version is at.
fn medium_hash(reference: &DecisionMediaRef) -> [u8; 32] {
    match reference {
        DecisionMediaRef::Image(image) => image.hash,
        DecisionMediaRef::Audio(audio) => audio.evidence.body_hash,
    }
}

fn canonical_guid(id: &str) -> Result<String> {
    uuid::Uuid::parse_str(id)
        .map(|id| format!("{{{id}}}").to_ascii_uppercase())
        .map_err(|_| invalid("invalid slide review shape identity"))
}

#[derive(Debug, thiserror::Error)]
pub enum SlideReviewError {
    #[error(transparent)]
    Vault(#[from] Error),
    #[error(transparent)]
    Pptx(#[from] PptxError),
    #[error(transparent)]
    Proposal(#[from] PptxProposalError),
}

#[cfg(test)]
mod tests;
