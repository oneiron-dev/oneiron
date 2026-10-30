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
    AnswerContract, BandMode, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial,
    DecisionMedia, DecisionMediaRef, DecisionQuestion, DecisionRung, EvidenceVersion, ImageRef,
    MAX_DECISION_IMAGE_BYTES, MAX_DECISION_STATE_BYTES, MediaCall, MediaServed, PairedReading,
    Reasoning, ReasoningCause, ResolvedMedia, Reversibility, SlideReviewLimits, StopCause,
    TypedDecision,
};
use crate::llm::image::ImageBytes;
use crate::retrieval_depth::RetrievalDeadline;
use crate::{Error, Result, Vault};
use oneiron_docedit::deck::{DeckView, ShapeView, SlideView, TemplateView};
use oneiron_docedit::retained_opc::{Limits, Package};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::{EditOp, OfficeFormat};
pub(crate) use carry::{SlideNow, carry_slide_judgments, deck_slides_now};
pub use run::review_slides;
pub(crate) use verify::{validate_judgment_rows, verify_carried_judgments, verify_judgments};

/// The name a unit's image goes by in its `state.media` and its call.
pub const REVIEW_IMAGE: &str = "review_image";

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

/// A review image's BLAKE3 hash in hex: the `hash` its [`ImageRef`] names in
/// `state.media`, and its judgment's `render_hash`, as text.
pub fn review_image_key(image: &[u8]) -> String {
    blake3::hash(image).to_hex().to_string()
}

/// The host's review renderer (ARCH-0077 "Review images"), which a proposer
/// wake asks for the changed slides of a held review: the engine renders
/// nothing itself.
pub trait SlideRenderer: Send + Sync {
    /// The renderer's identity, saved on each judgment as provisional evidence.
    fn name(&self) -> &str;
    /// One PNG or JPEG per entry of `slides` (1-based numbers in `deck`), in
    /// that order, each rendered from these exact bytes.
    fn render(&self, deck: &[u8], slides: &[u64]) -> Result<Vec<Vec<u8>>>;
    /// Reserve memory for `bytes` the caller is about to allocate; the
    /// reservation lives as long as the renderer (FIX 7653). A host's
    /// renderer refuses one the machine cannot hold, typed; a renderer that
    /// keeps no account of memory admits every one.
    fn admit(&self, bytes: u64) -> Result<()> {
        let _ = bytes;
        Ok(())
    }
    /// Name `reserved` of the bytes admitted allocated, as the `actual` bytes
    /// the caller now holds (FIX 8240): an exact reservation made, what an
    /// estimate came to, room left unused (`actual` 0), or bytes read before
    /// their size was known (`reserved` 0). Only bookkeeping: it never waits
    /// or refuses. A renderer that keeps no account of memory ignores it.
    fn materialized(&self, reserved: u64, actual: u64) {
        let _ = (reserved, actual);
    }
}

/// User-configured display words, including the severity words in comments.
/// No question, glossary, prompt or user-facing label is compiled into Rust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlideReviewLabels {
    pub yes: String,
    pub no: String,
    pub low: String,
    pub middle: String,
    pub high: String,
}

impl SlideReviewLabels {
    pub(crate) fn validate(&self) -> Result<()> {
        if [&self.yes, &self.no, &self.low, &self.middle, &self.high]
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > 128)
        {
            return Err(invalid("invalid slide review labels"));
        }
        Ok(())
    }
    pub(crate) fn comment(
        &self,
        answer: &DecisionAnswer,
        probability: f64,
        band: DecisionBand,
    ) -> String {
        let severity = if probability < band.low {
            &self.low
        } else if probability > band.high {
            &self.high
        } else {
            &self.middle
        };
        let text = match answer {
            DecisionAnswer::Noul(true) => self.yes.clone(),
            DecisionAnswer::Noul(false) => self.no.clone(),
            DecisionAnswer::Choice(value) => value.clone(),
            DecisionAnswer::Score(value) => value.to_string(),
            DecisionAnswer::Box(found) => found.map_or_else(
                || "absent".to_owned(),
                |found| {
                    format!(
                        "top {} bottom {} left {} right {}",
                        found.top, found.bottom, found.left, found.right
                    )
                },
            ),
            DecisionAnswer::Point(found) => found.map_or_else(
                || "absent".to_owned(),
                |found| format!("x {} y {}", found.x, found.y),
            ),
            DecisionAnswer::Abstain => unreachable!("abstentions never create comments"),
        };
        format!("{severity}: {text}")
    }
}

/// The managed anchor kept beside the comment, not only inside the exported
/// file (ARCH-0077, "Managed anchor"): the typed view's slide identity and
/// fingerprints, and for a shape unit its retained node and fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlideReviewAnchor {
    pub slide_part: String,
    pub sld_id: u32,
    pub slide_fingerprint: [u8; 32],
    pub render_fingerprint: [u8; 32],
    pub shape: Option<ShapeReviewAnchor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeReviewAnchor {
    /// The retained shape element: its part and document-order index.
    pub node_part: String,
    pub node_index: u64,
    pub shape_id: Option<u32>,
    pub fingerprint: [u8; 32],
}

/// Bound to its exported comment and exact source version. Settlement keeps
/// this record with the consume-once receipt, not just a client-side preview.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlideJudgment {
    pub thread_id: EntityId,
    pub target: PptxCommentTarget,
    pub anchor: SlideReviewAnchor,
    /// The shared ladder's decision and receipt, as it wrote them. For a Box or
    /// Point question, the coordinates' decision, or the presence step's when it
    /// was a confident no.
    pub decision: TypedDecision,
    /// The immutable primitive selected by the question version for this run;
    /// a Box or Point question's confident no stands on its presence step's Noul.
    pub answer_contract: AnswerContract,
    /// The presence step that started the coordinates; none for any other
    /// question, a ladder with no presence question, or a confident no.
    #[serde(default)]
    pub presence: Option<TypedDecision>,
    /// Where the located answer sits on the slide, for a host-rendered image of
    /// the whole slide at the deck's aspect; none for a stored image.
    #[serde(default)]
    pub location: Option<SlideLocation>,
    pub band_mode: BandMode,
    pub renderer: String,
    pub frontier: [u8; 32],
    /// The unit's `state.media`: its image's ref and whether its pixels rode
    /// with the call.
    #[serde(default)]
    pub media: Vec<DecisionMedia>,
    /// The hash of the image its media entry names (its ref's `hash`). A row
    /// from before media entries pinned its image on the receipt by it.
    pub render_hash: [u8; 32],
    /// Hash of the exact state the providers read: the unit, its text and its
    /// media entries.
    pub evidence_hash: [u8; 32],
    pub judged_version: Option<u64>,
    /// The deck's live body when it was reviewed: an edit to it never
    /// exported withdraws the slides it changed (FIX 2115).
    #[serde(default)]
    pub judged_live: Option<crate::office_body::LivePin>,
    pub comment: String,
    /// Runtime display words pinned so settle can recheck comment semantics.
    pub labels: SlideReviewLabels,
}

/// A located answer on its slide, in EMU from the slide's top-left corner: the
/// answer's fractions of a host-rendered whole-slide image times the deck's
/// slide size. A point is a box with no extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlideLocation {
    pub slide_width: i64,
    pub slide_height: i64,
    pub left: i64,
    pub top: i64,
    pub right: i64,
    pub bottom: i64,
}

impl SlideLocation {
    /// `answer`'s box or point on a slide of `size` (cx, cy), each edge rounded
    /// to the EMU; none when it found nothing, is not a box or point, or the
    /// size is not positive.
    pub fn of(answer: &DecisionAnswer, (width, height): (i64, i64)) -> Option<Self> {
        if width <= 0 || height <= 0 {
            return None;
        }
        let (left, top, right, bottom) = match answer {
            DecisionAnswer::Box(Some(found)) => (found.left, found.top, found.right, found.bottom),
            DecisionAnswer::Point(Some(found)) => (found.x, found.y, found.x, found.y),
            _ => return None,
        };
        let across = |fraction: f64| (fraction * width as f64).round() as i64;
        let down = |fraction: f64| (fraction * height as f64).round() as i64;
        Some(Self {
            slide_width: width,
            slide_height: height,
            left: across(left),
            top: down(top),
            right: across(right),
            bottom: down(bottom),
        })
    }

    /// A positive slide with the box inside it, its edges in order.
    pub fn within(&self) -> bool {
        self.slide_width > 0
            && self.slide_height > 0
            && 0 <= self.left
            && self.left <= self.right
            && self.right <= self.slide_width
            && 0 <= self.top
            && self.top <= self.bottom
            && self.bottom <= self.slide_height
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

/// A unit the ladder left unanswered. The decision carries its typed reason and
/// clock (a cut, no rung able to take it), or the presence step's when it left
/// a Box or Point question unanswered; none when the host had no image, or no
/// rung reads one for a Box or Point question.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlideAbstention {
    pub target: PptxCommentTarget,
    pub decision: Option<TypedDecision>,
}

/// A selected unit the review will not ask as given. A shape unit offers its
/// slide unit when the slide itself can be judged; a judgment never moves to a
/// nearby shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlideUnitRefusal {
    pub target: PptxCommentTarget,
    pub reason: SlideUnitRefusalReason,
    pub offer: Option<PptxCommentTarget>,
}

/// On the wire as its variant name (`MissingShape`, ...), the words a
/// review's refusals have always carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlideUnitRefusalReason {
    /// No shape on the slide carries the creation id.
    MissingShape,
    /// Several shapes carry it.
    AmbiguousShape,
    /// The shape no longer matches the caller's fingerprint.
    TargetChanged,
    /// The writer cannot verify the shape's slide-space position.
    UnresolvedGeometry,
    /// The unit's text, state or image exceeds the evidence budget; nothing is
    /// trimmed or scaled to fit.
    EvidenceBudget,
    /// The rendered image is not PNG or JPEG whose header gives its size.
    UnreadableImage,
    /// The run's deadline came before the unit's batch started: nothing was
    /// asked about it (FIX 9819).
    RunDeadline,
}

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
    /// deck's projection at its head, which the units' images were rendered
    /// from (FIX 11981). A unit is found there by its slide part and id; its
    /// comment still lands on `bytes`.
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

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
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
