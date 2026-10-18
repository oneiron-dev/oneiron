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

/// Persisted-row structural ceiling; a decoder must accept every row we write.
pub(crate) const MAX_JUDGMENTS: usize = 4096;

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
}

/// User-configured display words, including the severity words in comments.
/// No question, glossary, prompt or user-facing label is compiled into Rust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Whether a `width` by `height` image is drawn at the slide's own aspect,
/// within 1%: what a render of the whole slide is.
fn whole_slide((width, height): (u32, u32), (cx, cy): (i64, i64)) -> bool {
    width > 0
        && height > 0
        && cx > 0
        && cy > 0
        && ((f64::from(width) / f64::from(height)) / (cx as f64 / cy as f64) - 1.0).abs() <= 0.01
}

#[derive(Debug, Clone)]
pub struct SlideReviewRun {
    /// `None` when no unit was answered; no empty or phantom write is settled.
    pub proposal: Option<EditProposal>,
    pub abstained: Vec<SlideAbstention>,
    pub refused: Vec<SlideUnitRefusal>,
}

/// A unit the ladder left unanswered. The decision carries its typed reason and
/// clock (a cut, no rung able to take it), or the presence step's when it left
/// a Box or Point question unanswered; none when the host had no image, or no
/// rung reads one for a Box or Point question.
#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// One question over selected slide/shape units, one decide() call per unit
/// under the run's deadline. The ladder routes each call (its first rung, one
/// step up for a cause, a skipped empty rung, the cut rule) and writes its
/// receipt; an abstention lists its unit with that receipt. A Human ceiling is
/// refused: the landing is a comment proposal, not a person's queue. Errors and
/// malformed output leave no partial proposal behind.
pub fn review_slides(
    base: &SlideReviewBase<'_>,
    request: &SlideReviewRequest<'_>,
) -> std::result::Result<SlideReviewRun, SlideReviewError> {
    let SlideReviewRequest {
        units,
        question,
        principal,
        answered_by,
        author,
        dial,
        resident_dial,
        limits,
        policy,
        reversibility,
        labels,
        decider,
        evidence,
        budget,
        deadline,
        run_ref,
        at,
    } = *request;
    question.validate()?;
    let dial = resident_dial.map_or(Ok(dial), |resident| dial.narrow(resident))?;
    dial.band.validate()?;
    if !limits.valid() {
        return Err(invalid("invalid slide review limits").into());
    }
    let band_policy = policy.resolve(question, reversibility, dial.band)?;
    labels.validate()?;
    if dial.first > dial.ceiling
        || dial.ceiling == DecisionRung::Human
        || units.len() > limits.max_units
        || budget.is_zero()
    {
        return Err(invalid("invalid slide review selection or dial").into());
    }
    let inspection = inspect_pptx(base.bytes)?;
    if !inspection.signature_parts.is_empty() {
        return Err(PptxError::SignedPackage.into());
    }
    let package = Package::open(base.bytes, base.package_limits)
        .map_err(|_| invalid("slide review package"))?;
    let view = DeckView::read(&package).map_err(|_| invalid("slide review deck view"))?;
    // A located answer is kept in slide EMU when the deck gives its size.
    let slide_size = if question.contract.locates() {
        TemplateView::read(&package)
            .map_err(|_| invalid("slide review deck size"))?
            .slide_size
    } else {
        None
    };
    let frontier = *blake3::hash(base.bytes).as_bytes();
    let deck = EvidenceVersion {
        id: base.artifact,
        body_hash: frontier,
    };
    let evidence: Vec<EntityId> = evidence
        .iter()
        .copied()
        .chain(std::iter::once(base.artifact))
        .collect();
    let mut seen = HashSet::new();
    let mut abstained = Vec::new();
    let mut refused = Vec::new();
    let mut judgments = Vec::new();
    let mut patches = Vec::new();
    for unit in units {
        let target = &unit.target;
        let shape_key = target
            .shape_creation_id
            .as_deref()
            .map(canonical_guid)
            .transpose()?;
        let slide = target
            .slide
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| view.slides.get(index));
        let identity = inspection
            .slides
            .iter()
            .find(|slide| slide.slide == target.slide);
        let (Some(slide), Some(identity)) = (slide, identity) else {
            return Err(invalid("invalid slide review unit").into());
        };
        if slide.part != identity.part
            || slide.sld_id != identity.sld_id
            || target
                .slide_creation_id
                .is_some_and(|id| slide.creation_id != Some(id))
            || !seen.insert((target.slide, shape_key.clone()))
            || unit.image.len() > limits.max_image_bytes
            || unit.renderer.len() > 256
        {
            return Err(invalid("invalid slide review unit or exceeded evidence budget").into());
        }
        let read = match read_unit(slide, identity, target, shape_key.as_deref()) {
            Ok(read) => read,
            Err(reason) => {
                refused.push(refusal(target, reason));
                continue;
            }
        };
        // An unavailable image is not a negative answer or a malformed call.
        if unit.image.is_empty() || unit.renderer.trim().is_empty() {
            abstained.push(SlideAbstention {
                target: target.clone(),
                decision: None,
            });
            continue;
        }
        // A decision reads an image whole or not at all: none is scaled to fit.
        if unit.image.len() > MAX_DECISION_IMAGE_BYTES {
            refused.push(refusal(target, SlideUnitRefusalReason::EvidenceBudget));
            continue;
        }
        // A render's pixel size, which a located answer maps onto the slide.
        let (medium, rendered) = match &unit.image {
            SlideReviewImage::Rendered(bytes) => {
                let Some(media_type) = image_media_type(bytes) else {
                    refused.push(refusal(target, SlideUnitRefusalReason::UnreadableImage));
                    continue;
                };
                let image = ImageBytes {
                    bytes: bytes.clone(),
                    media_type: media_type.to_owned(),
                };
                let Ok(reference) = ImageRef::of(deck.clone(), &image, None) else {
                    refused.push(refusal(target, SlideUnitRefusalReason::UnreadableImage));
                    continue;
                };
                let size = (reference.width, reference.height);
                let medium = ResolvedMedia::Image {
                    name: REVIEW_IMAGE.to_owned(),
                    reference,
                    image,
                };
                (medium, Some(size))
            }
            SlideReviewImage::Stored(medium) => (medium.clone(), None),
        };
        // The host's decider says which rung its pixels ride to, if any.
        let call = MediaCall::of(dial, vec![medium], |images| {
            decider.first_taking(question, dial, images)
        })
        .map_err(|_| invalid("invalid slide review image"))?;
        let render_hash = call
            .entries
            .first()
            .map(|entry| medium_hash(&entry.reference))
            .ok_or_else(|| invalid("invalid slide review image"))?;
        // A Box or Point question locates in pixels: with none sent, nothing is
        // asked.
        if call.images.is_empty() && question.contract.locates() {
            abstained.push(SlideAbstention {
                target: target.clone(),
                decision: None,
            });
            continue;
        }
        let state = call
            .state(serde_json::json!({
                "unit": {
                    "slide": target.slide,
                    "sld_id": slide.sld_id,
                    "slide_creation_id": slide.creation_id,
                    "shape_creation_id": shape_key,
                    "shape_id": read.anchor.shape.as_ref().and_then(|shape| shape.shape_id),
                    "shape_name": read.name,
                },
                "text": read.text,
                "renderer": unit.renderer,
            }))
            .map_err(|_| invalid("slide review unit state"))?;
        let state_bytes =
            serde_json::to_vec(&state).map_err(|_| invalid("slide review unit state"))?;
        if read.text.len() > limits.max_text_bytes || state_bytes.len() > MAX_DECISION_STATE_BYTES {
            refused.push(refusal(target, SlideUnitRefusalReason::EvidenceBudget));
            continue;
        }
        let now = Instant::now();
        let clock =
            RetrievalDeadline::hard(now, budget.min(deadline.saturating_duration_since(now)));
        let unit_call = UnitCall {
            question,
            principal,
            evidence: &evidence,
            images: &call.images,
            state: &state,
            dial: call.dial,
            policy,
            reversibility,
            deadline: &clock,
        };
        // A Box or Point question asks presence first: its coordinates stand
        // with the presence step beside them, or a confident no stands alone.
        let (mut decision, mut presence, answered, answer_contract) = if question.contract.locates()
        {
            let located = decider.decide_located(&unit_call)?;
            let answered = located.answer != DecisionAnswer::Abstain;
            let contract = if located.location.is_some() {
                question.contract.clone()
            } else {
                AnswerContract::Noul
            };
            let (decision, presence) = located.split();
            (decision, presence, answered, contract)
        } else {
            let decision = decider.decide_unit(&unit_call)?;
            let answered = decision.answer != DecisionAnswer::Abstain;
            (decision, None, answered, question.contract.clone())
        };
        // The deck at its frontier, then each other version an image the
        // ladder was shown is of (a rendered image is of the deck itself).
        let pin_versions = |decision: &mut TypedDecision| {
            decision.receipt.evidence_versions = std::iter::once(deck.clone())
                .chain(
                    call.images
                        .iter()
                        .map(|image| image.evidence.clone())
                        .filter(|version| *version != deck),
                )
                .collect();
        };
        pin_versions(&mut decision);
        if let Some(presence) = &mut presence {
            pin_versions(presence);
        }
        if !answered {
            abstained.push(SlideAbstention {
                target: target.clone(),
                decision: Some(decision),
            });
            continue;
        }
        let probability = decision
            .probability
            .ok_or_else(|| invalid("missing review probability"))?;
        let location = rendered
            .zip(slide_size)
            .filter(|&(pixels, size)| whole_slide(pixels, size))
            .and_then(|(_, size)| SlideLocation::of(&decision.answer, size));
        let thread_id = EntityId::now();
        let comment = labels.comment(&decision.answer, probability, decision.receipt.band);
        patches.push(PptxCommentPatch {
            asked_by: principal,
            answered_by,
            author: author.clone(),
            thread_id,
            comment_id: thread_id,
            at,
            action: PptxCommentAction::Add {
                target: target.clone(),
                text: comment.clone(),
            },
        });
        judgments.push(SlideJudgment {
            thread_id,
            target: target.clone(),
            anchor: read.anchor,
            decision,
            answer_contract,
            presence,
            location,
            band_mode: band_policy.mode,
            renderer: unit.renderer.clone(),
            frontier,
            media: call.entries,
            render_hash,
            evidence_hash: *blake3::hash(&state_bytes).as_bytes(),
            judged_version: base.version,
            comment,
            labels: labels.clone(),
        });
    }
    if patches.is_empty() {
        return Ok(SlideReviewRun {
            proposal: None,
            abstained,
            refused,
        });
    }
    let mut proposal = run_comment_roundtrip(base.bytes, &patches, run_ref)?;
    proposal.base_version = base.version;
    proposal.manifest.slide_judgments = judgments;
    proposal.manifest.slide_question = Some(question.clone());
    Ok(SlideReviewRun {
        proposal: Some(proposal),
        abstained,
        refused,
    })
}

/// What the typed view gives one unit: its text, managed anchor and shape name.
struct UnitRead {
    text: String,
    anchor: SlideReviewAnchor,
    name: Option<String>,
}

/// A slide unit reads every text-bearing shape in document order; a shape unit
/// reads its one shape, which the writer must be able to anchor at its own
/// verified slide-space top-left.
fn read_unit(
    slide: &SlideView,
    identity: &PptxSlideIdentity,
    target: &PptxCommentTarget,
    shape_key: Option<&str>,
) -> std::result::Result<UnitRead, SlideUnitRefusalReason> {
    let mut anchor = SlideReviewAnchor {
        slide_part: slide.part.clone(),
        sld_id: slide.sld_id,
        slide_fingerprint: slide.content_fingerprint,
        render_fingerprint: slide.render_fingerprint,
        shape: None,
    };
    let Some(key) = shape_key else {
        let text = slide
            .shapes
            .iter()
            .filter_map(shape_text)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        return Ok(UnitRead {
            text,
            anchor,
            name: None,
        });
    };
    let shape = match slide
        .shapes
        .iter()
        .filter(|shape| shape.creation_id.as_deref() == Some(key))
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => return Err(SlideUnitRefusalReason::MissingShape),
        [shape] => *shape,
        _ => return Err(SlideUnitRefusalReason::AmbiguousShape),
    };
    let written = match identity
        .shapes
        .iter()
        .filter(|shape| shape.creation_id.as_deref() == Some(key))
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => return Err(SlideUnitRefusalReason::MissingShape),
        [written] => *written,
        _ => return Err(SlideUnitRefusalReason::AmbiguousShape),
    };
    if target
        .shape_fingerprint
        .is_some_and(|fingerprint| fingerprint != written.fingerprint)
    {
        return Err(SlideUnitRefusalReason::TargetChanged);
    }
    if written.position.is_none() {
        return Err(SlideUnitRefusalReason::UnresolvedGeometry);
    }
    anchor.shape = Some(ShapeReviewAnchor {
        node_part: shape.node.part.clone(),
        node_index: shape.node.index as u64,
        shape_id: shape.id,
        fingerprint: shape.content_fingerprint,
    });
    Ok(UnitRead {
        text: shape_text(shape).unwrap_or_default(),
        anchor,
        name: shape.name.clone(),
    })
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

fn refusal(target: &PptxCommentTarget, reason: SlideUnitRefusalReason) -> SlideUnitRefusal {
    let offer = (target.shape_creation_id.is_some()
        && !matches!(
            reason,
            SlideUnitRefusalReason::EvidenceBudget | SlideUnitRefusalReason::UnreadableImage
        ))
    .then(|| PptxCommentTarget {
        shape_creation_id: None,
        shape_fingerprint: None,
        ..target.clone()
    });
    SlideUnitRefusal {
        target: target.clone(),
        reason,
        offer,
    }
}

/// A render's media type, from its signature: PNG or JPEG only.
fn image_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else {
        None
    }
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

/// The encoder, preview and settlement share the same row-validity bound.
/// Uniqueness is checked independently of PPTX replay so discard cannot
/// persist a row the selected writer (or the ledger decoder) would reject.
pub(crate) fn validate_judgment_rows(rows: &[SlideJudgment]) -> Result<()> {
    if rows.len() > MAX_JUDGMENTS {
        return Err(invalid("too many persisted slide judgments"));
    }
    let mut threads = HashSet::new();
    let mut units = HashSet::new();
    for row in rows {
        let shape = row
            .target
            .shape_creation_id
            .as_deref()
            .map(|id| {
                uuid::Uuid::parse_str(id)
                    .map_err(|_| invalid("invalid slide judgment shape identity"))
            })
            .transpose()?;
        if !threads.insert(row.thread_id) || !units.insert((row.target.slide, shape)) {
            return Err(invalid("duplicate slide judgment thread or unit"));
        }
    }
    Ok(())
}

/// Validate the receipt against the actual comment ops at the settle door.
/// A public manifest is not a source of authority to invent judgment receipts.
pub(crate) fn verify_judgments(proposal: &EditProposal) -> Result<()> {
    verify_rows(proposal, false)
}

/// [`verify_judgments`] for answers the engine carried onto a newer head at
/// Keep: each still names the deck revision it was judged against, which may
/// be older than the proposal's base.
pub(crate) fn verify_carried_judgments(proposal: &EditProposal) -> Result<()> {
    verify_rows(proposal, true)
}

fn verify_rows(proposal: &EditProposal, carried: bool) -> Result<()> {
    let rows = &proposal.manifest.slide_judgments;
    validate_judgment_rows(rows)?;
    if rows.is_empty() {
        return Ok(());
    }
    let patches: Vec<_> = proposal
        .manifest
        .ops
        .iter()
        .filter_map(|op| {
            if let super::EditOp::PptxComment { patch } = op {
                Some(patch)
            } else {
                None
            }
        })
        .collect();
    if proposal.format != super::OfficeFormat::Pptx || rows.len() != patches.len() {
        return Err(invalid("review receipt/comment mismatch"));
    }
    for (row, patch) in rows.iter().zip(patches) {
        let PptxCommentAction::Add { target, text } = &patch.action else {
            return Err(invalid("review receipt requires a new comment"));
        };
        let decision = &row.decision;
        let receipt = &decision.receipt;
        let probability = decision
            .probability
            .ok_or_else(|| invalid("missing review probability"))?;
        if decision.answer == DecisionAnswer::Abstain || decision.human_ask.is_some() {
            return Err(invalid("abstentions cannot create comments"));
        }
        if row.thread_id != patch.thread_id
            || row.thread_id != patch.comment_id
            || row.target != *target
            || row.comment != *text
            || receipt.principal != patch.asked_by
            || !probability.is_finite()
            || !(0.0..=1.0).contains(&probability)
            || receipt.band.validate().is_err()
            || row.labels.validate().is_err()
            || row.answer_contract.validate().is_err()
            || !row.answer_contract.accepts(&decision.answer)
            || row.comment
                != row
                    .labels
                    .comment(&decision.answer, probability, receipt.band)
            || (row.band_mode == BandMode::Enforce && receipt.band_version == 0)
            || !ladder_route(row, probability)
            || !PairedReading::readings_valid(
                &receipt.paired,
                &receipt.person,
                receipt.question,
                &receipt.providers,
            )
            || receipt.question_version == 0
            || receipt.evidence_versions.iter().any(|version| {
                version.body_hash != row.frontier
                    && !row.media.iter().any(|entry| {
                        entry.served == MediaServed::Full && entry.reference.evidence() == version
                    })
                    // A row from before media entries pinned its image by its hash.
                    && (!row.media.is_empty() || version.body_hash != row.render_hash)
            })
            || row
                .media
                .iter()
                .any(|entry| medium_hash(&entry.reference) != row.render_hash)
            || row.location.as_ref().is_some_and(|location| {
                !location.within()
                    || SlideLocation::of(
                        &decision.answer,
                        (location.slide_width, location.slide_height),
                    )
                    .as_ref()
                        != Some(location)
            })
            || row.presence.as_ref().is_some_and(|presence| {
                presence.answer != DecisionAnswer::Noul(true)
                    || presence.in_band
                    || presence.human_ask.is_some()
                    || presence.receipt.principal != receipt.principal
                    || !row.answer_contract.locates()
            })
            || row.anchor.slide_part.is_empty()
            || row.anchor.shape.is_some() != target.shape_creation_id.is_some()
            || (!carried
                && (row.frontier != proposal.base_content_hash
                    || row.judged_version != proposal.base_version))
            || row.renderer.trim().is_empty()
            || row.renderer.len() > 256
        {
            return Err(invalid("review receipt/comment mismatch"));
        }
    }
    Ok(())
}

/// Whether the receipt is one the shared ladder writes for an answered unit below
/// the person: on the decision clock, either the first read standing (clear, or
/// taken at the cut outside its band) or one read a rung up for its cause.
fn ladder_route(row: &SlideJudgment, probability: f64) -> bool {
    let decision = &row.decision;
    let receipt = &decision.receipt;
    let Some(time) = receipt.time else {
        return false;
    };
    let enforced_margin = decision.in_band && row.band_mode == BandMode::Enforce;
    if receipt.providers.iter().any(|pin| {
        pin.model.trim().is_empty()
            || pin.version.trim().is_empty()
            || pin.rung == DecisionRung::Human
    }) || time.answered != receipt.providers.last().map(|pin| pin.rung)
    {
        return false;
    }
    match (receipt.providers.as_slice(), time.reasoning) {
        ([_], Reasoning::NotNeeded) => {
            time.stop == StopCause::Done
                && decision.in_band == receipt.band.contains(probability)
                && !enforced_margin
        }
        ([_], Reasoning::Skipped(_) | Reasoning::Cut(_)) => {
            time.stop == StopCause::Deadline
                && !decision.in_band
                && !receipt.band.contains(probability)
        }
        ([first, second], Reasoning::Ran(cause)) => {
            second.rung > first.rung
                && time.stop == StopCause::Done
                && match cause {
                    ReasoningCause::SmallMargin => enforced_margin,
                    ReasoningCause::PairedHigh => {
                        !enforced_margin && receipt.paired.iter().any(|row| row.provider == *first)
                    }
                    ReasoningCause::SecondMeasurement => false,
                }
        }
        _ => false,
    }
}

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
pub(crate) fn deck_slides_now(bytes: &[u8], limits: Limits) -> Result<Vec<SlideNow>> {
    let inspection = inspect_pptx(bytes).map_err(|_| invalid("held slide review deck"))?;
    let package = Package::open(bytes, limits).map_err(|_| invalid("held slide review deck"))?;
    let view = DeckView::read(&package).map_err(|_| invalid("held slide review deck view"))?;
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

#[derive(Debug, thiserror::Error)]
pub enum SlideReviewError {
    #[error(transparent)]
    Vault(#[from] Error),
    #[error(transparent)]
    Pptx(#[from] PptxError),
    #[error(transparent)]
    Proposal(#[from] PptxProposalError),
}

impl Vault {
    /// Review one artifact head through the host's decide() ladder. Keep/discard
    /// through the existing consume-once edit-settle door; a changed head is
    /// retained as a stale preview.
    pub fn review_blob_artifact_slides(
        &self,
        artifact: &EntityId,
        request: &SlideReviewRequest<'_>,
    ) -> std::result::Result<SlideReviewRun, SlideReviewError> {
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact)?
            .ok_or(Error::EntityNotFound)?;
        if super::OfficeFormat::from_media_type(&body.media_type)? != super::OfficeFormat::Pptx {
            return Err(PptxError::InvalidPatch.into());
        }
        let bytes = self
            .read_blob_artifact_version(artifact, head.version)?
            .ok_or(Error::EntityNotFound)?;
        self.review_blob_artifact_slides_at(artifact, head.version, &bytes, request)
    }

    /// [`Self::review_blob_artifact_slides`] over one version's `bytes`, which
    /// the units' images were rendered from.
    pub(crate) fn review_blob_artifact_slides_at(
        &self,
        artifact: &EntityId,
        version: u64,
        bytes: &[u8],
        request: &SlideReviewRequest<'_>,
    ) -> std::result::Result<SlideReviewRun, SlideReviewError> {
        // The policy read ends before any provider call starts.
        let (vault_limits, route) = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            let vault_limits = policy
                .slide_review_limits(request.principal)
                .ok_or_else(|| invalid("slide review policy manifest is invalid"))?;
            let route = policy
                .slide_review_route(request.principal)
                .ok_or_else(|| invalid("slide review route manifest is invalid"))?;
            (vault_limits, route)
        };
        let owner_dial = DecisionDial {
            first: route.first,
            ceiling: route.ceiling,
            band: request.dial.band,
        };
        let effective = SlideReviewRequest {
            limits: vault_limits.restrict(request.limits),
            dial: owner_dial.narrow(request.dial)?,
            ..*request
        };
        let base = SlideReviewBase {
            bytes,
            version: Some(version),
            artifact: *artifact,
            package_limits: self.docedit_package_limits()?,
        };
        let run = review_slides(&base, &effective)?;
        if let Some(proposal) = &run.proposal {
            self.measure_pptx_comment_patches(proposal);
        }
        Ok(run)
    }
}

#[cfg(test)]
mod tests;
