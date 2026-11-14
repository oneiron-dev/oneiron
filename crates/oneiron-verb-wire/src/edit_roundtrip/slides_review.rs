//! Moved from `crates/oneiron/src/edit_roundtrip/slides_review.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::llm::decision::media_ref::DecisionMedia;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_docedit::pptx_comments::PptxCommentTarget;
pub use oneiron_store::blob_artifact::slide_review::REVIEW_IMAGE;
pub use oneiron_store::blob_artifact::slide_review::SlideRenderer;
pub use oneiron_store::blob_artifact::slide_review::SlideUnitRefusalReason;
pub(crate) use oneiron_store::blob_artifact::slide_review::review_copy_bytes;
pub use oneiron_store::blob_artifact::slide_review::review_image_key;
use oneiron_store::model_decision::AnswerContract;
use oneiron_store::model_decision::BandMode;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::DecisionBand;
use oneiron_store::model_decision::DecisionRung;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::time::Duration;
use std::time::Instant;

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
    pub fn validate(&self) -> Result<()> {
        if [&self.yes, &self.no, &self.low, &self.middle, &self.high]
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > 128)
        {
            return Err(invalid("invalid slide review labels"));
        }
        Ok(())
    }

    pub fn comment(&self, answer: &DecisionAnswer, probability: f64, band: DecisionBand) -> String {
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
/// Each fingerprint is hex on a JSON wire (FIX 9342).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlideReviewAnchor {
    pub slide_part: String,
    pub sld_id: u32,
    #[serde(with = "oneiron_docedit::hex_digest")]
    #[schemars(with = "String")]
    pub slide_fingerprint: [u8; 32],
    #[serde(with = "oneiron_docedit::hex_digest")]
    #[schemars(with = "String")]
    pub render_fingerprint: [u8; 32],
    pub shape: Option<ShapeReviewAnchor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ShapeReviewAnchor {
    /// The retained shape element: its part and document-order index.
    pub node_part: String,
    pub node_index: u64,
    pub shape_id: Option<u32>,
    #[serde(with = "oneiron_docedit::hex_digest")]
    #[schemars(with = "String")]
    pub fingerprint: [u8; 32],
}

/// Bound to its exported comment and exact source version. Settlement keeps
/// this record with the consume-once receipt, not just a client-side preview.
/// Its frontier and hashes are hex on a JSON wire (FIX 9342).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The ceiling rung of the dial the ladder ran under: an enforced in-band
    /// answer from that rung stands with no reasoning step, since no stronger
    /// rung is left to read it again (FIX 10745).
    pub ceiling: DecisionRung,
    pub renderer: String,
    #[serde(with = "oneiron_docedit::hex_digest")]
    #[schemars(with = "String")]
    pub frontier: [u8; 32],
    /// The unit's `state.media`: its image's ref and whether its pixels rode
    /// with the call.
    #[serde(default)]
    pub media: Vec<DecisionMedia>,
    /// The hash of the image its media entry names (its ref's `hash`).
    #[serde(with = "oneiron_docedit::hex_digest")]
    #[schemars(with = "String")]
    pub render_hash: [u8; 32],
    /// Hash of the exact state the providers read: the unit, its text and its
    /// media entries.
    #[serde(with = "oneiron_docedit::hex_digest")]
    #[schemars(with = "String")]
    pub evidence_hash: [u8; 32],
    pub judged_version: Option<u64>,
    /// The deck's live body when it was reviewed: an edit to it never
    /// exported withdraws the slides it changed (FIX 2115).
    #[serde(default)]
    pub judged_live: Option<oneiron_store::typed_body::live_pin::LivePin>,
    pub comment: String,
    /// Runtime display words pinned so settle can recheck comment semantics.
    pub labels: SlideReviewLabels,
}

/// A located answer on its slide, in EMU from the slide's top-left corner: the
/// answer's fractions of a host-rendered whole-slide image times the deck's
/// slide size. A point is a box with no extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

/// A unit the ladder left unanswered. The decision carries its typed reason and
/// clock (a cut, no rung able to take it), or the presence step's when it left
/// a Box or Point question unanswered; none when the host had no image, or no
/// rung reads one for a Box or Point question.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlideAbstention {
    pub target: PptxCommentTarget,
    pub decision: Option<TypedDecision>,
    /// The live body the review read the unit on, when it read one: its
    /// decision names the head version as evidence (FIX 12051).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judged_live: Option<oneiron_store::typed_body::live_pin::LivePin>,
}

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
