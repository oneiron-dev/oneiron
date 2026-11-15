//! Moved from `crates/oneiron/src/office_body/pptx.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::office_body::pptx::preview::DeckPreview;
pub use crate::office_body::pptx::preview::DeckPreviewSlide;
pub use crate::office_body::pptx::verbs::DeckBodyView;
pub use crate::office_body::pptx::verbs::DeckGateView;
pub use crate::office_body::pptx::verbs::DeckNodeView;
pub use crate::office_body::pptx::verbs::DeckReviewView;
use oneiron_docedit::live::AttributionIndex;
use oneiron_docedit::live::LiveDeck;
use oneiron_docedit::live::NodeId;
use oneiron_docedit::live::PreflightReport;
use oneiron_docedit::live::StampedOp;
pub use oneiron_verb_wire::office_body::pptx::preview::DeckPreviewRequest;
pub use oneiron_verb_wire::office_body::pptx::verbs::DeckExportRequest;
pub use oneiron_verb_wire::office_body::pptx::verbs::DeckForkMergeRequest;
pub use oneiron_verb_wire::office_body::pptx::verbs::DeckGateRequest;
pub use oneiron_verb_wire::office_body::pptx::verbs::DeckOracleRequest;

/// A typed read of the deck body at one frontier.
#[derive(Debug, Clone)]
pub struct PptxBody {
    pub deck: LiveDeck,
    /// Every stamped operation the body holds, in log order.
    pub log: Vec<StampedOp>,
    /// Who made each visible thing; imported content has no maker.
    pub attribution: AttributionIndex,
    pub frontier: Vec<u8>,
}

/// A deck fork reviewed against the head it would land on.
#[derive(Debug, Clone)]
pub struct PptxReview {
    pub head: Vec<u8>,
    /// The fork's frontier this review read; a landing applies the fork up
    /// to it, beside `head` (FIX 9992).
    pub fork_head: Vec<u8>,
    pub report: PreflightReport,
    /// Units the fork touches that the head changed since its base: their
    /// answers are withdrawn (ARCH-0075 section 4), untouched units carry.
    pub stale_units: Vec<NodeId>,
    /// Why the relationship and render components could not be attached
    /// (the head or the candidate does not project); the diff then keeps its
    /// conservative affected slides.
    pub evidence_refusal: Option<String>,
}
pub mod preview;
pub mod verbs;
