//! Moved from `crates/oneiron/src/office_body/pptx/verbs.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::office_body::pptx::PptxBody;
use crate::office_body::pptx::PptxReview;
use oneiron_docedit::edit::Preset;
use oneiron_docedit::live::DeckDiff;
use oneiron_docedit::live::Gate;
use oneiron_docedit::live::GeometryProps;
use oneiron_docedit::live::NodeId;
use oneiron_docedit::live::NodeKind;
use oneiron_docedit::live::NodePayload;
use oneiron_docedit::live::OracleReceipt;
use oneiron_docedit::live::TextBody;
use oneiron_docedit::live::deck_export::PROJECTOR_VERSION;
pub use oneiron_verb_wire::office_body::pptx::verbs::DeckExportRequest;
pub use oneiron_verb_wire::office_body::pptx::verbs::DeckForkMergeRequest;
pub use oneiron_verb_wire::office_body::pptx::verbs::DeckGateRequest;
pub use oneiron_verb_wire::office_body::pptx::verbs::DeckOracleRequest;
use serde::Deserialize;
use serde::Serialize;

/// One deck node as a reader and an operation's author see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckNodeView {
    pub id: NodeId,
    pub kind: NodeKind,
    /// The slide or group holding it; `None` for a slide.
    pub parent: Option<NodeId>,
    pub name: Option<String>,
    /// Read from the imported package; false for a live-born node.
    pub imported: bool,
    pub geometry: GeometryProps,
    /// The placeholder kind and index, as read.
    pub placeholder: Option<(String, u32)>,
    pub preset: Option<Preset>,
    pub payload: Option<NodePayload>,
    /// A text shape's body, with the paragraph ids `set_text` keeps.
    pub text: Option<TextBody>,
    /// Who made it; `None` for imported content.
    pub made_by: Option<String>,
}

/// `vault.artifacts.body.read` for a deck: every node under the root in tree
/// order (each slide, then its shapes), at `frontier`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckBodyView {
    pub frontier: Vec<u8>,
    /// Operations applied since import.
    pub version: u64,
    pub nodes: Vec<DeckNodeView>,
}

/// `vault.artifacts.body.deck.review`: the fork's merge preflight against
/// the live head. A merge names `head` and `fork_head` and lands only when
/// `ok`, the fork up to `fork_head`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckReviewView {
    pub head: Vec<u8>,
    /// The fork's frontier this review read (FIX 9992).
    pub fork_head: Vec<u8>,
    pub head_version: u64,
    pub ok: bool,
    pub diff: DeckDiff,
    pub replay_refusals: Vec<String>,
    /// Units the fork touches that the head changed since its base.
    pub stale_units: Vec<NodeId>,
    /// Why the relationship and render evidence could not be attached.
    pub evidence_refusal: Option<String>,
}

/// `vault.artifacts.body.deck.gate` and `.oracle`: one profile's export
/// gate, open only on a clean all-pass receipt from a run of the current
/// projector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckGateView {
    pub profile: String,
    /// This server's projector. The receipt names its own run's projector,
    /// source revision and case manifest (FIX 3772); a receipt from a run of
    /// another projector is shown as that run's and opens nothing.
    pub projector: String,
    pub open: bool,
    pub receipt: Option<OracleReceipt>,
}

impl From<PptxBody> for DeckBodyView {
    fn from(body: PptxBody) -> Self {
        let PptxBody {
            mut deck,
            attribution,
            frontier,
            ..
        } = body;
        let nodes = deck
            .descendants(NodeId(0))
            .into_iter()
            .filter_map(|id| {
                let node = deck.nodes.remove(&id)?;
                Some(DeckNodeView {
                    id,
                    kind: node.kind,
                    parent: node.parent.filter(|parent| *parent != NodeId(0)),
                    name: node.name,
                    imported: node.binding.is_some(),
                    geometry: node.geometry,
                    placeholder: node.placeholder,
                    preset: node.preset,
                    payload: node.payload,
                    text: deck.texts.remove(&id),
                    made_by: attribution
                        .created_by
                        .get(&id)
                        .map(|(actor, _)| actor.clone()),
                })
            })
            .collect();
        Self {
            frontier,
            version: deck.version,
            nodes,
        }
    }
}

impl From<PptxReview> for DeckReviewView {
    fn from(review: PptxReview) -> Self {
        Self {
            head: review.head,
            fork_head: review.fork_head,
            head_version: review.report.head_version,
            ok: review.report.ok,
            diff: review.report.diff,
            replay_refusals: review.report.replay_refusals,
            stale_units: review.stale_units,
            evidence_refusal: review.evidence_refusal,
        }
    }
}

impl From<Gate> for DeckGateView {
    fn from(gate: Gate) -> Self {
        Self {
            open: gate.is_open(),
            profile: gate.profile,
            projector: PROJECTOR_VERSION.to_owned(),
            receipt: gate.receipt,
        }
    }
}
