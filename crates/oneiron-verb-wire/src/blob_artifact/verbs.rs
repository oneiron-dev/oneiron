//! Moved from `crates/oneiron/src/blob_artifact/verbs.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::edit_roundtrip::slides_review::SlideReviewLabels;
use base64::Engine as _;
use oneiron_authority::share_travel::TravelChoice;
use oneiron_docedit::edit::transaction::DeckTransaction;
use oneiron_docedit::pptx_comments::PptxAuthor;
use oneiron_docedit::pptx_comments::PptxCommentTarget;
use oneiron_store::blob_artifact::deck_context::DeckEditContext;
use oneiron_store::blob_artifact::review_request::SlideReviewLimitsInput;
use oneiron_store::blob_artifact::slide_review::SlideUnitRefusalReason;
use oneiron_store::model_decision::DecisionDial;
use oneiron_store::model_decision::DecisionQuestion;
use oneiron_store::model_decision::Reversibility;
use oneiron_store::write_envelope::provenance::made_by::MadeBy;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;

/// One file of a folder ask and the result row its answer fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FolderItemInput {
    pub artifact_ref: String,
    pub row: u32,
}

/// One artifact, by ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRefRequest {
    pub artifact_ref: String,
}

/// One version's export: `version`, or the head when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactExportRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub version: Option<u64>,
    /// The born-with text to send with the file; absent sends none (OF-491).
    #[serde(default)]
    pub travel: Option<TravelChoice>,
    /// Why an agent needs the keys in a file stored with keys in it, one
    /// line (OF-560). With a grant over them the agent reads the stored
    /// bytes, and the read's receipt keeps this; otherwise the owner is
    /// asked, and the keys read masked. Absent, they read masked.
    #[serde(default)]
    pub why: Option<String>,
}

/// Exactly one source: a task, ask, code-mode run or skill row, or an agent run ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BornFromRequest {
    #[serde(default)]
    pub task_ref: Option<String>,
    #[serde(default)]
    pub ask_ref: Option<String>,
    #[serde(default)]
    pub run_ref: Option<String>,
    #[serde(default)]
    pub skill_ref: Option<String>,
    #[serde(default)]
    pub agent_run: Option<String>,
}

/// One native deck transaction over the artifact's head, held for Keep.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckProposeRequest {
    pub artifact_ref: String,
    /// The transaction in its closed grammar: base, marks, seed and steps,
    /// each step's target the slide part, native shape id and content
    /// fingerprint `vault.artifacts.inspect_deck` reads.
    pub transaction: DeckTransaction,
    pub run_ref: String,
    /// The deck edit context (made_by actor, the thread it answers, renders).
    #[serde(default)]
    pub context: DeckEditContext,
    /// The envelope Keep gives the version, with the task or ask it answers.
    #[serde(default)]
    pub made_by: Option<MadeBy>,
    /// The delta receipt id this rework answers (FIX 11967).
    #[serde(default)]
    pub delta_receipt: Option<String>,
}

/// One native organ result offered to an artifact as its next version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeOutputRequest {
    pub artifact_ref: String,
    pub run_ref: String,
    pub name: String,
    pub media_type: String,
    pub content_base64: String,
    #[serde(default)]
    pub report: serde_json::Value,
    /// The envelope Keep gives the version; absent gives the writer's own.
    #[serde(default)]
    pub made_by: Option<MadeBy>,
    /// Additional rows the caller declares it read. Waiting-proposal readers
    /// must admit each row. This is not authority or a complete read log.
    #[serde(default)]
    pub read_rows: Vec<String>,
    /// The delta receipt id this rework answers (FIX 11967).
    #[serde(default)]
    pub delta_receipt: Option<String>,
}

/// Keep, Discard or Undo of one proposal by its ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalSettleRequest {
    pub artifact_ref: String,
    pub proposal_ref: String,
    /// The brief the settle rides; an agent's settle needs a standing grant on it.
    #[serde(default)]
    pub brief_ref: Option<String>,
    /// Why a proposal was discarded.
    #[serde(default)]
    pub reason: Option<String>,
}

/// One slide review of an artifact's head: the units to judge, each with
/// the image its renderer made of those exact bytes, and the typed question
/// every unit is asked through the host's decide() ladder. Answered units
/// become comments in one proposal held for Keep or Discard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlideReviewSubmit {
    pub artifact_ref: String,
    /// The run ref the proposal is held under: the consume-once key.
    pub run_ref: String,
    pub units: Vec<SlideReviewUnitInput>,
    /// The typed question every unit is asked: the engine's shared
    /// `DecisionQuestion` (`{id, version, text, class, contract,
    /// accept_type}`), the same shape `vault.graph.ask` takes.
    pub question: DecisionQuestion,
    /// Who the comments are by.
    pub author: PptxAuthor,
    /// The display words, severity words included.
    pub labels: SlideReviewLabels,
    /// `reversible_read` (the default) or `outbound_effect`.
    #[serde(default)]
    pub reversibility: Option<Reversibility>,
    /// Access-checked evidence beside the deck, by ref.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Each unit call's budget; 30 s when absent.
    #[serde(default)]
    pub unit_budget_ms: Option<u64>,
    /// The whole review's deadline from now; five minutes when absent.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// The made_by envelope Keep gives the version.
    #[serde(default)]
    pub made_by: Option<MadeBy>,
    /// The caller's own dial (FIX 9336): a first rung, a ceiling and a band
    /// inside the host's, which it narrows and never widens. Absent, the
    /// host's dial runs.
    #[serde(default)]
    pub resident_dial: Option<DecisionDial>,
    /// The caller's own pacing (FIX 9336), each narrowing the vault's
    /// policy row and never widening it; absent, the vault's row runs.
    #[serde(default)]
    pub limits: SlideReviewLimitsInput,
}

/// One unit to judge: a slide or a shape (its `PptxCommentTarget`),
/// its rendered image and the renderer that made it. The image is at most
/// one of `review_image`, the PNG or JPEG bytes in base64, or
/// `review_image_ref`, a stored image's view handle (`<asset>@<hash>`) read
/// through the caller's own lane. With neither, a host that has a slide
/// renderer renders the slide from the head itself, under its own renderer
/// name; without one, the unit is read for its structure only and abstains.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlideReviewUnitInput {
    pub target: PptxCommentTarget,
    #[serde(default)]
    pub review_image: Option<String>,
    #[serde(default)]
    pub review_image_ref: Option<String>,
    pub renderer: String,
}

/// A unit the review would not ask as given, and the slide unit it offers
/// instead, if any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SlideUnitRefused {
    pub target: PptxCommentTarget,
    pub reason: SlideUnitRefusalReason,
    pub offer: Option<PptxCommentTarget>,
    pub judged_live: Option<oneiron_store::typed_body::live_pin::LivePin>,
}

/// One typed question over an artifact's units (ARCH-0076 §2): rows of a
/// sheet, paragraphs of a document, or files answered into a workbook
/// column. Each unit is asked through the host's decide() ladder; the
/// answers become one proposal held for Keep or Discard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAskSubmit {
    /// Where the answers land: the workbook for sheet rows and folder
    /// items, the document for paragraphs.
    pub artifact_ref: String,
    /// The run ref the proposal is held under: the consume-once key.
    pub run_ref: String,
    /// The typed question every unit is asked: the engine's shared
    /// `DecisionQuestion` (`{id, version, text, class, contract,
    /// accept_type}`), the same shape `vault.graph.ask` takes.
    pub question: DecisionQuestion,
    pub units: ArtifactAskUnits,
    /// `reversible_read` (the default) or `outbound_effect`.
    #[serde(default)]
    pub reversibility: Option<Reversibility>,
    /// Access-checked evidence beside the artifact, by ref.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Each unit call's budget; 30 s when absent.
    #[serde(default)]
    pub unit_budget_ms: Option<u64>,
    /// The whole ask's deadline from now; five minutes when absent.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// The made_by envelope Keep gives the version.
    #[serde(default)]
    pub made_by: Option<MadeBy>,
}

/// The units one ask covers, and where each answer lands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactAskUnits {
    /// Each row of `rows` (an A1 range on `sheet`) is one unit, read across
    /// the range's columns; its answer fills column `answer_column`
    /// (1-based) of that row.
    SheetRows {
        sheet: String,
        rows: String,
        answer_column: u32,
        /// The row naming the read columns.
        #[serde(default)]
        header_row: Option<u32>,
        /// Holder cap on answers; the vault's policy can only narrow it.
        #[serde(default)]
        max_count: Option<u64>,
    },
    /// Each paragraph, by its stable block id, is one unit; its answer
    /// lands as a Word comment quoting it.
    Paragraphs {
        blocks: Vec<String>,
        /// Native story for these local ids, omitted for the document body.
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<oneiron_docedit::docx_body::DocxStoryScope>,
        /// The comments' author name.
        author: String,
        /// The display words, severity words included.
        labels: SlideReviewLabels,
    },
    /// Each file is one unit, read whole at its head; its answer fills
    /// column `answer_column` of its row on `sheet`.
    FolderItems {
        sheet: String,
        answer_column: u32,
        items: Vec<FolderItemInput>,
        /// Holder cap on answers; the vault's policy can only narrow it.
        #[serde(default)]
        max_count: Option<u64>,
    },
}

/// `vault.artifacts.admit`'s input: one artifact ask whose provider output
/// the caller already holds, admitted unit by unit instead of measured by
/// the host's ladder. `decisions` are consumed in the order the ask reads
/// its units (sheet rows in row order, paragraphs in `blocks` order,
/// folder items in `items` order); a unit the ask refuses or that abstains
/// for missing input consumes none. Each decision's receipt must name
/// `ask.question` at its version, the caller as its principal and only
/// the providers that measured it: the engine validates every decision —
/// its provider-bound paired and person readings included — before any
/// proposal is held, so an invalid measurement mints nothing. A missing
/// paired reading stays missing; no zero is fabricated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAdmitSubmit {
    pub ask: ArtifactAskSubmit,
    /// The provider measurements to admit, one per unit the ask decides,
    /// in unit order.
    pub decisions: Vec<TypedDecision>,
}
