//! The artifact family's agent verbs (`vault.artifacts.*`, OF-511): one
//! typed door per contract verb for every transport the SDK table generates
//! (embedded, HTTP facade, MCP, remote, N-API, Python). Each runs as the
//! bound actor; a person's Keep, Discard or Undo is the owner's consent, an
//! agent's rides a standing grant on the brief it names.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::review_request::SlideReviewLimitsInput;
use super::{
    ArtifactKind, ArtifactVersionView, ArtifactView, BornFromArtifact, BornFromSource,
    VersionReconciliation,
};
use super::{DeckProposeRejection, DeckTransaction};
use crate::claim::ClaimReadStatus;
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::pptx::{PptxAuthor, PptxCommentPatch, PptxCommentTarget};
use crate::edit_roundtrip::slides_review::{
    REVIEW_IMAGE, SlideAbstention, SlideJudgment, SlideRenderer, SlideReviewError,
    SlideReviewImage, SlideReviewLabels, SlideReviewRequest, SlideReviewUnit,
    SlideUnitRefusalReason, review_copy_bytes,
};
use crate::edit_roundtrip::{
    ArtifactAsk, DeckEditContext, DeckEditOutcome, EditOp, FolderAsk, FolderItem, ParagraphAsk,
    RangeRef, SheetRowsAsk, UnitAbstention, UnitCall, UnitDecider, UnitRefusal,
};
use crate::edit_settle::{
    KeepUndo, MadeByReader, NativeOutput, OrganWaitView, PendingProposalView, SettleConsent,
    SettledReview,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::lens::RecordRef;
use crate::llm::decision::{
    DecisionBandPolicy, DecisionDial, DecisionQuestion, ResolvedMedia, Reversibility, TypedDecision,
};
use crate::memory::{
    MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult, resolve_image_ref,
};
use crate::provenance::made_by::{MadeBy, MadeByTrigger};
use crate::receipt::ReceiptRecord;
use crate::secret_custody::SecretSight;
use crate::share_travel::{BornWith, TravelChoice, TravelKind};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

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

/// One version's export file, its bytes base64, with the born-with text the
/// sharer chose to send. Its made_by stays home; `vault.artifacts.view` reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactExportFile {
    pub artifact_ref: String,
    pub version: u64,
    pub kind: ArtifactKind,
    pub name: String,
    pub media_type: String,
    pub content_hash: String,
    pub born_with: BornWith,
    pub content_base64: String,
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

/// What a source produced: the artifacts it created, and every version it made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BornFromView {
    pub born: Vec<EntityId>,
    /// `born` as typed record refs (OF-063), each of the kind its row is: a
    /// source's births are any rows it made, not only artifacts.
    pub born_records: Vec<RecordRef>,
    pub versions: Vec<BornFromArtifact>,
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
}

/// A held proposal, or the refusal naming the step and its check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckProposeOutcome {
    pub proposed: Option<PendingProposalView>,
    pub rejected: Option<DeckProposeRejection>,
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

/// What a review did: the proposal held for Keep (none when no unit was
/// answered), each answered unit's judgment and the comment it became, as
/// that proposal's manifest keeps them, the units the ladder left
/// unanswered, and those it refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlideReviewOutcome {
    pub proposed: Option<PendingProposalView>,
    /// Each answered unit's judgment: its decision and receipt, the managed
    /// anchor, the located answer, the comment text and its words.
    pub judgments: Vec<SlideJudgment>,
    /// The comment each answer became, with the asker, the answerer and the
    /// displayed author it keeps apart.
    pub comments: Vec<PptxCommentPatch>,
    /// Each unit the ladder left unanswered, with its decision when one ran.
    pub abstained: Vec<SlideAbstention>,
    pub refused: Vec<SlideUnitRefused>,
}

/// A unit the review would not ask as given, and the slide unit it offers
/// instead, if any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlideUnitRefused {
    pub target: PptxCommentTarget,
    pub reason: SlideUnitRefusalReason,
    pub offer: Option<PptxCommentTarget>,
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

/// One file of a folder ask and the result row its answer fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FolderItemInput {
    pub artifact_ref: String,
    pub row: u32,
}

/// What an ask did: the proposal held for Keep (none when no unit was
/// answered), the units left unanswered with their receipts, and those it
/// refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactAskOutcome {
    pub proposed: Option<PendingProposalView>,
    pub abstained: Vec<UnitAbstention>,
    pub refused: Vec<UnitRefusal>,
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

/// Whether a held organ call was let go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedWait {
    pub released: bool,
}

/// A kept proposal: the version it became, the threads it moved, its
/// receipt and the review it settled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeptProposal {
    pub version: ArtifactVersionView,
    /// The head moved first: the output was retained against it instead.
    pub stranded: bool,
    pub remapped: usize,
    pub drifted: usize,
    pub receipt: ReceiptRecord,
    /// The kept output forked from the version it was made against while
    /// the head was another; that head stays beside it as its own version
    /// (FIX 2700). `None` when it did not fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation: Option<VersionReconciliation>,
    /// The review it settled, typed: each slide and paragraph judgment and
    /// each comment's asker, answerer and selected author (FIX 9337).
    #[serde(default)]
    pub review: SettledReview,
}

/// A discarded proposal's receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscardedProposal {
    pub receipt: ReceiptRecord,
}

/// An undone Keep: the version the undo appended.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UndoneKeep {
    pub undo: KeepUndo,
    pub version: ArtifactVersionView,
    pub reattached: usize,
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

/// The decider an artifact admission runs under: the caller's submitted
/// measurements, taken one per unit the ask decides, in unit order. It
/// measures nothing itself and reads no images; `ArtifactAsk::decide`
/// validates each decision it hands back before anything is held.
struct AdmittedDecider {
    decisions: std::sync::Mutex<std::collections::VecDeque<TypedDecision>>,
}

impl UnitDecider for AdmittedDecider {
    fn reads_images(&self) -> bool {
        false
    }

    fn decide_unit(&self, _call: &UnitCall<'_>) -> crate::Result<TypedDecision> {
        self.decisions
            .lock()
            .map_err(|_| invalid("artifact admission decisions"))?
            .pop_front()
            .ok_or_else(|| invalid("an artifact admission names fewer decisions than units asked"))
    }
}

fn entity(text: &str) -> MemoryResult<EntityId> {
    Ok(EntityId::from_hex(text)?)
}

impl Memory<'_> {
    fn artifact_actor(&self) -> WriteActor {
        self.write_actor()
    }

    fn artifact_moment(&self) -> (TimeRange, u64) {
        let now = self.vault().now_recorded_at();
        (
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
    }

    /// A person's settle is the owner's consent; an agent's rides a standing
    /// grant on the brief it names.
    fn artifact_consent(&self, brief_ref: Option<String>) -> MemoryResult<SettleConsent> {
        if self.actor_class() == EdgeActorClass::Human {
            return Ok(SettleConsent::OwnerConsent { brief_ref });
        }
        let brief_ref = brief_ref
            .ok_or_else(|| invalid("an agent's settle names the brief its grant covers"))?;
        Ok(SettleConsent::StandingGrant { brief_ref })
    }

    /// `vault.artifacts.view`: kind, name, type, head and every version with
    /// its made_by and born-from.
    pub fn artifacts_view(&self, input: &ArtifactRefRequest) -> MemoryResult<Option<ArtifactView>> {
        Ok(self
            .vault()
            .blob_artifact_view(&entity(&input.artifact_ref)?)?)
    }

    /// `vault.artifacts.export`: one version's export file, with the born-with
    /// text the caller chose to send and a share receipt listing it.
    pub fn artifacts_export(
        &self,
        input: &ArtifactExportRequest,
    ) -> MemoryResult<Option<ArtifactExportFile>> {
        let vault = self.vault();
        let Some(file) = self.export_blob_artifact_sighted(
            &entity(&input.artifact_ref)?,
            input.version,
            input.why.as_deref(),
        )?
        else {
            return Ok(None);
        };
        // The owner's export comes back to the owner, a download or a save to
        // their own machine: the owner's own read (OF-222). Any other
        // caller's leaves for another party: it reads nothing of a world kept
        // off an unknown machine, and prompt text only from the sources its
        // own read lane reads (FIX 6054).
        let travel = TravelChoice::or_default(input.travel.as_ref(), TravelKind::Artifact);
        let text = if self.secret_sight()? == SecretSight::Owner {
            vault.born_with_text(&file.artifact_id, Some(&file.made_by))?
        } else {
            self.born_with_text_for_reader(&file.artifact_id, &file.made_by, &travel)?
        };
        let born_with = travel.project(text);
        let content_hash = super::hash_hex(&file.content_hash);
        vault.record_export_travel(
            file.artifact_id.to_hex(),
            file.version,
            content_hash.clone(),
            &self.actor(),
            &born_with,
        )?;
        Ok(Some(ArtifactExportFile {
            artifact_ref: file.artifact_id.to_hex(),
            version: file.version,
            kind: file.kind,
            name: file.name,
            media_type: file.media_type,
            content_hash,
            born_with,
            content_base64: base64::engine::general_purpose::STANDARD.encode(&file.bytes),
        }))
    }

    /// `vault.artifacts.born_from`: what a task, ask, run, skill or agent run produced.
    pub fn artifacts_born_from(&self, input: &BornFromRequest) -> MemoryResult<BornFromView> {
        let source = match (
            input.task_ref.as_deref(),
            input.ask_ref.as_deref(),
            input.run_ref.as_deref(),
            input.skill_ref.as_deref(),
            input.agent_run.as_ref(),
        ) {
            (Some(task), None, None, None, None) => {
                BornFromSource::Trigger(MadeByTrigger::Task(entity(task)?))
            }
            (None, Some(ask), None, None, None) => {
                BornFromSource::Trigger(MadeByTrigger::Ask(entity(ask)?))
            }
            (None, None, Some(run), None, None) => {
                BornFromSource::Trigger(MadeByTrigger::Run(entity(run)?))
            }
            (None, None, None, Some(skill), None) => {
                BornFromSource::Trigger(MadeByTrigger::Skill(entity(skill)?))
            }
            (None, None, None, None, Some(run_ref)) => BornFromSource::AgentRun(run_ref.clone()),
            _ => {
                return Err(invalid(
                    "name exactly one of task_ref, ask_ref, run_ref, skill_ref or agent_run",
                )
                .into());
            }
        };
        let vault = self.vault();
        let born = match &source {
            BornFromSource::Trigger(trigger) => vault.rows_born_from(&trigger.row())?,
            BornFromSource::AgentRun(_) => Vec::new(),
        };
        // Each born row is named by the kind its row is; one whose kind no
        // longer reads is listed in `born` alone.
        let born_records = vault.born_records(&born)?;
        Ok(BornFromView {
            born,
            born_records,
            versions: vault.artifacts_born_from(&source)?,
        })
    }

    /// `vault.artifacts.proposals`: the proposals waiting beside one artifact
    /// that this handle's own lane admits (FIX 9311): the artifact, the
    /// version each was made against, its records covered by the artifact,
    /// and each source its made_by names. A withheld one leaves no trace.
    pub fn artifacts_proposals(
        &self,
        input: &ArtifactRefRequest,
    ) -> MemoryResult<Vec<PendingProposalView>> {
        let artifact = entity(&input.artifact_ref)?;
        let lane = self
            .read_lane(ClaimReadStatus::Recorded)?
            .with_artifact_records_cover(&[artifact]);
        Ok(self.vault().pending_proposals_scoped(&lane, &artifact)?)
    }

    /// `slides` of the artifact's head as `renderer` draws them, each with the
    /// renderer's name, in order, beside the bytes admitted to `renderer` for
    /// the copy the review makes of each (FIX 8244). `None` when the head
    /// cannot be read, the render fails or comes back short, or the machine
    /// cannot hold those copies: those units are read for their structure
    /// only.
    fn render_head_slides(
        &self,
        artifact: &EntityId,
        renderer: &dyn SlideRenderer,
        slides: &[u64],
    ) -> Option<(Vec<(Vec<u8>, String)>, u64)> {
        let rendered = self
            .vault()
            .blob_artifact_head(artifact)
            .and_then(|head| {
                let head = head.ok_or(Error::EntityNotFound)?;
                let (deck, rows) = self
                    .vault()
                    .read_blob_artifact_version_listing(artifact, head.version)?
                    .ok_or(Error::EntityNotFound)?;
                // The head it draws is read for the review (FIX 5455).
                self.produced_from(rows);
                Ok(deck)
            })
            .and_then(|deck| renderer.render(&deck, slides));
        match rendered {
            Ok(images) if images.len() == slides.len() => {
                let copies = review_copy_bytes(&images);
                if let Err(error) = renderer.admit(copies) {
                    tracing::warn!(kind = ?error.kind(), "slide review images not admitted");
                    return None;
                }
                let images = images
                    .into_iter()
                    .map(|image| (image, renderer.name().to_owned()))
                    .collect();
                Some((images, copies))
            }
            Ok(_) => {
                tracing::warn!("the slide renderer returned the wrong number of images");
                None
            }
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "slide review render failed");
                None
            }
        }
    }

    /// `vault.artifacts.review_slides` on an embedded handle, which holds no
    /// decision ladder: a server's host door answers it.
    pub fn artifacts_review_slides(
        &self,
        _input: &SlideReviewSubmit,
    ) -> MemoryResult<SlideReviewOutcome> {
        Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "slide review asks through a server's decision ladder",
            &["Call vault.artifacts.review_slides on a server, where the host's ladder answers."],
        ))
    }

    /// `vault.artifacts.review_slides` through a host's decide() ladder:
    /// reviews the artifact's head as the bound actor and holds the
    /// proposal for Keep or Discard (`vault.artifacts.keep`/`discard`). A
    /// unit that names no image is rendered from the head by `renderer`,
    /// the host's own (local CPU, unmetered); with none, or when the render
    /// fails, it is read for its structure only and abstains, never refused.
    pub fn artifacts_review_slides_through(
        &self,
        input: &SlideReviewSubmit,
        decider: &dyn UnitDecider,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        renderer: Option<&dyn SlideRenderer>,
    ) -> MemoryResult<SlideReviewOutcome> {
        let artifact = entity(&input.artifact_ref)?;
        let question = input.question.clone();
        question.validate()?;
        let reversibility = input.reversibility.unwrap_or(Reversibility::ReversibleRead);
        let made_by = input.made_by.as_ref();
        // A stored image is read, and its pull recorded, through the caller's
        // own lane before any rung is asked.
        let lane = input
            .units
            .iter()
            .any(|unit| unit.review_image_ref.is_some())
            .then(|| self.read_lane(ClaimReadStatus::Recorded))
            .transpose()?;
        let units = input
            .units
            .iter()
            .map(|unit| {
                let target = unit.target.clone();
                let image = match (&unit.review_image, &unit.review_image_ref, &lane) {
                    (Some(encoded), None, _) => Some(SlideReviewImage::Rendered(
                        base64::engine::general_purpose::STANDARD
                            .decode(encoded)
                            .map_err(|_| invalid("a unit's review image is not base64"))?,
                    )),
                    (None, Some(handle), Some(lane)) => Some(SlideReviewImage::Stored(
                        resolve_image_ref(lane, REVIEW_IMAGE, handle, None)?.value,
                    )),
                    (None, None, _) => None,
                    _ => {
                        return Err(invalid(
                            "a slide review unit names at most one image: review_image or review_image_ref",
                        )
                        .into());
                    }
                };
                Ok((target, image, unit.renderer.clone()))
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        drop(lane);
        let unrendered: Vec<u64> = units
            .iter()
            .filter(|(_, image, _)| image.is_none())
            .map(|(target, _, _)| target.slide)
            .collect();
        let (renders, admitted) = match renderer {
            Some(renderer) if !unrendered.is_empty() => {
                self.render_head_slides(&artifact, renderer, &unrendered)
            }
            _ => None,
        }
        .unwrap_or_default();
        let mut renders = renders.into_iter();
        let units: Vec<SlideReviewUnit> = units
            .into_iter()
            .map(|(target, image, renderer)| match image {
                Some(image) => SlideReviewUnit {
                    target,
                    image,
                    renderer,
                },
                // An empty image abstains after the unit's structure is read.
                None => {
                    let (image, renderer) = renders.next().unwrap_or_default();
                    SlideReviewUnit {
                        target,
                        image: SlideReviewImage::Rendered(image),
                        renderer,
                    }
                }
            })
            .collect();
        let evidence = input
            .evidence_refs
            .iter()
            .map(|reference| entity(reference))
            .collect::<MemoryResult<Vec<_>>>()?;
        let actor = self.artifact_actor();
        let (_, at) = self.artifact_moment();
        let started = std::time::Instant::now();
        let request = SlideReviewRequest {
            units: &units,
            question: &question,
            principal: actor.entity_ref(),
            answered_by: actor.entity_ref(),
            author: &input.author,
            dial,
            resident_dial: input.resident_dial,
            // The vault's stored policy row, narrowed by the caller's own.
            limits: input.limits.limits(),
            policy,
            reversibility,
            labels: &input.labels,
            decider,
            evidence: &evidence,
            budget: std::time::Duration::from_millis(input.unit_budget_ms.unwrap_or(30_000)),
            deadline: started
                + std::time::Duration::from_millis(input.deadline_ms.unwrap_or(300_000)),
            run_ref: &input.run_ref,
            // The comment writer stamps epoch milliseconds.
            at: at.saturating_mul(1000),
        };
        let run = self
            .vault()
            .review_blob_artifact_slides(&artifact, &request);
        // The review's copies are gone with it: their room goes back (FIX 8244).
        if let Some(renderer) = renderer {
            renderer.materialized(admitted, 0);
        }
        let run = run.map_err(|error| match error {
            SlideReviewError::Vault(error) => MemoryError::from(error),
            other => MemoryError::from(Error::InvalidConfig(other.to_string())),
        })?;
        // The head version the review read (FIX 5455).
        self.produced_from(run.read_rows.iter().copied());
        // What the review read beside its base, its evidence and each stored
        // image, waits with its proposal for that proposal's readers (FIX 9312).
        let stored = units.iter().filter_map(|unit| match &unit.image {
            SlideReviewImage::Stored(ResolvedMedia::Image { reference, .. }) => {
                Some(reference.evidence.id)
            }
            _ => None,
        });
        let read: Vec<EntityId> = run
            .read_rows
            .iter()
            .chain(&evidence)
            .copied()
            .chain(stored)
            .collect();
        let proposed = match &run.proposal {
            Some(proposal) => Some(self.vault().retain_edit_proposal_with_reads(
                &artifact,
                proposal,
                made_by,
                self.made_by_reader(made_by)?,
                (actor, at),
                &read,
            )?),
            None => None,
        };
        // Each answered unit's judgment and comment, from the manifest the
        // held proposal keeps.
        let (judgments, comments) = run
            .proposal
            .as_ref()
            .map(|proposal| {
                let comments = proposal
                    .manifest
                    .ops
                    .iter()
                    .filter_map(|op| match op {
                        EditOp::PptxComment { patch } => Some(patch.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                (proposal.manifest.slide_judgments.clone(), comments)
            })
            .unwrap_or_default();
        Ok(SlideReviewOutcome {
            proposed,
            judgments,
            comments,
            abstained: run.abstained,
            refused: run
                .refused
                .into_iter()
                .map(|unit| SlideUnitRefused {
                    target: unit.target,
                    reason: unit.reason,
                    offer: unit.offer,
                })
                .collect(),
        })
    }

    /// `vault.artifacts.ask` on an embedded handle, which holds no decision
    /// ladder: a server's host door answers it.
    pub fn artifacts_ask(&self, _input: &ArtifactAskSubmit) -> MemoryResult<ArtifactAskOutcome> {
        Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "an artifact ask asks through a server's decision ladder",
            &["Call vault.artifacts.ask on a server, where the host's ladder answers."],
        ))
    }

    /// `vault.artifacts.ask` through a host's decide(): asks each unit as
    /// the bound actor and holds the answers as one proposal for Keep or
    /// Discard (`vault.artifacts.keep`/`discard`). It lists the rows its
    /// reads picked (FIX 5455): each version it read, the asked artifact's
    /// head and every folder file's.
    pub fn artifacts_ask_through(
        &self,
        input: &ArtifactAskSubmit,
        decider: &dyn UnitDecider,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
    ) -> MemoryResult<ArtifactAskOutcome> {
        let (outcome, read) = self.artifacts_ask_run(input, decider, dial, policy)?;
        self.produced_from(read);
        Ok(outcome)
    }

    /// [`Self::artifacts_ask_through`]'s ask, beside the rows its reads
    /// picked.
    fn artifacts_ask_run(
        &self,
        input: &ArtifactAskSubmit,
        decider: &dyn UnitDecider,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
    ) -> MemoryResult<(ArtifactAskOutcome, Vec<EntityId>)> {
        let artifact = entity(&input.artifact_ref)?;
        let question = input.question.clone();
        question.validate()?;
        let reversibility = input.reversibility.unwrap_or(Reversibility::ReversibleRead);
        let made_by = input.made_by.as_ref();
        let evidence = input
            .evidence_refs
            .iter()
            .map(|reference| entity(reference))
            .collect::<MemoryResult<Vec<_>>>()?;
        // The caller's own lane reads the target and its evidence (FIX 1533).
        let named: Vec<EntityId> = std::iter::once(artifact)
            .chain(evidence.iter().copied())
            .collect();
        self.require_credential_reads(&named)?;
        let actor = self.artifact_actor();
        let (_, at) = self.artifact_moment();
        let started = std::time::Instant::now();
        let ask = ArtifactAsk {
            question: &question,
            principal: actor.entity_ref(),
            dial,
            policy,
            reversibility,
            decider,
            evidence: &evidence,
            budget: std::time::Duration::from_millis(input.unit_budget_ms.unwrap_or(30_000)),
            deadline: started
                + std::time::Duration::from_millis(input.deadline_ms.unwrap_or(300_000)),
            run_ref: &input.run_ref,
        };
        let vault = self.vault();
        let run = match &input.units {
            ArtifactAskUnits::SheetRows {
                sheet,
                rows,
                answer_column,
                header_row,
                max_count,
            } => vault.ask_blob_artifact_sheet_rows(
                &artifact,
                &SheetRowsAsk {
                    ask,
                    sheet,
                    rows: RangeRef::parse(rows)?,
                    answer_col: *answer_column,
                    header_row: *header_row,
                    max_count_override: *max_count,
                    only_rows: None,
                },
            )?,
            ArtifactAskUnits::Paragraphs {
                blocks,
                author,
                labels,
            } => vault.ask_blob_artifact_paragraphs(
                &artifact,
                &ParagraphAsk {
                    ask,
                    blocks,
                    author,
                    labels,
                },
            )?,
            ArtifactAskUnits::FolderItems {
                sheet,
                answer_column,
                items,
                max_count,
            } => {
                let items = items
                    .iter()
                    .map(|item| {
                        Ok(FolderItem {
                            artifact: entity(&item.artifact_ref)?,
                            row: item.row,
                        })
                    })
                    .collect::<MemoryResult<Vec<_>>>()?;
                // A credential reads only the files its lane serves; the rest
                // are refused, never sent to a model.
                let ids: Vec<EntityId> = items.iter().map(|item| item.artifact).collect();
                let readable = self.credential_readable_ids(&ids)?;
                let (asked, unread): (Vec<FolderItem>, Vec<FolderItem>) =
                    items.into_iter().partition(|item| {
                        readable
                            .as_ref()
                            .is_none_or(|readable| readable.contains(&item.artifact))
                    });
                let mut run = if asked.is_empty() {
                    crate::edit_roundtrip::ArtifactAskRun {
                        proposal: None,
                        abstained: Vec::new(),
                        refused: Vec::new(),
                        read_rows: Vec::new(),
                    }
                } else {
                    vault.ask_folder_items_into_sheet(
                        &artifact,
                        &FolderAsk {
                            ask,
                            items: &asked,
                            sheet,
                            answer_col: *answer_column,
                            max_count_override: *max_count,
                            sight: self.secret_sight()?,
                        },
                    )?
                };
                run.refused.extend(unread.iter().map(|item| UnitRefusal {
                    unit: serde_json::json!({
                        "file": item.artifact.to_hex(),
                        "row": item.row,
                    }),
                    reason: "unreadable_file".into(),
                }));
                run
            }
        };
        // What the ask read beside its base and its evidence waits with its
        // proposal for that proposal's readers (FIX 9312).
        let read: Vec<EntityId> = run.read_rows.iter().chain(&evidence).copied().collect();
        let proposed = match &run.proposal {
            Some(proposal) => Some(vault.retain_edit_proposal_with_reads(
                &artifact,
                proposal,
                made_by,
                self.made_by_reader(made_by)?,
                (actor, at),
                &read,
            )?),
            None => None,
        };
        let outcome = ArtifactAskOutcome {
            proposed,
            abstained: run.abstained,
            refused: run.refused,
        };
        Ok((outcome, run.read_rows))
    }

    /// `vault.artifacts.admit` on an embedded handle: a server's host door
    /// answers it, beside `vault.artifacts.ask`.
    pub fn artifacts_admit(
        &self,
        _input: &ArtifactAdmitSubmit,
    ) -> MemoryResult<ArtifactAskOutcome> {
        Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "an artifact admission lands through a server's host door",
            &["Call vault.artifacts.admit on a server."],
        ))
    }

    /// `vault.artifacts.admit` through a server's door: the caller's own
    /// provider measurements, admitted as the bound actor in place of the
    /// host ladder's. Each unit's decision goes through the same
    /// `ArtifactAsk::decide` validation an ask's does — receipt question,
    /// version and principal, contract, probability, providers and their
    /// bound paired/person readings — before the proposal is held, so a
    /// measurement no listed provider took, a duplicate provider, a
    /// reading of the answered question itself, a zero version or an
    /// out-of-range probability is refused and mints no proposal. It lists
    /// the rows its reads picked, as an ask does (FIX 5455, FIX 5814).
    pub fn artifacts_admit_through(
        &self,
        input: &ArtifactAdmitSubmit,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
    ) -> MemoryResult<ArtifactAskOutcome> {
        if input.decisions.is_empty() {
            return Err(invalid("an artifact admission names its decisions").into());
        }
        let decider = AdmittedDecider {
            decisions: std::sync::Mutex::new(input.decisions.iter().cloned().collect()),
        };
        let (outcome, read) = self.artifacts_ask_run(&input.ask, &decider, dial, policy)?;
        self.produced_from(read);
        Ok(outcome)
    }

    /// `vault.artifacts.waits`: the organ calls held beside one artifact
    /// until one of the owner's nodes can run them, each saying why it waits.
    pub fn artifacts_waits(&self, input: &ArtifactRefRequest) -> MemoryResult<Vec<OrganWaitView>> {
        Ok(self.vault().organ_waits(&entity(&input.artifact_ref)?)?)
    }

    /// `vault.artifacts.release_wait`: lets one held organ call go, by its
    /// run ref (`proposal_ref`), under the consent a Discard needs.
    pub fn artifacts_release_wait(
        &self,
        input: &ProposalSettleRequest,
    ) -> MemoryResult<ReleasedWait> {
        self.artifact_consent(input.brief_ref.clone())?;
        let released = self
            .vault()
            .release_organ_wait(&entity(&input.artifact_ref)?, &input.proposal_ref)?;
        Ok(ReleasedWait { released })
    }

    /// `vault.artifacts.propose_deck`: runs one native deck transaction over
    /// the head and holds the proposal for Keep.
    pub fn artifacts_propose_deck(
        &self,
        input: &DeckProposeRequest,
    ) -> MemoryResult<DeckProposeOutcome> {
        let artifact = entity(&input.artifact_ref)?;
        match self.vault().propose_blob_artifact_deck_edit(
            &artifact,
            &input.transaction.canonical(),
            &input.run_ref,
            input.context.clone(),
        )? {
            DeckEditOutcome::Proposed(proposal) => Ok(DeckProposeOutcome {
                proposed: Some(self.vault().retain_edit_proposal(
                    &artifact,
                    &proposal,
                    input.made_by.as_ref(),
                    self.made_by_reader(input.made_by.as_ref())?,
                    self.artifact_actor(),
                    self.vault().now_recorded_at(),
                )?),
                rejected: None,
            }),
            DeckEditOutcome::Rejected(rejection) => Ok(DeckProposeOutcome {
                proposed: None,
                rejected: Some(DeckProposeRejection::from(*rejection)),
            }),
        }
    }

    /// `vault.artifacts.propose_output`: one native organ result, held for Keep.
    pub fn artifacts_propose_output(
        &self,
        input: &NativeOutputRequest,
    ) -> MemoryResult<PendingProposalView> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&input.content_base64)
            .map_err(|_| invalid("content_base64 is not base64"))?;
        let output = NativeOutput {
            run_ref: input.run_ref.clone(),
            name: input.name.clone(),
            media_type: input.media_type.clone(),
            bytes,
            report: input.report.clone(),
            made_by: input.made_by.clone(),
        };
        Ok(self.vault().propose_native_output(
            &entity(&input.artifact_ref)?,
            &output,
            self.made_by_reader(output.made_by.as_ref())?,
            self.artifact_actor(),
            self.vault().now_recorded_at(),
        )?)
    }

    /// The read a named made_by is admitted under as its proposal is
    /// retained (FIX 1229): this handle's own lane, built only when an
    /// envelope is named.
    pub(crate) fn made_by_reader(
        &self,
        made_by: Option<&MadeBy>,
    ) -> MemoryResult<Option<MadeByReader<'_>>> {
        made_by
            .map(|_| {
                self.read_lane(ClaimReadStatus::Recorded)
                    .map(MadeByReader::Lane)
            })
            .transpose()
    }

    /// `vault.artifacts.keep`: settles one waiting proposal into a version.
    pub fn artifacts_keep(&self, input: &ProposalSettleRequest) -> MemoryResult<KeptProposal> {
        let consent = self.artifact_consent(input.brief_ref.clone())?;
        let (occurred, now) = self.artifact_moment();
        let outcome = self.vault().keep_pending_proposal(
            &entity(&input.artifact_ref)?,
            &input.proposal_ref,
            &consent,
            self.artifact_actor(),
            occurred,
            now,
        )?;
        Ok(KeptProposal {
            version: ArtifactVersionView::from(&outcome.version),
            stranded: outcome.stranded_proposal.is_some(),
            remapped: outcome.reanchor.remapped.len(),
            drifted: outcome.reanchor.drifted.len(),
            receipt: outcome.receipt,
            reconciliation: outcome.reconciliation,
            review: outcome.review,
        })
    }

    /// `vault.artifacts.discard`: drops one waiting proposal, once.
    pub fn artifacts_discard(
        &self,
        input: &ProposalSettleRequest,
    ) -> MemoryResult<DiscardedProposal> {
        let consent = self.artifact_consent(input.brief_ref.clone())?;
        let outcome = self.vault().discard_pending_proposal(
            &entity(&input.artifact_ref)?,
            &input.proposal_ref,
            &consent,
            self.artifact_actor(),
            input.reason.as_deref().unwrap_or_default(),
            self.vault().now_recorded_at(),
        )?;
        Ok(DiscardedProposal {
            receipt: outcome.receipt,
        })
    }

    /// `vault.artifacts.undo`: undoes one Keep with a new version.
    pub fn artifacts_undo(&self, input: &ProposalSettleRequest) -> MemoryResult<UndoneKeep> {
        let consent = self.artifact_consent(input.brief_ref.clone())?;
        let (occurred, now) = self.artifact_moment();
        let outcome = self.vault().undo_kept_proposal(
            &entity(&input.artifact_ref)?,
            &input.proposal_ref,
            &consent,
            self.artifact_actor(),
            occurred,
            now,
        )?;
        Ok(UndoneKeep {
            undo: outcome.undo,
            version: ArtifactVersionView::from(&outcome.version),
            reattached: outcome.reanchor.remapped.len(),
        })
    }
}
