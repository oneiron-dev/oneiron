//! The artifact family's agent verbs (`vault.artifacts.*`, OF-511): one
//! typed door per contract verb for every transport the SDK table generates
//! (embedded, HTTP facade, MCP, remote, N-API, Python). Each runs as the
//! bound actor; a person's Keep, Discard or Undo is the owner's consent, an
//! agent's rides a standing grant on the brief it names.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{ArtifactKind, ArtifactVersionView, ArtifactView, BornFromArtifact, BornFromSource};
use crate::claim::ClaimReadStatus;
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::pptx::{PptxAuthor, PptxCommentTarget};
use crate::edit_roundtrip::slides_review::{
    REVIEW_IMAGE, SlideRenderer, SlideReviewError, SlideReviewImage, SlideReviewLabels,
    SlideReviewRequest, SlideReviewUnit,
};
use crate::edit_roundtrip::{
    ArtifactAsk, DeckEditContext, EditOutcome, FolderAsk, FolderItem, ParagraphAsk, RangeRef,
    SheetRowsAsk, UnitAbstention, UnitDecider, UnitRefusal,
};
use crate::edit_settle::{
    KeepUndo, NativeOutput, OrganWaitView, PendingProposalView, SettleConsent,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::llm::decision::{
    DecisionBandPolicy, DecisionDial, DecisionQuestion, Reversibility, SlideReviewLimits,
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
    pub versions: Vec<BornFromArtifact>,
}

/// One native deck transaction over the artifact's head, held for Keep.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckProposeRequest {
    pub artifact_ref: String,
    /// The transaction: a JSON object, or its exact canonical text.
    pub transaction: serde_json::Value,
    pub run_ref: String,
    /// The deck edit context (made_by actor, the thread it answers, renders).
    #[serde(default)]
    pub context: serde_json::Value,
    /// The envelope Keep gives the version, with the task or ask it answers.
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}

/// A held proposal, or the refusal naming the step and its check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeckProposeOutcome {
    pub proposed: Option<PendingProposalView>,
    pub rejected: Option<serde_json::Value>,
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
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
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
    /// The typed question (`DecisionQuestion`), as JSON.
    pub question: serde_json::Value,
    /// Who the comments are by (`PptxAuthor`), as JSON.
    pub author: serde_json::Value,
    /// The display words, severity words included (`SlideReviewLabels`), as JSON.
    pub labels: serde_json::Value,
    /// `reversible_read` (the default) or `outbound_effect`.
    #[serde(default)]
    pub reversibility: Option<serde_json::Value>,
    /// Access-checked evidence beside the deck, by ref.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Each unit call's budget; 30 s when absent.
    #[serde(default)]
    pub unit_budget_ms: Option<u64>,
    /// The whole review's deadline from now; five minutes when absent.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// The made_by envelope Keep gives the version, as JSON.
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}

/// One unit to judge: a slide or a shape (`PptxCommentTarget`, as JSON),
/// its rendered image and the renderer that made it. The image is at most
/// one of `review_image`, the PNG or JPEG bytes in base64, or
/// `review_image_ref`, a stored image's view handle (`<asset>@<hash>`) read
/// through the caller's own lane. With neither, a host that has a slide
/// renderer renders the slide from the head itself, under its own renderer
/// name; without one, the unit is read for its structure only and abstains.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlideReviewUnitInput {
    pub target: serde_json::Value,
    #[serde(default)]
    pub review_image: Option<String>,
    #[serde(default)]
    pub review_image_ref: Option<String>,
    pub renderer: String,
}

/// What a review did: the proposal held for Keep (none when no unit was
/// answered), the units the ladder left unanswered, and those it refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlideReviewOutcome {
    pub proposed: Option<PendingProposalView>,
    pub abstained: Vec<serde_json::Value>,
    pub refused: Vec<SlideUnitRefused>,
}

/// A unit the review would not ask as given, and the slide unit it offers
/// instead, if any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlideUnitRefused {
    pub target: serde_json::Value,
    pub reason: String,
    pub offer: Option<serde_json::Value>,
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
    /// The typed question (`DecisionQuestion`), as JSON.
    pub question: serde_json::Value,
    pub units: ArtifactAskUnits,
    /// `reversible_read` (the default) or `outbound_effect`.
    #[serde(default)]
    pub reversibility: Option<serde_json::Value>,
    /// Access-checked evidence beside the artifact, by ref.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Each unit call's budget; 30 s when absent.
    #[serde(default)]
    pub unit_budget_ms: Option<u64>,
    /// The whole ask's deadline from now; five minutes when absent.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// The made_by envelope Keep gives the version, as JSON.
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
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
        /// The display words, severity words included (`SlideReviewLabels`), as JSON.
        labels: serde_json::Value,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactAskOutcome {
    pub proposed: Option<PendingProposalView>,
    pub abstained: Vec<UnitAbstention>,
    pub refused: Vec<UnitRefusal>,
}

/// Whether a held organ call was let go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedWait {
    pub released: bool,
}

/// A kept proposal: the version it became, the threads it moved, its receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeptProposal {
    pub version: ArtifactVersionView,
    /// The head moved first: the output was retained against it instead.
    pub stranded: bool,
    pub remapped: usize,
    pub drifted: usize,
    pub receipt: ReceiptRecord,
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

fn entity(text: &str) -> MemoryResult<EntityId> {
    Ok(EntityId::from_hex(text)?)
}

fn json_field<T: serde::de::DeserializeOwned>(
    value: Option<serde_json::Value>,
    field: &str,
) -> MemoryResult<Option<T>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => {
            Ok(Some(serde_json::from_value(value).map_err(|_| {
                invalid(&format!("{field} is not a valid value"))
            })?))
        }
    }
}

impl Memory<'_> {
    fn artifact_actor(&self) -> WriteActor {
        WriteActor::new(self.actor(), self.actor_class())
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
        // caller's leaves for another party, and reads nothing of a world
        // kept off an unknown machine.
        let text = if self.secret_sight()? == SecretSight::Owner {
            vault.born_with_text(&file.artifact_id, Some(&file.made_by))?
        } else {
            vault.born_with_text_for_another(&file.artifact_id, Some(&file.made_by))?
        };
        let born_with =
            TravelChoice::or_default(input.travel.as_ref(), TravelKind::Artifact).project(text);
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
        let born = match &source {
            BornFromSource::Trigger(trigger) => self.vault().rows_born_from(&trigger.row())?,
            BornFromSource::AgentRun(_) => Vec::new(),
        };
        Ok(BornFromView {
            born,
            versions: self.vault().artifacts_born_from(&source)?,
        })
    }

    /// `vault.artifacts.proposals`: the proposals waiting beside one artifact.
    pub fn artifacts_proposals(
        &self,
        input: &ArtifactRefRequest,
    ) -> MemoryResult<Vec<PendingProposalView>> {
        Ok(self
            .vault()
            .pending_proposals(&entity(&input.artifact_ref)?)?)
    }

    /// `slides` of the artifact's head as `renderer` draws them, each with the
    /// renderer's name, in order. `None` when the head cannot be read or the
    /// render fails or comes back short: those units are read for their
    /// structure only.
    fn render_head_slides(
        &self,
        artifact: &EntityId,
        renderer: &dyn SlideRenderer,
        slides: &[u64],
    ) -> Option<Vec<(Vec<u8>, String)>> {
        let rendered = self
            .vault()
            .blob_artifact_head(artifact)
            .and_then(|head| {
                let head = head.ok_or(Error::EntityNotFound)?;
                self.vault()
                    .read_blob_artifact_version(artifact, head.version)?
                    .ok_or(Error::EntityNotFound)
            })
            .and_then(|deck| renderer.render(&deck, slides));
        match rendered {
            Ok(images) if images.len() == slides.len() => Some(
                images
                    .into_iter()
                    .map(|image| (image, renderer.name().to_owned()))
                    .collect(),
            ),
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
        let required =
            |value: &serde_json::Value, field: &str| -> MemoryResult<serde_json::Value> {
                if value.is_null() {
                    return Err(invalid(&format!("a slide review names its {field}")).into());
                }
                Ok(value.clone())
            };
        let question: DecisionQuestion =
            json_field(Some(required(&input.question, "question")?), "question")?
                .ok_or_else(|| invalid("a slide review names its question"))?;
        let author: PptxAuthor = json_field(Some(required(&input.author, "author")?), "author")?
            .ok_or_else(|| invalid("a slide review names its author"))?;
        let labels: SlideReviewLabels =
            json_field(Some(required(&input.labels, "labels")?), "labels")?
                .ok_or_else(|| invalid("a slide review names its labels"))?;
        let reversibility: Reversibility =
            json_field(input.reversibility.clone(), "reversibility")?
                .unwrap_or(Reversibility::ReversibleRead);
        let made_by: Option<MadeBy> = json_field(input.made_by.clone(), "made_by")?;
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
                let target: PptxCommentTarget = json_field(Some(unit.target.clone()), "target")?
                    .ok_or_else(|| invalid("a slide review unit names its target"))?;
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
        let mut renders = match renderer {
            Some(renderer) if !unrendered.is_empty() => {
                self.render_head_slides(&artifact, renderer, &unrendered)
            }
            _ => None,
        }
        .into_iter()
        .flatten();
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
            author: &author,
            dial,
            resident_dial: None,
            // The vault re-imposes its stored policy's limits.
            limits: SlideReviewLimits::default(),
            policy,
            reversibility,
            labels: &labels,
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
            .review_blob_artifact_slides(&artifact, &request)
            .map_err(|error| match error {
                SlideReviewError::Vault(error) => MemoryError::from(error),
                other => MemoryError::from(Error::InvalidConfig(other.to_string())),
            })?;
        let proposed = match &run.proposal {
            Some(proposal) => Some(self.vault().retain_edit_proposal(
                &artifact,
                proposal,
                made_by.as_ref(),
                actor,
                at,
            )?),
            None => None,
        };
        let target_json = |target: &PptxCommentTarget| {
            serde_json::to_value(target).unwrap_or(serde_json::Value::Null)
        };
        Ok(SlideReviewOutcome {
            proposed,
            abstained: run
                .abstained
                .iter()
                .map(|unit| {
                    serde_json::json!({
                        "target": target_json(&unit.target),
                        "decision": unit.decision,
                    })
                })
                .collect(),
            refused: run
                .refused
                .iter()
                .map(|unit| SlideUnitRefused {
                    target: target_json(&unit.target),
                    reason: format!("{:?}", unit.reason),
                    offer: unit.offer.as_ref().map(target_json),
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
    /// Discard (`vault.artifacts.keep`/`discard`).
    pub fn artifacts_ask_through(
        &self,
        input: &ArtifactAskSubmit,
        decider: &dyn UnitDecider,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
    ) -> MemoryResult<ArtifactAskOutcome> {
        let artifact = entity(&input.artifact_ref)?;
        if input.question.is_null() {
            return Err(invalid("an artifact ask names its question").into());
        }
        let question: DecisionQuestion = json_field(Some(input.question.clone()), "question")?
            .ok_or_else(|| invalid("an artifact ask names its question"))?;
        let reversibility: Reversibility =
            json_field(input.reversibility.clone(), "reversibility")?
                .unwrap_or(Reversibility::ReversibleRead);
        let made_by: Option<MadeBy> = json_field(input.made_by.clone(), "made_by")?;
        let evidence = input
            .evidence_refs
            .iter()
            .map(|reference| entity(reference))
            .collect::<MemoryResult<Vec<_>>>()?;
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
            } => {
                let labels: SlideReviewLabels = json_field(Some(labels.clone()), "labels")?
                    .ok_or_else(|| invalid("a paragraph ask names its labels"))?;
                vault.ask_blob_artifact_paragraphs(
                    &artifact,
                    &ParagraphAsk {
                        ask,
                        blocks,
                        author,
                        labels: &labels,
                    },
                )?
            }
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
        let proposed = match &run.proposal {
            Some(proposal) => Some(vault.retain_edit_proposal(
                &artifact,
                proposal,
                made_by.as_ref(),
                actor,
                at,
            )?),
            None => None,
        };
        Ok(ArtifactAskOutcome {
            proposed,
            abstained: run.abstained,
            refused: run.refused,
        })
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
        let transaction = match &input.transaction {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        let context: DeckEditContext =
            json_field(Some(input.context.clone()), "context")?.unwrap_or_default();
        let made_by: Option<MadeBy> = json_field(input.made_by.clone(), "made_by")?;
        match self.vault().propose_blob_artifact_deck_edit(
            &artifact,
            &transaction,
            &input.run_ref,
            context,
        )? {
            EditOutcome::Proposed(proposal) => Ok(DeckProposeOutcome {
                proposed: Some(self.vault().retain_edit_proposal(
                    &artifact,
                    &proposal,
                    made_by.as_ref(),
                    self.artifact_actor(),
                    self.vault().now_recorded_at(),
                )?),
                rejected: None,
            }),
            EditOutcome::Rejected { inspection, report } => Ok(DeckProposeOutcome {
                proposed: None,
                rejected: Some(serde_json::json!({ "inspection": inspection, "report": report })),
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
            made_by: json_field(input.made_by.clone(), "made_by")?,
        };
        Ok(self.vault().propose_native_output(
            &entity(&input.artifact_ref)?,
            &output,
            self.artifact_actor(),
            self.vault().now_recorded_at(),
        )?)
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
