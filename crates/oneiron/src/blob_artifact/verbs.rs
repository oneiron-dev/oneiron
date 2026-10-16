//! The artifact family's agent verbs (`vault.artifacts.*`, OF-511): one
//! typed door per contract verb for every transport the SDK table generates
//! (embedded, HTTP facade, MCP, remote, N-API, Python). Each runs as the
//! bound actor; a person's Keep, Discard or Undo is the owner's consent, an
//! agent's rides a standing grant on the brief it names.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{ArtifactKind, ArtifactVersionView, ArtifactView, BornFromArtifact, BornFromSource};
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::{DeckEditContext, EditOutcome};
use crate::edit_settle::{
    KeepUndo, NativeOutput, OrganWaitView, PendingProposalView, SettleConsent,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult};
use crate::provenance::made_by::{MadeBy, MadeByTrigger};
use crate::receipt::ReceiptRecord;
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
        let Some(file) = vault.export_blob_artifact_as(
            &entity(&input.artifact_ref)?,
            input.version,
            self.secret_sight()?,
        )?
        else {
            return Ok(None);
        };
        let born_with = TravelChoice::or_default(input.travel.as_ref(), TravelKind::Artifact)
            .project(vault.born_with_text(&file.artifact_id, Some(&file.made_by))?);
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
