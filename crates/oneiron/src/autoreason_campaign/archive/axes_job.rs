//! The Coach's output-archive axes job (ARM05 P2). Canon: "For each task, the
//! Coach proposes two or three axes from the goal and sample outputs ...
//! Embedding clusters are the fallback" (ARCH-0053 #output-archive), a
//! workflow recipe the Coach runs (ARCH-0079 #creativity).
//!
//! The campaign's controller queues one request with
//! `vault.research.archive.propose_axes`; the request's premises are checked
//! then as the Coach's record checks them. The host's Coach runs the recipe on
//! its model seat outside any writer and, when the answer is not two or three
//! categorical axes of two or more bins, clusters the samples on the vault's
//! on-device embedder. The engine records the proposal through the axes
//! producer writer, so its receipt is one install and repropose accept.
//! `vault.research.archive.proposal` reads the request's state back.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::producers::{self, ArchiveAxesMethod, ArchiveAxesMint, AxesPremises};
use super::records::{self, attempt};
use super::{
    ArchiveAxesProposal, ArchiveAxis, ArchiveDescriptor, ArchiveOutputRef, ArchiveQualityMetric,
};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::side_table::{self, Named, SideTable};
use crate::store::embedding::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingPayload,
};
use crate::{EntityId, Error, Result, Vault};

const REQUESTS: SideTable<[u8; 16], ArchiveAxesRequestRecord, Named> =
    SideTable::new(&side_table::AUTORESEARCH_ARCHIVE_AXES_REQUEST);

/// What the recipe reads of one sample output's text. Canon sets no number;
/// this is the engine's policy.
const SAMPLE_TEXT_BYTES: usize = 4096;
/// Most clusters the embedding fallback makes. Canon sets no number; this is
/// the engine's policy.
const MAX_CLUSTERS: usize = 8;
/// Assignment rounds the clustering runs at most.
const CLUSTER_ROUNDS: usize = 32;
/// Why a request ended with no descriptor.
const NO_DESCRIPTOR: &str = "the recipe found no two or three categorical axes, and no on-device embedder served the clusters fallback";

/// `vault.research.archive.propose_axes`'s input: a first proposal for a
/// campaign root, or a re-proposal after a bunched archive.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CampaignArchiveProposeAxes {
    /// Axes for `root`'s first archive, from the goal and these samples.
    First {
        root: EntityId,
        task: EntityId,
        project: EntityId,
        goal_ref: EntityId,
        quality_metric: ArchiveQualityMetric,
        sample_outputs: Vec<ArchiveOutputRef>,
    },
    /// Axes for `root`, a new campaign after the bunched archive of `from`,
    /// over the outputs `from` measured, under its task, goal and ruler.
    Reproposal { root: EntityId, from: EntityId },
}

/// One queued axes request: `vault.research.archive.proposal` reads its state.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveAxesQueued {
    pub request: EntityId,
}

/// `vault.research.archive.proposal`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveProposalRequest {
    pub request: EntityId,
}

/// An axes request's state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CampaignArchiveProposalState {
    /// Queued; the Coach has not answered it yet.
    Pending,
    /// The Coach's proposal, recorded by the axes producer: install (or
    /// repropose) takes it as it is.
    Proposed {
        proposal: ArchiveAxesProposal,
        method: ArchiveAxesMethod,
    },
    /// The recipe found no categorical axes, and no on-device embedder served
    /// the fallback. Nothing was recorded.
    #[serde(rename = "none")]
    NoDescriptor { reason: String },
    /// The request's premises no longer held when the Coach answered: a goal
    /// that moved, a sample that no longer serves, a judge off its pin, an
    /// archive installed meanwhile. Nothing was recorded.
    Failed { reason: String },
}

impl CampaignArchiveProposalState {
    /// The state's name, for a log line that quotes no vault content.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Proposed { .. } => "proposed",
            Self::NoDescriptor { .. } => "none",
            Self::Failed { .. } => "failed",
        }
    }
}

/// One sample output as the recipe reads it: its text at its revision,
/// clipped.
#[derive(Debug, Clone)]
pub struct ArchiveAxesSample {
    pub output: ArchiveOutputRef,
    pub text: String,
}

/// What the Coach's recipe reads: the campaign's human goal and the sample
/// outputs at their revisions.
#[derive(Debug, Clone)]
pub struct ArchiveAxesBrief {
    pub goal_ref: EntityId,
    pub goal: String,
    pub samples: Vec<ArchiveAxesSample>,
}

impl ArchiveAxesBrief {
    /// The rows the recipe's model call carries for its egress checks: the
    /// goal claim and each sample.
    pub fn source_rows(&self) -> Vec<EntityId> {
        let mut rows = vec![self.goal_ref];
        rows.extend(self.samples.iter().map(|sample| sample.output.entity));
        rows.sort();
        rows.dedup();
        rows
    }
}

/// The recipe's answer on the Coach's model seat.
#[derive(Debug, Clone)]
pub struct ArchiveAxesReply {
    /// The model's text: one JSON object, `{"axes": [{"name": .., "bins":
    /// [..]}]}`.
    pub text: String,
    /// The model that answered.
    pub model: String,
    /// The recipe wording's revision.
    pub recipe_revision: String,
}

/// What the host lends the Coach's axes job: its model seat and its embedder.
pub trait ArchiveAxesHost {
    /// The recipe's answer to `brief` on the Coach's model seat; `None` with
    /// no seat, or a call the seat refused.
    ///
    /// # Errors
    ///
    /// A fault of the call that should fail the attempt.
    fn recipe(&self, brief: &ArchiveAxesBrief) -> Result<Option<ArchiveAxesReply>>;

    /// The vault's admitted embedder, for the clusters fallback; `None` while
    /// none serves.
    fn embedder(&self) -> Option<Arc<dyn Embedder>>;
}

/// One request: what it is for, and its state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArchiveAxesRequestRecord {
    root: EntityId,
    from: Option<EntityId>,
    task: EntityId,
    project: EntityId,
    goal_ref: EntityId,
    quality_metric: ArchiveQualityMetric,
    sample_outputs: Vec<ArchiveOutputRef>,
    state: CampaignArchiveProposalState,
}

impl ArchiveAxesRequestRecord {
    fn premises(&self) -> AxesPremises<'_> {
        AxesPremises {
            root: self.root,
            from: self.from,
            task: self.task,
            project: self.project,
            goal_ref: self.goal_ref,
            quality_metric: &self.quality_metric,
            sample_outputs: &self.sample_outputs,
        }
    }

    /// The campaign root the request is for.
    pub(crate) fn root(&self) -> EntityId {
        self.root
    }

    /// The entities of the samples the recipe reads.
    pub(crate) fn sample_entities(&self) -> Vec<EntityId> {
        self.sample_outputs
            .iter()
            .map(|output| output.entity)
            .collect()
    }

    pub(crate) fn into_state(self) -> CampaignArchiveProposalState {
        self.state
    }
}

/// A pending request for `input`, its premises checked as the Coach's record
/// will check them. A re-proposal takes its task, goal, ruler and samples
/// (the outputs `from` measured) from `from`'s archive.
pub(crate) fn request_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &CampaignArchiveProposeAxes,
) -> Result<ArchiveAxesRequestRecord> {
    let record = match input {
        CampaignArchiveProposeAxes::First {
            root,
            task,
            project,
            goal_ref,
            quality_metric,
            sample_outputs,
        } => ArchiveAxesRequestRecord {
            root: *root,
            from: None,
            task: *task,
            project: *project,
            goal_ref: *goal_ref,
            quality_metric: quality_metric.clone(),
            sample_outputs: sample_outputs.clone(),
            state: CampaignArchiveProposalState::Pending,
        },
        CampaignArchiveProposeAxes::Reproposal { root, from } => {
            let old = records::read_in_txn(vault, txn, attempt(*from)?)?;
            ArchiveAxesRequestRecord {
                root: *root,
                from: Some(*from),
                task: old.pin.task(),
                project: old.project,
                goal_ref: old.pin.goal_ref(),
                quality_metric: old.pin.quality_metric().clone(),
                sample_outputs: producers::measured_outputs(&old),
                state: CampaignArchiveProposalState::Pending,
            }
        }
    };
    producers::axes_premises_in_txn(vault, txn, &record.premises())?;
    Ok(record)
}

/// Stores `record` under a new request id and queues the Coach's job for it,
/// under the caller's writer. The caller wakes the host after the commit.
pub(crate) fn queue_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &ArchiveAxesRequestRecord,
    now: u64,
) -> Result<EntityId> {
    let request = vault.new_entity_id()?;
    REQUESTS.put(&vault.store, txn, request.as_bytes(), record)?;
    crate::dreamer_runner::maintenance::coach::enqueue_coach_archive_axes_in_txn(
        vault, txn, &request, now,
    )?;
    Ok(request)
}

/// The request `request`.
pub(crate) fn request_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: EntityId,
) -> Result<ArchiveAxesRequestRecord> {
    REQUESTS
        .get(&vault.store, txn, request.as_bytes())?
        .ok_or(Error::EntityNotFound)
}

impl Vault {
    /// Answers the axes request a leased `coach.archive_axes` attempt names:
    /// the recipe on the Coach's model seat, else clusters of the samples on
    /// the on-device embedder, recorded by the axes producer writer under the
    /// Coach's authority. A request already answered is left as it is.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, a request it does
    /// not name, a fault of the host's call or embedder, and storage errors.
    /// A premise that no longer holds is no error: the request records it as
    /// failed.
    pub fn run_coach_archive_axes(
        &self,
        attempt: &DreamerAdmittedAttempt,
        host: &dyn ArchiveAxesHost,
    ) -> Result<CampaignArchiveProposalState> {
        let request = self.coach_archive_axes_target(attempt)?;
        let brief = {
            let txn = self.store.env.read_txn()?;
            let record = request_record_in_txn(self, &txn, request)?;
            if record.state != CampaignArchiveProposalState::Pending {
                return Ok(record.state);
            }
            refusable(brief_in_txn(self, &txn, &record))?
        };
        // Outside any writer: the model call and the embedder.
        let found = match brief {
            Ok(brief) => Ok(descriptor_for(&brief, host)?),
            Err(reason) => Err(reason),
        };
        self.with_write_txn(|txn| {
            let mut record = request_record_in_txn(self, txn, request)?;
            if record.state != CampaignArchiveProposalState::Pending {
                return Ok(record.state);
            }
            record.state = match found {
                Err(reason) => CampaignArchiveProposalState::Failed { reason },
                Ok(None) => CampaignArchiveProposalState::NoDescriptor {
                    reason: NO_DESCRIPTOR.to_owned(),
                },
                Ok(Some((descriptor, method))) => {
                    let mint = ArchiveAxesMint {
                        root: record.root,
                        from: record.from,
                        task: record.task,
                        project: record.project,
                        goal_ref: record.goal_ref,
                        quality_metric: record.quality_metric.clone(),
                        sample_outputs: record.sample_outputs.clone(),
                        descriptor,
                        producer: self.coach_authority_in_txn(txn)?.entity_ref(),
                        method: method.clone(),
                    };
                    match refusable(producers::mint_axes_in_txn(self, txn, mint))? {
                        Ok(proposal) => CampaignArchiveProposalState::Proposed { proposal, method },
                        Err(reason) => CampaignArchiveProposalState::Failed { reason },
                    }
                }
            };
            REQUESTS.put(&self.store, txn, request.as_bytes(), &record)?;
            Ok(record.state)
        })
    }
}

/// Splits a refused premise, which the request records, from a fault, which
/// fails the attempt so the queue runs it again.
fn refusable<T>(result: Result<T>) -> Result<std::result::Result<T, String>> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(error @ (Error::InvalidConfig(_) | Error::EntityNotFound)) => {
            Ok(Err(error.to_string()))
        }
        Err(error) => Err(error),
    }
}

/// The recipe's brief: the request's premises re-checked, the goal, and each
/// sample's text at its revision.
fn brief_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &ArchiveAxesRequestRecord,
) -> Result<ArchiveAxesBrief> {
    let (_, goal) = producers::axes_premises_in_txn(vault, txn, &record.premises())?;
    let mut samples = Vec::with_capacity(record.sample_outputs.len());
    for output in &record.sample_outputs {
        let text = records::output_text_in_txn(vault, txn, output)?.ok_or_else(|| {
            Error::InvalidConfig("a sample output no longer serves at its revision".into())
        })?;
        samples.push(ArchiveAxesSample {
            output: output.clone(),
            text: clip(text, SAMPLE_TEXT_BYTES),
        });
    }
    Ok(ArchiveAxesBrief {
        goal_ref: record.goal_ref,
        goal: goal.goal,
        samples,
    })
}

/// The descriptor for `brief`: the recipe's axes when they are two or three
/// distinct axes of two or more bins, else clusters of the samples on the
/// on-device embedder, else none.
fn descriptor_for(
    brief: &ArchiveAxesBrief,
    host: &dyn ArchiveAxesHost,
) -> Result<Option<(ArchiveDescriptor, ArchiveAxesMethod)>> {
    if let Some(reply) = host.recipe(brief)?
        && let Some(axes) = parse_axes(&reply.text)
    {
        let descriptor = ArchiveDescriptor::Axes { axes };
        if descriptor.validate().is_ok() {
            return Ok(Some((
                descriptor,
                ArchiveAxesMethod::CoachRecipe {
                    recipe_revision: reply.recipe_revision,
                    model: reply.model,
                },
            )));
        }
    }
    let Some(embedder) = host.embedder() else {
        return Ok(None);
    };
    // The samples' words stay on this device, as an off-record room's
    // summaries do: the fallback embeds only on an on-device embedder.
    if embedder.locality() != EmbedderLocality::OnDevice {
        return Ok(None);
    }
    // An embedder refuses a blank row; a blank sample takes no vector.
    let inputs: Vec<PendingEmbeddingInput> = brief
        .samples
        .iter()
        .filter(|sample| !sample.text.trim().is_empty())
        .map(|sample| PendingEmbeddingInput {
            entity_id: sample.output.entity,
            payload: PendingEmbeddingPayload::SummaryText(sample.text.clone()),
            pending_embedding_token: blake3::hash(sample.text.as_bytes()).as_bytes().to_vec(),
        })
        .collect();
    if inputs.is_empty() {
        return Ok(None);
    }
    let vectors = embedder.embed(&inputs)?;
    if vectors.len() != inputs.len()
        || vectors
            .iter()
            .any(|vector| vector.len() != embedder.dimensions())
    {
        return Err(Error::InvariantViolation(
            "an embedder answered the archive samples with other than one vector each",
        ));
    }
    let points: Vec<Vec<f64>> = vectors
        .iter()
        .map(|vector| vector.iter().copied().map(f64::from).collect())
        .collect();
    let descriptor = ArchiveDescriptor::EmbeddingClusters {
        model_revision: embedder.model_id().to_owned(),
        centers: cluster_centers(&points),
    };
    Ok(descriptor
        .validate()
        .is_ok()
        .then_some((descriptor, ArchiveAxesMethod::EmbeddingClusters)))
}

/// The recipe's answer: one JSON object, fenced or not.
#[derive(Deserialize)]
struct RecipeAnswer {
    axes: Vec<ArchiveAxis>,
}

/// The axes in the recipe's answer, or `None` when it holds no such object.
fn parse_axes(text: &str) -> Option<Vec<ArchiveAxis>> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    serde_json::from_str::<RecipeAnswer>(text.get(start..=end)?)
        .ok()
        .map(|answer| answer.axes)
}

/// `text` cut to at most `bytes` bytes, at a character boundary.
fn clip(mut text: String, bytes: usize) -> String {
    if text.len() > bytes {
        let mut end = bytes;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// The index and squared distance of the center nearest `point`; the first
/// such center on a tie, as placement's nearest pinned center takes it.
fn nearest(centers: &[Vec<f64>], point: &[f64]) -> (usize, f64) {
    let mut best = (0, f64::INFINITY);
    for (index, center) in centers.iter().enumerate() {
        let distance: f64 = point.iter().zip(center).map(|(a, b)| (a - b).powi(2)).sum();
        if distance < best.1 {
            best = (index, distance);
        }
    }
    best
}

/// Deterministic k-means over the distinct sample embeddings, in sample
/// order: k is the ceiling of the square root of their count, at least two
/// while two distinct points exist and at most [`MAX_CLUSTERS`]. The seeds
/// are the first point, then each time the point farthest from every seed;
/// assignment rounds run until no point moves. A cluster left empty keeps its
/// center.
fn cluster_centers(points: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let mut distinct: Vec<&[f64]> = Vec::new();
    for point in points {
        if !distinct.contains(&point.as_slice()) {
            distinct.push(point);
        }
    }
    let mut centers = seed_centers(&distinct);
    let mut assignment: Vec<usize> = Vec::new();
    for _ in 0..CLUSTER_ROUNDS {
        let next: Vec<usize> = distinct
            .iter()
            .map(|point| nearest(&centers, point).0)
            .collect();
        if next == assignment {
            break;
        }
        assignment = next;
        for (index, center) in centers.iter_mut().enumerate() {
            move_to_mean(center, &distinct, &assignment, index);
        }
    }
    centers
}

/// The first point, then each time the point farthest from every seed, until
/// there are k seeds.
fn seed_centers(distinct: &[&[f64]]) -> Vec<Vec<f64>> {
    let Some(first) = distinct.first() else {
        return Vec::new();
    };
    let mut k = 1;
    while k * k < distinct.len() {
        k += 1;
    }
    let k = k.clamp(2, MAX_CLUSTERS).min(distinct.len());
    let mut centers = vec![first.to_vec()];
    while centers.len() < k {
        let mut farthest = (0, 0.0);
        for (index, point) in distinct.iter().enumerate() {
            let distance = nearest(&centers, point).1;
            if distance > farthest.1 {
                farthest = (index, distance);
            }
        }
        centers.push(distinct[farthest.0].to_vec());
    }
    centers
}

/// Moves `center` to the mean of the points assigned to cluster `index`; a
/// cluster with none keeps its center.
fn move_to_mean(center: &mut [f64], distinct: &[&[f64]], assignment: &[usize], index: usize) {
    let members: Vec<&[f64]> = distinct
        .iter()
        .zip(assignment)
        .filter(|(_, cluster)| **cluster == index)
        .map(|(point, _)| *point)
        .collect();
    let Ok(count) = u32::try_from(members.len()) else {
        return;
    };
    if count == 0 {
        return;
    }
    for (dimension, value) in center.iter_mut().enumerate() {
        *value = members.iter().map(|point| point[dimension]).sum::<f64>() / f64::from(count);
    }
}
