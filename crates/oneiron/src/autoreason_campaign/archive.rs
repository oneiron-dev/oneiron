//! OF-545: a rebuildable output archive, joined from placement and scoring
//! receipts. It owns no output bodies, learning claims or skill variants.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::workspace_roster::GoalRecord;

use super::{CampaignError, CampaignResult};

mod axes;
pub(crate) mod records;
pub use records::{
    CampaignArchiveAdmission, CampaignArchiveBest, CampaignArchiveCoverage,
    CampaignArchiveInstall, CampaignArchiveOutput, CampaignArchivePlacement,
    CampaignArchiveRecord, CampaignArchiveReproposal, CampaignArchiveRequest,
    CampaignArchiveView,
};
pub use axes::{
    ArchiveAxesProposal, ArchiveAxesRequest, ArchiveAxis, ArchiveDescriptor,
    CoachArchiveAxesRecipe, propose_campaign_archive,
};

/// A specific output revision. References must resolve to immutable content,
/// not a mutable entity's current body.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveOutputRef {
    pub entity: EntityId,
    pub revision: String,
}

impl ArchiveOutputRef {
    pub(super) fn validate(&self) -> CampaignResult<()> {
        nonblank(&self.revision, "archive output revision")
    }
}

/// Coordinates use the axis order in the pinned definition. Cluster cells are
/// deliberately unnamed and cannot mix with categorical cells.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchiveCell {
    Axes { bins: Vec<String> },
    Cluster { index: usize },
}

/// The scoring definition shared by every output in this campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveQualityMetric {
    pub metric_id: String,
    pub revision: String,
}

/// Immutable campaign descriptor. Its content hash binds every receipt to the
/// task, human goal revision, quality ruler, proposal and sample outputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchivePin {
    campaign_id: String,
    task: EntityId,
    goal_ref: EntityId,
    goal_digest: String,
    quality_metric: ArchiveQualityMetric,
    proposal_receipt: EntityId,
    sample_outputs: Vec<ArchiveOutputRef>,
    descriptor: ArchiveDescriptor,
}

impl CampaignArchivePin {
    pub fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    pub fn task(&self) -> EntityId {
        self.task
    }

    pub fn goal_ref(&self) -> EntityId {
        self.goal_ref
    }

    pub fn descriptor(&self) -> &ArchiveDescriptor {
        &self.descriptor
    }

    pub fn quality_metric(&self) -> &ArchiveQualityMetric {
        &self.quality_metric
    }

    pub fn proposal_receipt(&self) -> EntityId {
        self.proposal_receipt
    }

    pub fn sample_outputs(&self) -> &[ArchiveOutputRef] {
        &self.sample_outputs
    }

    /// Revalidated after deserialization, before any placement or projection.
    pub fn validate(&self) -> CampaignResult<()> {
        nonblank(&self.campaign_id, "archive campaign id")?;
        nonblank(&self.quality_metric.metric_id, "archive quality metric id")?;
        nonblank(
            &self.quality_metric.revision,
            "archive quality metric revision",
        )?;
        if self.goal_digest.len() != 64
            || !self.goal_digest.bytes().all(|b| b.is_ascii_hexdigit())
            || self.sample_outputs.is_empty()
        {
            return invalid("archive pin", "goal digest and recipe samples are required");
        }
        let mut outputs = BTreeSet::new();
        for output in &self.sample_outputs {
            output.validate()?;
            if !outputs.insert(output) {
                return invalid("archive pin", "duplicate recipe sample");
            }
        }
        self.descriptor.validate()
    }

    pub fn version(&self) -> CampaignResult<String> {
        self.validate()?;
        digest(self)
    }

    /// Campaign descriptors can only describe this exact, read-only goal.
    pub fn check_goal(&self, goal: &GoalRecord) -> CampaignResult<()> {
        self.validate()?;
        if self.goal_digest != goal_digest(goal)? {
            return invalid(
                "archive goal",
                "human goal revision differs from the campaign pin",
            );
        }
        Ok(())
    }

    /// Routes a categorical placement through the host's typed judgment seam.
    /// The result must echo this pin and the exact output revision.
    pub fn judge_output(
        &self,
        output: &ArchiveOutputRef,
        judge: &dyn ArchiveCellJudge,
    ) -> CampaignResult<ArchiveCellJudgment> {
        self.validate()?;
        output.validate()?;
        if !matches!(&self.descriptor, ArchiveDescriptor::Axes { .. }) {
            return invalid(
                "archive judgment",
                "cluster campaigns require an embedding receipt",
            );
        }
        let judgment = judge.place(self, output)?;
        self.validate_judgment(&judgment)?;
        if &judgment.output != output {
            return invalid("archive judgment", "judge placed another output revision");
        }
        Ok(judgment)
    }

    /// Embedding fallback produces the same typed placement receipt shape.
    /// Ties use the first pinned center, so a rebuild never shuffles cells.
    pub fn place_embedding(
        &self,
        output: ArchiveOutputRef,
        receipt: EntityId,
        model_revision: &str,
        embedding: &[f64],
    ) -> CampaignResult<ArchiveCellJudgment> {
        self.validate()?;
        output.validate()?;
        let cell = self.descriptor.nearest_cluster(model_revision, embedding)?;
        Ok(ArchiveCellJudgment {
            receipt,
            pin_version: self.version()?,
            output,
            cell,
        })
    }

    fn validate_judgment(&self, judgment: &ArchiveCellJudgment) -> CampaignResult<()> {
        judgment.output.validate()?;
        if judgment.pin_version != self.version()? {
            return invalid(
                "archive judgment",
                "placement uses another campaign or definition",
            );
        }
        self.descriptor.validate_cell(&judgment.cell)
    }
}

/// A typed, receipted judgment, not free text from which a cell is guessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCellJudgment {
    pub receipt: EntityId,
    pub pin_version: String,
    pub output: ArchiveOutputRef,
    pub cell: ArchiveCell,
}

pub trait ArchiveCellJudge {
    fn place(
        &self,
        pin: &CampaignArchivePin,
        output: &ArchiveOutputRef,
    ) -> CampaignResult<ArchiveCellJudgment>;
}

/// A score on the pin's quality metric, normalized with higher always better.
/// The receipt remains the source of truth; the archive never writes a twin
/// score into `learning.*` or changes an outcome's original judgment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveOutputScore {
    pub receipt: EntityId,
    pub pin_version: String,
    pub output: ArchiveOutputRef,
    pub quality: f64,
}

/// The two source receipts for one output revision.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveEntry {
    pub placement: ArchiveCellJudgment,
    pub score: ArchiveOutputScore,
}

/// Disposable view. Only the pin and original receipts need to be retained.
/// Keeping losing outputs here also permits capability coverage to be measured
/// independently of which skill currently owns a cell's best score.
#[derive(Debug, Clone, PartialEq)]
pub struct OutputArchive {
    pin: CampaignArchivePin,
    outputs: BTreeMap<ArchiveOutputRef, ArchiveEntry>,
    best: BTreeMap<ArchiveCell, ArchiveOutputRef>,
}

impl OutputArchive {
    /// Joins evidence by immutable output reference. Ambiguous rescoring and
    /// mixed definition versions are refused, not silently averaged together.
    pub fn rebuild(
        pin: CampaignArchivePin,
        placements: &[ArchiveCellJudgment],
        scores: &[ArchiveOutputScore],
    ) -> CampaignResult<Self> {
        pin.validate()?;
        let version = pin.version()?;
        let mut judged = BTreeMap::new();
        for placement in placements {
            pin.validate_judgment(placement)?;
            if let Some(previous) = judged.insert(placement.output.clone(), placement.clone())
                && previous != *placement
            {
                return invalid("archive receipts", "conflicting placements for one output");
            }
        }
        let mut outputs: BTreeMap<ArchiveOutputRef, ArchiveEntry> = BTreeMap::new();
        for score in scores {
            score.output.validate()?;
            if score.pin_version != version
                || !score.quality.is_finite()
                || !(0.0..=1.0).contains(&score.quality)
            {
                return invalid(
                    "archive score",
                    "score must use the pinned ruler and lie in 0..=1",
                );
            }
            let placement = judged
                .get(&score.output)
                .ok_or(CampaignError::ReportMismatch {
                    reason: "scored output has no placement receipt",
                })?;
            let entry = ArchiveEntry {
                placement: placement.clone(),
                score: score.clone(),
            };
            if let Some(previous) = outputs.insert(score.output.clone(), entry.clone())
                && previous != entry
            {
                return invalid("archive receipts", "conflicting scores for one output");
            }
        }
        if judged.len() != outputs.len() {
            return invalid("archive receipts", "placed output has no quality receipt");
        }
        let mut best: BTreeMap<ArchiveCell, ArchiveOutputRef> = BTreeMap::new();
        // BTreeMap's output order breaks quality ties deterministically. A
        // replacement competes only with its own cell, never the global best.
        for (output, entry) in &outputs {
            let incumbent = best.get(&entry.placement.cell);
            if incumbent.is_none_or(|id| entry.score.quality > outputs[id].score.quality) {
                best.insert(entry.placement.cell.clone(), output.clone());
            }
        }
        Ok(Self { pin, outputs, best })
    }

    pub fn pin(&self) -> &CampaignArchivePin {
        &self.pin
    }

    /// One winner per cell, useful as a diverse set of parents next round.
    pub fn kept_outputs(&self) -> impl Iterator<Item = &ArchiveEntry> {
        self.best.values().map(|output| &self.outputs[output])
    }

    pub fn output(&self, output: &ArchiveOutputRef) -> Option<&ArchiveEntry> {
        self.outputs.get(output)
    }

    /// Counts all measured outputs, not just the winners (one per cell).
    pub fn cell_counts(&self) -> BTreeMap<ArchiveCell, usize> {
        let mut counts = BTreeMap::new();
        for entry in self.outputs.values() {
            *counts.entry(entry.placement.cell.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// "Most outputs" means a strict majority, not a configurable score.
    pub fn needs_axes_reproposal(&self) -> bool {
        self.outputs.len() > 1
            && self
                .cell_counts()
                .values()
                .any(|count| *count > self.outputs.len() / 2)
    }

    /// Re-proposal never relabels this campaign's cells or changes its goal.
    /// Samples and the quality ruler are carried into a NEW campaign pin.
    pub fn propose_next_campaign(
        &self,
        campaign_id: &str,
        goal: &GoalRecord,
        recipe: &dyn CoachArchiveAxesRecipe,
    ) -> CampaignResult<CampaignArchivePin> {
        self.pin.check_goal(goal)?;
        if campaign_id == self.pin.campaign_id() || !self.needs_axes_reproposal() {
            return invalid(
                "archive reproposal",
                "requires bunching and a new campaign id",
            );
        }
        let samples: Vec<_> = self.outputs.keys().cloned().collect();
        propose_campaign_archive(
            campaign_id,
            self.pin.quality_metric.clone(),
            &ArchiveAxesRequest {
                task: self.pin.task,
                goal_ref: self.pin.goal_ref,
                goal,
                sample_outputs: &samples,
            },
            recipe,
        )
    }

    /// Cell coverage of a particular replay arm, including outputs that lost
    /// to another arm's better output. Missing evidence never counts as a kind.
    pub fn coverage(&self, outputs: &[ArchiveOutputRef]) -> CampaignResult<BTreeSet<ArchiveCell>> {
        let mut cells = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for output in outputs {
            if !seen.insert(output) {
                return invalid(
                    "archive coverage",
                    "duplicate output revision in replay arm",
                );
            }
            let entry = self
                .outputs
                .get(output)
                .ok_or(CampaignError::ReportMismatch {
                    reason: "coverage output has no joined scoring and placement receipts",
                })?;
            cells.insert(entry.placement.cell.clone());
        }
        Ok(cells)
    }
}

pub(super) fn goal_digest(goal: &GoalRecord) -> CampaignResult<String> {
    digest(goal)
}

fn digest(value: &impl Serialize) -> CampaignResult<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| CampaignError::ReportMismatch {
        reason: "archive pin cannot be serialized",
    })?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

pub(super) fn nonblank(value: &str, field: &'static str) -> CampaignResult<()> {
    if value.trim().is_empty() {
        invalid(field, "must not be blank")
    } else {
        Ok(())
    }
}

pub(super) fn invalid<T>(field: &'static str, reason: &'static str) -> CampaignResult<T> {
    Err(CampaignError::InvalidConfig { field, reason })
}
