//! Coach-owned, per-task archive descriptors. Recipes and model calls are
//! supplied by the host; the engine pins their result, not prompt text.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::workspace_roster::GoalRecord;

use super::{
    ArchiveCell, ArchiveOutputRef, ArchiveQualityMetric, CampaignArchivePin, invalid, nonblank,
};
use crate::autoreason_campaign::CampaignResult;

/// One categorical dimension proposed from this task's goal and samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAxis {
    pub name: String,
    pub bins: Vec<String>,
}

/// Descriptors are output kinds, never optimization axes of a skill or goal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchiveDescriptor {
    Axes {
        axes: Vec<ArchiveAxis>,
    },
    /// Cluster indices deliberately have no generated category names. The
    /// embedding model and centers are fixed along with the campaign axes.
    EmbeddingClusters {
        model_revision: String,
        centers: Vec<Vec<f64>>,
    },
}

impl ArchiveDescriptor {
    pub(super) fn validate(&self) -> CampaignResult<()> {
        match self {
            Self::Axes { axes } => {
                if !(2..=3).contains(&axes.len()) {
                    return invalid("archive axes", "a Coach proposal needs two or three axes");
                }
                let mut names = BTreeSet::new();
                for axis in axes {
                    nonblank(&axis.name, "archive axis name")?;
                    if !names.insert(&axis.name) || axis.bins.len() < 2 {
                        return invalid(
                            "archive axes",
                            "axes must be distinct with at least two bins",
                        );
                    }
                    let mut bins = BTreeSet::new();
                    for bin in &axis.bins {
                        nonblank(bin, "archive axis bin")?;
                        if !bins.insert(bin) {
                            return invalid("archive axes", "duplicate bin");
                        }
                    }
                }
            }
            Self::EmbeddingClusters {
                model_revision,
                centers,
            } => {
                nonblank(model_revision, "archive embedding model revision")?;
                let dimensions = centers.first().map_or(0, Vec::len);
                if centers.is_empty() || dimensions == 0 {
                    return invalid("archive clusters", "nonempty centers are required");
                }
                for (index, center) in centers.iter().enumerate() {
                    if center.len() != dimensions
                        || center.iter().any(|value| !value.is_finite())
                        || centers[..index].contains(center)
                    {
                        return invalid(
                            "archive clusters",
                            "centers must be finite, distinct and aligned",
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_cell(&self, cell: &ArchiveCell) -> CampaignResult<()> {
        let valid = match (self, cell) {
            (Self::Axes { axes }, ArchiveCell::Axes { bins }) => {
                bins.len() == axes.len()
                    && axes
                        .iter()
                        .zip(bins)
                        .all(|(axis, bin)| axis.bins.contains(bin))
            }
            (Self::EmbeddingClusters { centers, .. }, ArchiveCell::Cluster { index }) => {
                *index < centers.len()
            }
            _ => false,
        };
        if !valid {
            return invalid(
                "archive cell",
                "cell does not belong to the pinned descriptor",
            );
        }
        Ok(())
    }

    pub(super) fn nearest_cluster(
        &self,
        model_revision: &str,
        embedding: &[f64],
    ) -> CampaignResult<ArchiveCell> {
        let Self::EmbeddingClusters {
            model_revision: pinned,
            centers,
        } = self
        else {
            return invalid(
                "archive placement",
                "this campaign uses typed categorical placement",
            );
        };
        if pinned != model_revision
            || embedding.len() != centers[0].len()
            || embedding.iter().any(|value| !value.is_finite())
        {
            return invalid(
                "archive embedding",
                "embedding differs from the pinned model or shape",
            );
        }
        let mut best = (0, f64::INFINITY);
        for (index, center) in centers.iter().enumerate() {
            let distance: f64 = embedding
                .iter()
                .zip(center)
                .map(|(a, b)| (a - b).powi(2))
                .sum();
            if !distance.is_finite() {
                return invalid("archive embedding", "cluster distance is not finite");
            }
            if distance < best.1 {
                best = (index, distance);
            }
        }
        Ok(ArchiveCell::Cluster { index: best.0 })
    }
}

/// Inputs to the Coach recipe. Borrowing the goal makes its read-only role explicit.
pub struct ArchiveAxesRequest<'a> {
    pub task: EntityId,
    pub goal_ref: EntityId,
    pub goal: &'a GoalRecord,
    pub sample_outputs: &'a [ArchiveOutputRef],
}

/// The proposal's receipt retains the recipe/model provenance outside this view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAxesProposal {
    pub receipt: EntityId,
    pub descriptor: ArchiveDescriptor,
}

/// A workflow skill run on the Coach's existing scheduler and authority.
/// `None` means it found no useful categorical axes, not a model/authority error.
pub trait CoachArchiveAxesRecipe {
    fn propose_axes(
        &self,
        request: &ArchiveAxesRequest<'_>,
    ) -> CampaignResult<Option<ArchiveAxesProposal>>;

    /// Cluster the same sample outputs on a pinned embedding model when the
    /// categorical recipe cannot separate them. No invented global taxonomy.
    fn embedding_clusters(
        &self,
        request: &ArchiveAxesRequest<'_>,
    ) -> CampaignResult<ArchiveAxesProposal>;
}

/// Runs the Coach recipe and freezes one descriptor for a new campaign.
/// A later proposal creates a different campaign; no method edits this pin.
pub fn propose_campaign_archive(
    campaign_id: &str,
    quality_metric: ArchiveQualityMetric,
    request: &ArchiveAxesRequest<'_>,
    recipe: &dyn CoachArchiveAxesRecipe,
) -> CampaignResult<CampaignArchivePin> {
    nonblank(campaign_id, "archive campaign id")?;
    nonblank(&quality_metric.metric_id, "archive quality metric id")?;
    nonblank(&quality_metric.revision, "archive quality metric revision")?;
    if request.goal.goal.trim().is_empty() || request.sample_outputs.is_empty() {
        return invalid("archive recipe", "a goal and sample outputs are required");
    }
    let mut samples = BTreeSet::new();
    for output in request.sample_outputs {
        output.validate()?;
        if !samples.insert(output) {
            return invalid("archive samples", "duplicate output revision");
        }
    }
    let proposal = if let Some(proposal) = recipe.propose_axes(request)? {
        if !matches!(&proposal.descriptor, ArchiveDescriptor::Axes { .. }) {
            return invalid("archive recipe", "categorical recipe returned clusters");
        }
        proposal
    } else {
        let proposal = recipe.embedding_clusters(request)?;
        if !matches!(
            &proposal.descriptor,
            ArchiveDescriptor::EmbeddingClusters { .. }
        ) {
            return invalid(
                "archive recipe",
                "embedding fallback returned categorical axes",
            );
        }
        proposal
    };
    proposal.descriptor.validate()?;
    let mut samples = request.sample_outputs.to_vec();
    samples.sort();
    let pin = CampaignArchivePin {
        campaign_id: campaign_id.to_owned(),
        task: request.task,
        goal_ref: request.goal_ref,
        goal_digest: super::goal_digest(request.goal)?,
        quality_metric,
        proposal_receipt: proposal.receipt,
        sample_outputs: samples,
        descriptor: proposal.descriptor,
    };
    pin.validate()?;
    Ok(pin)
}
