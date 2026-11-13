//! Engine-minted producer records behind an output archive's receipt ids
//! (FIX ARCHIVE-RECEIPT-UNVERIFIED; RULING ARM05-PRODUCERS, 13 Nov 21:30).
//! Only the engine's producers write them: the Coach's axes recipe or its
//! embedding fallback, the typed placement judgment and the quality score.
//! Install, repropose and record resolve every receipt their caller names to
//! its record here, and refuse one that is missing, of another kind, or bound
//! to another campaign, task, goal revision, ruler, sample set, descriptor,
//! output, cell or score. A caller never supplies its own receipt.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::records::{self, ARCHIVES, ReceiptedRecipe, attempt, campaign_error};
use super::{
    ArchiveAxesProposal, ArchiveAxesRequest, ArchiveCell, ArchiveCellJudgment, ArchiveDescriptor,
    ArchiveOutputRef, ArchiveOutputScore, ArchiveQualityMetric, CampaignArchivePin,
    CampaignArchivePlacement, propose_campaign_archive,
};
use crate::autoreason_campaign::research::{self, ResearchBinding};
use crate::llm::decision::{DecisionAnswer, TypedDecision};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::JudgeRubric;
use crate::workspace_roster::GoalRecord;
use crate::{EntityId, Error, Result, Vault};

const PRODUCERS: SideTable<[u8; 16], ArchiveProducerRecord, Named> =
    SideTable::new(&side_table::AUTORESEARCH_ARCHIVE_PRODUCER);

/// How the Coach reached an axes descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchiveAxesMethod {
    /// The categorical recipe on the Coach's model seat.
    CoachRecipe {
        /// The recipe wording's revision.
        recipe_revision: String,
        /// The model that answered.
        model: String,
    },
    /// Clusters of the samples on the pinned embedder the descriptor names.
    EmbeddingClusters,
}

/// What placed an output in its cell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchivePlacementBasis {
    /// One typed choice per pinned axis, in axis order (ARCH-0076): each
    /// answer is one of that axis's bins.
    Judgment {
        /// The typed decisions, one per axis.
        decisions: Vec<TypedDecision>,
    },
    /// The output's embedding on the pinned embedder. The cell is its nearest
    /// pinned center, with no model judgment.
    Embedding {
        /// The embedder revision the descriptor pins.
        model_revision: String,
        /// The output's embedding.
        embedding: Vec<f64>,
    },
}

/// One axes proposal to record for a campaign root: the request the Coach
/// answered and its answer.
#[derive(Debug, Clone)]
pub struct ArchiveAxesMint {
    /// The campaign root the descriptor is for.
    pub root: EntityId,
    /// The bunched campaign this re-proposal follows; `None` for a first one.
    pub from: Option<EntityId>,
    /// The task the archive is pinned to.
    pub task: EntityId,
    /// The project whose authenticated goal the campaign uses.
    pub project: EntityId,
    /// That goal's current claim.
    pub goal_ref: EntityId,
    /// The ruler: a judge skill at its pinned package revision.
    pub quality_metric: ArchiveQualityMetric,
    /// The sample outputs the recipe read, at their revisions.
    pub sample_outputs: Vec<ArchiveOutputRef>,
    /// The proposed descriptor.
    pub descriptor: ArchiveDescriptor,
    /// The actor that ran the recipe: the Coach.
    pub producer: EntityId,
    /// How the descriptor was reached.
    pub method: ArchiveAxesMethod,
}

/// One producer record, keyed by the receipt id the archive carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ArchiveProducerRecord {
    Axes {
        root: EntityId,
        from: Option<EntityId>,
        task: EntityId,
        goal_ref: EntityId,
        goal_digest: String,
        quality_metric: ArchiveQualityMetric,
        /// Sorted, as the pin keeps them.
        sample_outputs: Vec<ArchiveOutputRef>,
        descriptor: ArchiveDescriptor,
        producer: EntityId,
        method: ArchiveAxesMethod,
    },
    Placement {
        root: EntityId,
        pin_version: String,
        output: ArchiveOutputRef,
        cell: ArchiveCell,
        basis: ArchivePlacementBasis,
        principal: EntityId,
    },
    Score {
        root: EntityId,
        pin_version: String,
        output: ArchiveOutputRef,
        quality: f64,
        quality_metric: ArchiveQualityMetric,
        /// The judge's record version and the BLAKE3 hex of the rubric read.
        rubric_version: String,
        rubric_digest: String,
        decision: TypedDecision,
        principal: EntityId,
    },
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

/// The judge rubric an archive's quality metric pins (RULING
/// ARCHIVE-QUALITY-RULER, 13 Nov 22:47): `metric_id` is a judge SKILL's id and
/// `revision` its stored package's canonical tree hash. A metric naming no
/// such skill at that revision, or a judge that moved off it, is refused.
pub(crate) fn ruler_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    metric: &ArchiveQualityMetric,
) -> Result<JudgeRubric> {
    let refused = || {
        invalid(
            "the quality metric names no judge skill at that package revision; bind a new campaign",
        )
    };
    let skill = EntityId::from_hex(&metric.metric_id).map_err(|_| refused())?;
    crate::skill_optimize::pinned_judge_rubric_in_txn(vault, txn, &skill, &metric.revision)?
        .ok_or_else(refused)
}

/// What one axes proposal is for: the campaign root, the bunched campaign a
/// re-proposal follows, and the task, goal, ruler and samples it reads.
pub(super) struct AxesPremises<'a> {
    pub(super) root: EntityId,
    pub(super) from: Option<EntityId>,
    pub(super) task: EntityId,
    pub(super) project: EntityId,
    pub(super) goal_ref: EntityId,
    pub(super) quality_metric: &'a ArchiveQualityMetric,
    pub(super) sample_outputs: &'a [ArchiveOutputRef],
}

/// The outputs an archive scored, sorted and each once: a re-proposal's
/// samples.
pub(super) fn measured_outputs(record: &records::CampaignArchiveRecord) -> Vec<ArchiveOutputRef> {
    record
        .scores
        .iter()
        .map(|score| score.output.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Checks an axes proposal's premises as install (or repropose) checks them:
/// no archive at the root yet, its binding, the campaign's current goal, a
/// TASK, held output revisions, the ruler and, for a re-proposal, a bunched
/// archive of the same task, goal and ruler over its measured outputs.
/// Returns the root's binding and the goal.
pub(super) fn axes_premises_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    premises: &AxesPremises<'_>,
) -> Result<(ResearchBinding, GoalRecord)> {
    let root = attempt(premises.root)?;
    if ARCHIVES.contains(&vault.store, txn, root.as_bytes())? {
        return Err(invalid(
            "an archive descriptor is immutable; bind a new campaign",
        ));
    }
    let binding = research::binding_in_txn(vault, txn, root)?;
    let goal = records::goal_in_txn(vault, txn, &binding, premises.project, premises.goal_ref)?;
    records::task_in_txn(vault, txn, &premises.task)?;
    for output in premises.sample_outputs {
        records::output_in_txn(vault, txn, output)?;
    }
    ruler_in_txn(vault, txn, premises.quality_metric)?;
    if let Some(from) = premises.from {
        let mut samples = premises.sample_outputs.to_vec();
        samples.sort();
        let old = records::read_in_txn(vault, txn, attempt(from)?)?;
        let bunched = records::rebuild(&old)?.needs_axes_reproposal();
        if from == premises.root
            || !bunched
            || old.project != premises.project
            || old.pin.task() != premises.task
            || old.pin.goal_ref() != premises.goal_ref
            || old.pin.quality_metric() != premises.quality_metric
            || measured_outputs(&old) != samples
        {
            return Err(invalid(
                "a re-proposal follows a bunched archive of the same task, goal and ruler, over its measured outputs",
            ));
        }
    }
    Ok((binding, goal))
}

/// Records the Coach's axes proposal for `mint.root`, after the same checks
/// install (or repropose) runs on it, and returns the proposal install takes.
pub(crate) fn mint_axes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    mint: ArchiveAxesMint,
) -> Result<ArchiveAxesProposal> {
    let (binding, goal) = axes_premises_in_txn(
        vault,
        txn,
        &AxesPremises {
            root: mint.root,
            from: mint.from,
            task: mint.task,
            project: mint.project,
            goal_ref: mint.goal_ref,
            quality_metric: &mint.quality_metric,
            sample_outputs: &mint.sample_outputs,
        },
    )?;
    match (&mint.method, &mint.descriptor) {
        (ArchiveAxesMethod::CoachRecipe { .. }, ArchiveDescriptor::Axes { .. })
        | (ArchiveAxesMethod::EmbeddingClusters, ArchiveDescriptor::EmbeddingClusters { .. }) => {}
        _ => return Err(invalid("the axes method and the descriptor kind differ")),
    }
    let mut samples = mint.sample_outputs.clone();
    samples.sort();
    let proposal = ArchiveAxesProposal {
        receipt: vault.new_entity_id()?,
        descriptor: mint.descriptor.clone(),
    };
    // The proposal function install runs validates the descriptor, the samples
    // and the goal here too, so a recorded proposal is one install accepts.
    propose_campaign_archive(
        &binding.config.campaign_id,
        mint.quality_metric.clone(),
        &ArchiveAxesRequest {
            task: mint.task,
            goal_ref: mint.goal_ref,
            goal: &goal,
            sample_outputs: &mint.sample_outputs,
        },
        &ReceiptedRecipe(proposal.clone()),
    )
    .map_err(campaign_error)?;
    let record = ArchiveProducerRecord::Axes {
        root: mint.root,
        from: mint.from,
        task: mint.task,
        goal_ref: mint.goal_ref,
        goal_digest: super::goal_digest(&goal).map_err(campaign_error)?,
        quality_metric: mint.quality_metric,
        sample_outputs: samples,
        descriptor: mint.descriptor,
        producer: mint.producer,
        method: mint.method,
    };
    PRODUCERS.put(&vault.store, txn, proposal.receipt.as_bytes(), &record)?;
    Ok(proposal)
}

/// The installed pin of `root`, whose goal is still current and whose
/// version is `descriptor_revision`.
pub(super) fn current_pin_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    descriptor_revision: &str,
) -> Result<CampaignArchivePin> {
    let root = attempt(root)?;
    let record = records::read_in_txn(vault, txn, root)?;
    let binding = research::binding_in_txn(vault, txn, root)?;
    let goal = records::goal_in_txn(vault, txn, &binding, record.project, record.pin.goal_ref())?;
    record.pin.check_goal(&goal).map_err(campaign_error)?;
    if record.pin.version().map_err(campaign_error)? != descriptor_revision {
        return Err(invalid(
            "the output names another archive descriptor revision",
        ));
    }
    Ok(record.pin)
}

/// Records one output's placement under `root`'s descriptor revision and
/// returns the placement record takes. A judgment needs one typed choice of
/// a pinned bin per axis, with no human ask; an embedding takes its nearest
/// pinned center.
pub(crate) fn mint_placement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    root: EntityId,
    descriptor_revision: &str,
    output: ArchiveOutputRef,
    basis: ArchivePlacementBasis,
    principal: EntityId,
) -> Result<CampaignArchivePlacement> {
    let pin = current_pin_in_txn(vault, txn, root, descriptor_revision)?;
    records::output_in_txn(vault, txn, &output)?;
    let cell = match (&basis, pin.descriptor()) {
        (ArchivePlacementBasis::Judgment { decisions }, ArchiveDescriptor::Axes { axes }) => {
            if decisions.len() != axes.len() {
                return Err(invalid(
                    "a placement needs one typed choice per pinned axis",
                ));
            }
            let mut bins = Vec::with_capacity(axes.len());
            for (axis, decision) in axes.iter().zip(decisions) {
                match &decision.answer {
                    DecisionAnswer::Choice(bin)
                        if decision.human_ask.is_none() && axis.bins.contains(bin) =>
                    {
                        bins.push(bin.clone());
                    }
                    _ => {
                        return Err(invalid(
                            "each axis needs a typed choice of one of its pinned bins",
                        ));
                    }
                }
            }
            ArchiveCell::Axes { bins }
        }
        (
            ArchivePlacementBasis::Embedding {
                model_revision,
                embedding,
            },
            descriptor,
        ) => descriptor
            .nearest_cluster(model_revision, embedding)
            .map_err(campaign_error)?,
        (ArchivePlacementBasis::Judgment { .. }, _) => {
            return Err(invalid(
                "an embedding-cluster campaign places by its pinned embedder",
            ));
        }
    };
    let receipt = vault.new_entity_id()?;
    let record = ArchiveProducerRecord::Placement {
        root,
        pin_version: descriptor_revision.to_owned(),
        output: output.clone(),
        cell: cell.clone(),
        basis: basis.clone(),
        principal,
    };
    PRODUCERS.put(&vault.store, txn, receipt.as_bytes(), &record)?;
    Ok(match basis {
        ArchivePlacementBasis::Judgment { .. } => CampaignArchivePlacement::Judgment {
            judgment: ArchiveCellJudgment {
                receipt,
                pin_version: descriptor_revision.to_owned(),
                output,
                cell,
            },
        },
        ArchivePlacementBasis::Embedding {
            model_revision,
            embedding,
        } => CampaignArchivePlacement::Embedding {
            output,
            receipt,
            model_revision,
            embedding,
        },
    })
}

/// Records one output's quality score under `root`'s descriptor revision and
/// returns the score record takes. The decision is one typed score in
/// `0..=1` with no human ask, made while the pin's judge still stands at its
/// pinned package revision.
pub(crate) fn mint_score_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    root: EntityId,
    descriptor_revision: &str,
    output: ArchiveOutputRef,
    decision: TypedDecision,
    principal: EntityId,
) -> Result<ArchiveOutputScore> {
    let pin = current_pin_in_txn(vault, txn, root, descriptor_revision)?;
    records::output_in_txn(vault, txn, &output)?;
    let rubric = ruler_in_txn(vault, txn, pin.quality_metric())?;
    let quality = match decision.answer {
        DecisionAnswer::Score(quality)
            if decision.human_ask.is_none()
                && quality.is_finite()
                && (0.0..=1.0).contains(&quality) =>
        {
            quality
        }
        _ => return Err(invalid("a quality score is one typed score in 0..=1")),
    };
    let receipt = vault.new_entity_id()?;
    let record = ArchiveProducerRecord::Score {
        root,
        pin_version: descriptor_revision.to_owned(),
        output: output.clone(),
        quality,
        quality_metric: pin.quality_metric().clone(),
        rubric_version: rubric.version,
        rubric_digest: blake3::Hash::from_bytes(rubric.digest).to_hex().to_string(),
        decision,
        principal,
    };
    PRODUCERS.put(&vault.store, txn, receipt.as_bytes(), &record)?;
    Ok(ArchiveOutputScore {
        receipt,
        pin_version: descriptor_revision.to_owned(),
        output,
        quality,
    })
}

/// How many producer records the engine holds, for a test door.
#[cfg(oneiron_test_support)]
pub(crate) fn producer_record_count(vault: &Vault) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    Ok(PRODUCERS.scan(&vault.store, &txn)?.len())
}

/// Install's and repropose's check: the pin's proposal receipt names the
/// engine's axes record for `root` (following `from` on a re-proposal), over
/// this pin's task, goal revision, ruler, sample set and descriptor.
pub(super) fn check_axes_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    from: Option<EntityId>,
    pin: &CampaignArchivePin,
) -> Result<()> {
    match PRODUCERS.get(&vault.store, txn, pin.proposal_receipt.as_bytes())? {
        Some(ArchiveProducerRecord::Axes {
            root: recorded_root,
            from: recorded_from,
            task,
            goal_ref,
            goal_digest,
            quality_metric,
            sample_outputs,
            descriptor,
            ..
        }) if recorded_root == root
            && recorded_from == from
            && task == pin.task
            && goal_ref == pin.goal_ref
            && goal_digest == pin.goal_digest
            && quality_metric == pin.quality_metric
            && sample_outputs == pin.sample_outputs
            && descriptor == pin.descriptor =>
        {
            Ok(())
        }
        Some(ArchiveProducerRecord::Axes { .. }) => Err(invalid(
            "the proposal receipt records another campaign, task, goal, ruler, sample set or descriptor",
        )),
        Some(_) => Err(invalid("the proposal receipt is not an axes proposal")),
        None => Err(invalid(
            "the proposal names no axes proposal the engine recorded",
        )),
    }
}

/// Record's placement check: the receipt names the engine's placement of
/// this output in this cell under this descriptor revision, by a judgment, or
/// by this exact embedding when `embedding` is given.
pub(super) fn check_placement_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    placement: &ArchiveCellJudgment,
    embedding: Option<(&str, &[f64])>,
) -> Result<()> {
    match PRODUCERS.get(&vault.store, txn, placement.receipt.as_bytes())? {
        Some(ArchiveProducerRecord::Placement {
            root: recorded_root,
            pin_version,
            output,
            cell,
            basis,
            ..
        }) => {
            let basis_matches = match (&basis, embedding) {
                (ArchivePlacementBasis::Judgment { .. }, None) => true,
                (
                    ArchivePlacementBasis::Embedding {
                        model_revision,
                        embedding: recorded,
                    },
                    Some((model, vector)),
                ) => model_revision == model && recorded.as_slice() == vector,
                _ => false,
            };
            if recorded_root != root
                || pin_version != placement.pin_version
                || output != placement.output
                || cell != placement.cell
                || !basis_matches
            {
                return Err(invalid(
                    "the placement receipt records another campaign, descriptor, output, cell or basis",
                ));
            }
            Ok(())
        }
        Some(_) => Err(invalid("the placement receipt is not a placement")),
        None => Err(invalid(
            "the placement names no placement the engine recorded",
        )),
    }
}

/// Record's score check: the receipt names the engine's score of this output
/// under this descriptor revision and the pin's ruler, with this quality.
pub(super) fn check_score_receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    pin: &CampaignArchivePin,
    score: &ArchiveOutputScore,
) -> Result<()> {
    match PRODUCERS.get(&vault.store, txn, score.receipt.as_bytes())? {
        Some(ArchiveProducerRecord::Score {
            root: recorded_root,
            pin_version,
            output,
            quality,
            quality_metric,
            ..
        }) if recorded_root == root
            && pin_version == score.pin_version
            && output == score.output
            && quality.to_bits() == score.quality.to_bits()
            && quality_metric == pin.quality_metric =>
        {
            Ok(())
        }
        Some(ArchiveProducerRecord::Score { .. }) => Err(invalid(
            "the score receipt records another campaign, descriptor, output, quality or ruler",
        )),
        Some(_) => Err(invalid("the score receipt is not a quality score")),
        None => Err(invalid(
            "the score names no quality score the engine recorded",
        )),
    }
}

/// Records the Coach's axes proposal: the engine's axes producer writer (the
/// Coach host job calls it). The proposal it returns is what
/// `vault.research.archive.install` or `.repropose` takes.
///
/// # Errors
///
/// A root with an archive or no binding, a goal other than the campaign's
/// current one, a task that is not a TASK, an output at a revision it never
/// held, a ruler that is no judge skill at its pinned package, a descriptor
/// install would refuse, a re-proposal of an unbunched archive, and storage
/// errors.
pub fn mint_archive_axes(vault: &Vault, mint: ArchiveAxesMint) -> Result<ArchiveAxesProposal> {
    vault.with_write_txn(|txn| mint_axes_in_txn(vault, txn, mint))
}

/// Records one output's placement: the engine's placement producer writer
/// (the judge door calls it). The placement it returns is what
/// `vault.research.archive.record` takes.
///
/// # Errors
///
/// No installed archive, another descriptor revision, a goal that moved, an
/// output at a revision it never held, a judgment that is not one typed
/// choice of a pinned bin per axis, an embedding off the pinned embedder, and
/// storage errors.
pub fn mint_archive_placement(
    vault: &Vault,
    root: EntityId,
    descriptor_revision: &str,
    output: ArchiveOutputRef,
    basis: ArchivePlacementBasis,
    principal: EntityId,
) -> Result<CampaignArchivePlacement> {
    vault.with_write_txn(|txn| {
        mint_placement_in_txn(
            vault,
            txn,
            root,
            descriptor_revision,
            output,
            basis,
            principal,
        )
    })
}

/// Records one output's quality score: the engine's score producer writer
/// (the judge door calls it). The score it returns is what
/// `vault.research.archive.record` takes.
///
/// # Errors
///
/// No installed archive, another descriptor revision, a goal that moved, an
/// output at a revision it never held, a judge that moved off the pinned
/// package, a decision that is not one typed score in `0..=1`, and storage
/// errors.
pub fn mint_archive_score(
    vault: &Vault,
    root: EntityId,
    descriptor_revision: &str,
    output: ArchiveOutputRef,
    decision: TypedDecision,
    principal: EntityId,
) -> Result<ArchiveOutputScore> {
    vault.with_write_txn(|txn| {
        mint_score_in_txn(
            vault,
            txn,
            root,
            descriptor_revision,
            output,
            decision,
            principal,
        )
    })
}
