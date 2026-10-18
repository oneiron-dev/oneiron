//! Retained descriptor and source receipts for the public campaign archive.
//! Winners and coverage are rebuilt, never stored as learning claims.
use serde::{Deserialize, Serialize};

use super::{
    ArchiveAxesProposal, ArchiveAxesRequest, ArchiveCell, ArchiveCellJudge, ArchiveCellJudgment,
    ArchiveDescriptor, ArchiveOutputRef, ArchiveOutputScore, ArchiveQualityMetric,
    CampaignArchivePin, CoachArchiveAxesRecipe, OutputArchive, propose_campaign_archive,
};
use crate::autoreason_campaign::coverage::project_output_coverage;
use crate::autoreason_campaign::research::{self, ResearchBinding};
use crate::autoreason_campaign::{CampaignError, CampaignResult};
use crate::side_table::{self, Named, SideTable};
use crate::workspace_roster::GoalRecord;
use crate::{AttemptId, EntityId, Error, Result, Vault};

const ARCHIVES: SideTable<[u8; 16], CampaignArchiveRecord, Named> =
    SideTable::new(&side_table::AUTORESEARCH_OUTPUT_ARCHIVE);
const REPLAYS: SideTable<([u8; 16], [u8; 16]), ArchiveReplayOutputs, Named> =
    SideTable::new(&side_table::AUTORESEARCH_OUTPUT_REPLAY);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveRecord {
    pub project: EntityId,
    pub pin: CampaignArchivePin,
    pub placements: Vec<ArchiveCellJudgment>,
    pub scores: Vec<ArchiveOutputScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveInstall {
    pub root: EntityId,
    pub task: EntityId,
    pub project: EntityId,
    pub goal_ref: EntityId,
    pub quality_metric: ArchiveQualityMetric,
    pub sample_outputs: Vec<ArchiveOutputRef>,
    /// A receipted Coach recipe result, categorical or embedding fallback.
    pub proposal: ArchiveAxesProposal,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveRequest {
    pub root: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveReproposal {
    pub root: EntityId,
    pub new_root: EntityId,
    pub proposal: ArchiveAxesProposal,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CampaignArchivePlacement {
    Judgment {
        judgment: ArchiveCellJudgment,
    },
    Embedding {
        output: ArchiveOutputRef,
        receipt: EntityId,
        model_revision: String,
        embedding: Vec<f64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveOutput {
    pub root: EntityId,
    pub descriptor_revision: String,
    pub placement: CampaignArchivePlacement,
    pub score: ArchiveOutputScore,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveBest {
    pub cell: ArchiveCell,
    pub output: ArchiveOutputRef,
    pub score: f64,
    pub placement_receipt: EntityId,
    pub scoring_receipt: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveView {
    pub descriptor_revision: String,
    pub pin: CampaignArchivePin,
    pub best: Vec<CampaignArchiveBest>,
    pub needs_axes_reproposal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveCoverage {
    pub root: EntityId,
    pub candidate: EntityId,
    pub incumbent: EntityId,
    pub descriptor_revision: String,
    pub incumbent_outputs: Vec<ArchiveOutputRef>,
    pub candidate_outputs: Vec<ArchiveOutputRef>,
}

/// Admission to the coverage floor only; other promotion gates still apply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignArchiveAdmission {
    pub descriptor_revision: String,
    pub candidate: EntityId,
    pub required_cells: Vec<ArchiveCell>,
    pub covered_cells: Vec<ArchiveCell>,
    pub admitted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ArchiveReplayOutputs {
    pin_version: String,
    outputs: Vec<ArchiveOutputRef>,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

pub(crate) fn attempt(id: EntityId) -> Result<AttemptId> {
    AttemptId::from_bytes(id.as_bytes())
}

fn campaign_error(error: CampaignError) -> Error {
    match error {
        CampaignError::Decision(error) => error,
        other => invalid(&other.to_string()),
    }
}

/// The controller supplies an already receipted recipe result. The same
/// proposal function validates and freezes both descriptor kinds.
struct ReceiptedRecipe(ArchiveAxesProposal);
impl CoachArchiveAxesRecipe for ReceiptedRecipe {
    fn propose_axes(
        &self,
        _: &ArchiveAxesRequest<'_>,
    ) -> CampaignResult<Option<ArchiveAxesProposal>> {
        Ok(matches!(&self.0.descriptor, ArchiveDescriptor::Axes { .. }).then(|| self.0.clone()))
    }
    fn embedding_clusters(
        &self,
        _: &ArchiveAxesRequest<'_>,
    ) -> CampaignResult<ArchiveAxesProposal> {
        Ok(self.0.clone())
    }
}

struct ReceiptedPlacement(ArchiveCellJudgment);
impl ArchiveCellJudge for ReceiptedPlacement {
    fn place(
        &self,
        _: &CampaignArchivePin,
        _: &ArchiveOutputRef,
    ) -> CampaignResult<ArchiveCellJudgment> {
        Ok(self.0.clone())
    }
}

fn goal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &ResearchBinding,
    project: EntityId,
    goal_ref: EntityId,
) -> Result<GoalRecord> {
    research::check_goal_current_in_txn(vault, txn, binding)?;
    let (current, goal) = vault
        .project_intake_goal_in_txn(txn, project)?
        .ok_or(invalid("an archive requires an authenticated project goal"))?;
    if current != goal_ref
        || binding
            .goal
            .as_ref()
            .is_some_and(|pin| pin.project != Some((project, goal_ref)))
    {
        return Err(invalid(
            "the archive must use the campaign's current human goal",
        ));
    }
    let goal_has_coverage = goal.floor_axes.iter().any(|axis| axis.name == "coverage");
    let campaign_has_coverage = binding.config.metric_set.axes.iter().any(|axis| {
        axis.name == "coverage"
            && axis.role == crate::autoreason_campaign::general::MetricRole::Floor
    });
    if goal_has_coverage && !campaign_has_coverage {
        return Err(invalid(
            "the campaign ruler must retain the human goal's coverage floor",
        ));
    }
    Ok(goal)
}

fn entity_type_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, entity: &EntityId) -> Result<u8> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, entity)?.is_live() {
        return Err(Error::EntityNotFound);
    }
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, entity)?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("archive entity header"))?;
    Ok(header.entity_type)
}

fn output_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, output: &ArchiveOutputRef) -> Result<()> {
    if entity_type_in_txn(vault, txn, &output.entity)? == crate::registry::ENTITY_TYPE_SKILL {
        return Err(invalid(
            "the campaign archive holds outputs, never skill variants",
        ));
    }
    Ok(())
}

pub(crate) fn read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
) -> Result<CampaignArchiveRecord> {
    ARCHIVES
        .get(&vault.store, txn, root.as_bytes())?
        .ok_or(invalid("the campaign has no installed output archive"))
}

fn rebuild(record: &CampaignArchiveRecord) -> Result<OutputArchive> {
    OutputArchive::rebuild(record.pin.clone(), &record.placements, &record.scores)
        .map_err(campaign_error)
}

pub(crate) fn view(record: &CampaignArchiveRecord) -> Result<CampaignArchiveView> {
    let archive = rebuild(record)?;
    Ok(CampaignArchiveView {
        descriptor_revision: record.pin.version().map_err(campaign_error)?,
        pin: record.pin.clone(),
        best: archive
            .kept_outputs()
            .map(|entry| CampaignArchiveBest {
                cell: entry.placement.cell.clone(),
                output: entry.score.output.clone(),
                score: entry.score.quality,
                placement_receipt: entry.placement.receipt,
                scoring_receipt: entry.score.receipt,
            })
            .collect(),
        needs_axes_reproposal: archive.needs_axes_reproposal(),
    })
}

pub(crate) fn install_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: CampaignArchiveInstall,
) -> Result<CampaignArchiveView> {
    let root = attempt(input.root)?;
    let binding = research::binding_in_txn(vault, txn, root)?;
    let goal = goal_in_txn(vault, txn, &binding, input.project, input.goal_ref)?;
    if entity_type_in_txn(vault, txn, &input.task)? != crate::registry::ENTITY_TYPE_TASK {
        return Err(invalid("an output archive is pinned to a task"));
    }
    for output in &input.sample_outputs {
        output_in_txn(vault, txn, output)?;
    }
    let pin = propose_campaign_archive(
        &binding.config.campaign_id,
        input.quality_metric,
        &ArchiveAxesRequest {
            task: input.task,
            goal_ref: input.goal_ref,
            goal: &goal,
            sample_outputs: &input.sample_outputs,
        },
        &ReceiptedRecipe(input.proposal),
    )
    .map_err(campaign_error)?;
    install_pin(vault, txn, root, input.project, pin)
}

fn install_pin(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    project: EntityId,
    pin: CampaignArchivePin,
) -> Result<CampaignArchiveView> {
    if ARCHIVES.contains(&vault.store, txn, root.as_bytes())? {
        return Err(invalid(
            "an archive descriptor is immutable; bind a new campaign",
        ));
    }
    let record = CampaignArchiveRecord {
        project,
        pin,
        placements: Vec::new(),
        scores: Vec::new(),
    };
    let answer = view(&record)?;
    ARCHIVES.put(&vault.store, txn, root.as_bytes(), &record)?;
    Ok(answer)
}

pub(crate) fn repropose_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: CampaignArchiveReproposal,
) -> Result<CampaignArchiveView> {
    let old_root = attempt(input.root)?;
    let new_root = attempt(input.new_root)?;
    let old = read_in_txn(vault, txn, old_root)?;
    let old_binding = research::binding_in_txn(vault, txn, old_root)?;
    let goal = goal_in_txn(vault, txn, &old_binding, old.project, old.pin.goal_ref())?;
    let new_binding = research::binding_in_txn(vault, txn, new_root)?;
    goal_in_txn(vault, txn, &new_binding, old.project, old.pin.goal_ref())?;
    let pin = rebuild(&old)?
        .propose_next_campaign(
            &new_binding.config.campaign_id,
            &goal,
            &ReceiptedRecipe(input.proposal),
        )
        .map_err(campaign_error)?;
    install_pin(vault, txn, new_root, old.project, pin)
}

pub(crate) fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: CampaignArchiveOutput,
) -> Result<CampaignArchiveView> {
    let root = attempt(input.root)?;
    let mut record = read_in_txn(vault, txn, root)?;
    let binding = research::binding_in_txn(vault, txn, root)?;
    let goal = goal_in_txn(vault, txn, &binding, record.project, record.pin.goal_ref())?;
    record.pin.check_goal(&goal).map_err(campaign_error)?;
    if record.pin.version().map_err(campaign_error)? != input.descriptor_revision {
        return Err(invalid(
            "the output names another archive descriptor revision",
        ));
    }
    let placement = match input.placement {
        CampaignArchivePlacement::Judgment { judgment } => {
            let output = judgment.output.clone();
            record
                .pin
                .judge_output(&output, &ReceiptedPlacement(judgment))
        }
        CampaignArchivePlacement::Embedding {
            output,
            receipt,
            model_revision,
            embedding,
        } => record
            .pin
            .place_embedding(output, receipt, &model_revision, &embedding),
    }
    .map_err(campaign_error)?;
    if placement.output != input.score.output {
        return Err(invalid(
            "placement and scoring must name the same output revision",
        ));
    }
    output_in_txn(vault, txn, &placement.output)?;
    // Exact retries keep one copy of each original receipt. Rebuild refuses
    // any conflicting placement, score, cell or definition before the write.
    if !record.placements.contains(&placement) {
        record.placements.push(placement);
    }
    if !record.scores.contains(&input.score) {
        record.scores.push(input.score);
    }
    let answer = view(&record)?;
    ARCHIVES.put(&vault.store, txn, root.as_bytes(), &record)?;
    Ok(answer)
}

fn put_replay(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    root: AttemptId,
    node: AttemptId,
    replay: &ArchiveReplayOutputs,
) -> Result<()> {
    let key = (*root.as_bytes(), *node.as_bytes());
    if let Some(previous) = REPLAYS.get(&vault.store, txn, &key)? {
        if previous != *replay {
            return Err(invalid("a replay arm's measured outputs are immutable"));
        }
    } else {
        REPLAYS.put(&vault.store, txn, &key, replay)?;
    }
    Ok(())
}

pub(crate) fn coverage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: CampaignArchiveCoverage,
) -> Result<CampaignArchiveAdmission> {
    let root = attempt(input.root)?;
    let candidate = attempt(input.candidate)?;
    let incumbent = research::research_incumbent_in_txn(vault, txn, root)?;
    if incumbent != attempt(input.incumbent)? || candidate == incumbent {
        return Err(invalid(
            "coverage must compare the candidate with the current incumbent",
        ));
    }
    let nodes = research::nodes_in_txn(vault, txn, root)?;
    if !nodes.contains_key(candidate.as_bytes()) || !nodes.contains_key(incumbent.as_bytes()) {
        return Err(invalid("both replay arms must belong to the campaign"));
    }
    let mut before = input.incumbent_outputs;
    let mut after = input.candidate_outputs;
    // Projection catches duplicate refs before canonical ordering is retained.
    let record = read_in_txn(vault, txn, root)?;
    let answer = project_in_txn(vault, txn, root, input.candidate, &record, &before, &after)?;
    if answer.descriptor_revision != input.descriptor_revision {
        return Err(invalid(
            "coverage names another archive descriptor revision",
        ));
    }
    before.sort();
    after.sort();
    put_replay(
        vault,
        txn,
        root,
        incumbent,
        &ArchiveReplayOutputs {
            pin_version: answer.descriptor_revision.clone(),
            outputs: before,
        },
    )?;
    put_replay(
        vault,
        txn,
        root,
        candidate,
        &ArchiveReplayOutputs {
            pin_version: answer.descriptor_revision.clone(),
            outputs: after,
        },
    )?;
    Ok(answer)
}

fn project_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
    candidate: EntityId,
    record: &CampaignArchiveRecord,
    before: &[ArchiveOutputRef],
    after: &[ArchiveOutputRef],
) -> Result<CampaignArchiveAdmission> {
    let binding = research::binding_in_txn(vault, txn, root)?;
    let goal = goal_in_txn(vault, txn, &binding, record.project, record.pin.goal_ref())?;
    let archive = rebuild(record)?;
    let (required, covered) =
        project_output_coverage(&goal, &archive, before, after).map_err(campaign_error)?;
    Ok(CampaignArchiveAdmission {
        descriptor_revision: record.pin.version().map_err(campaign_error)?,
        candidate,
        admitted: required.is_subset(&covered),
        required_cells: required.into_iter().collect(),
        covered_cells: covered.into_iter().collect(),
    })
}

/// Promotion re-reads the retained source receipts and exact replay arms in
/// its own writing snapshot. The controller cannot substitute a scalar.
pub(crate) fn promotion_coverage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
    incumbent: AttemptId,
    candidate: AttemptId,
    pin: &CampaignArchivePin,
) -> Result<CampaignArchiveAdmission> {
    let record = read_in_txn(vault, txn, root)?;
    if record.pin != *pin {
        return Err(invalid(
            "promotion must reference the installed archive descriptor",
        ));
    }
    let version = pin.version().map_err(campaign_error)?;
    let read = |node: AttemptId| -> Result<ArchiveReplayOutputs> {
        let replay = REPLAYS
            .get(&vault.store, txn, &(*root.as_bytes(), *node.as_bytes()))?
            .ok_or(invalid(
                "coverage admission needs both measured replay arms",
            ))?;
        if replay.pin_version != version {
            return Err(invalid("replay outputs use another descriptor revision"));
        }
        Ok(replay)
    };
    project_in_txn(
        vault,
        txn,
        root,
        EntityId::from_bytes(*candidate.as_bytes())?,
        &record,
        &read(incumbent)?.outputs,
        &read(candidate)?.outputs,
    )
}
