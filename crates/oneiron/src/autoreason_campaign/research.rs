//! The autoresearch loop's record over the existing run tree (OF-351).
//!
//! A campaign is "one configured run of the loop", represented as "a run-tree
//! branch plus claims": the root attempt is the campaign's identity and every
//! experiment is an existing attempt under it. No second tree exists. This
//! module records what the workflow did to that tree (bind, fork, measure,
//! weave, prune, select, promote) and reserves its spend on the RSI line. It
//! calls no model itself. A campaign bound with an execution spec lets the
//! Coach host drive the loop through `continuation`: it dispatches the spec's
//! agents and records their answers through these doors. Without one, the
//! workflow skill drives its own record. Selection stays the Coach tick's.
//!
//! - The ruler is bound once. A skill campaign's metric set must be the
//!   skill's authenticated goal axes; only the goal-intake door changes those,
//!   and a moved goal stops promotion rather than re-ruling it.
//! - Selection reads search-split evidence only: confirmed fact hits times the
//!   attribution-check score, less latency/hop cost. Unattributable signal
//!   earns nothing. Held-out and sealed numbers never enter it.
//! - "Surprise picks the next experiment. It never prunes." A prune names a
//!   cause and ends a branch's eligibility; its attempts, claims and outputs
//!   stay as evidence. A buggy node takes debug children instead.
//! - Every weave names the claim it landed through the gate, its common
//!   ancestor and its validation overlap, and is refused until a held-out win
//!   in this campaign turned merge crossover on.
//! - Parents rank by the DGM formula until the engine estimator's information
//!   gain wins a held-out selection benchmark (`estimator`). Each round
//!   receipts every branch's Beta belief either way.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::general::{CampaignConfig, Measurement, MetricRole};
use super::selection::{
    MeasuredBranch, OracleSignal, ParentRanking, SelectionDecision, SelectionPolicy,
    decide_experiment_for, selection_policy_for,
};
use super::{CampaignDatasetRef, CampaignError};
use crate::agent_dispatch::{AgentDispatchTarget, AgentDispatcher};
use crate::entity_id::bytes_to_hex_lower;
use crate::run_tree::{RunTree, RunTreeNode, render_run_tree};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::{EvalSeat, GoalAxisKind, GoalAxisSpec, skill_edit_goal};
use crate::{
    AttemptId, AttemptQueue, ClaimApprovalStatus, ClaimLifecycleStatus, EntityId, Error, Result,
    Vault,
};

mod budget;
mod continuation;
mod estimator;
mod promotion;

pub use budget::{
    ResearchBudgetRead, ResearchReservation, ResearchReservationLine, refund_research_work,
    research_budget, research_reservations, reserve_research_exploration, reserve_research_work,
    settle_research_work,
};
pub use continuation::{
    ResearchContinuation, ResearchContinuationState, ResearchRunning, ResearchSplit, ResearchTask,
    ResearchWork, advance_research_continuations, ensure_research_continuations,
    research_work_pending,
};
pub use estimator::{
    BranchBelief, ENGINE_ESTIMATOR_VERSION, MIN_SELECTION_BENCHMARK_CASES, PriorRung, PriorSeed,
    SelectionBenchmark, SelectionRanking, record_selection_benchmark, selection_benchmark,
};
pub use promotion::{
    CampaignPromotionReceipt, ConfirmationOutcome, ConfirmationReceipt, HeldOutCall,
    PromotionBasis, PromotionDisposition, promote_measured, promotion_basis, research_incumbent,
    research_promotions, reserve_confirmation,
};

/// One bound campaign, keyed by its root attempt.
const BINDING: SideTable<[u8; 16], ResearchBinding, Named> =
    SideTable::new(&side_table::AUTORESEARCH_BINDING);
/// One experiment node, keyed by root attempt then node attempt.
const NODE: SideTable<([u8; 16], [u8; 16]), ExperimentNode, Named> =
    SideTable::new(&side_table::AUTORESEARCH_NODE);
/// One selection round, keyed by root attempt then round number.
const ROUND: SideTable<([u8; 16], u64), SelectionReceipt, Named> =
    SideTable::new(&side_table::AUTORESEARCH_ROUND);

const MAX_REF_BYTES: usize = 256;
const MAX_REFS: usize = 64;
const MAX_WEAVE_PARENTS: usize = 8;

/// What a campaign improves, and so which ruler it is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchTarget {
    /// A governed skill. Its authenticated goal is the ruler, and a promotion
    /// stands only on the skill gate's own accepted verdict.
    Skill { skill: EntityId },
    /// A workflow configuration (an authoring strategy, a prompt, a knob
    /// set). The campaign's pinned metric set is the ruler.
    Config { subject: String },
}

/// The goal record a skill campaign was bound under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchGoalPin {
    pub goal_id: EntityId,
    pub revision: String,
    /// The joined project and its goal claim, when the goal has one.
    pub project: Option<(EntityId, EntityId)>,
}

/// The sealed cohort a campaign confirms on: OF-578's exposure ledger, not a
/// campaign twin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchConfirmationSeat {
    pub seat: EvalSeat,
    pub cohort: EntityId,
}

/// A candidate configuration the sandbox wrote: a content reference and the
/// digest of its bytes. The loop never reads or runs the config itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRef {
    pub config_ref: String,
    pub config_sha256: String,
}

/// The agents the host runs a campaign's work with (FIX 886). Each is an
/// AGENT_DEF running its own workflow skill; each answers with one JSON
/// object and never writes the campaign record itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchExecution {
    /// Writes one candidate configuration in its own sandbox.
    pub experimenter: EntityId,
    /// The campaign's judge: scores one candidate on one split.
    pub scorer: EntityId,
    /// Runs the sealed confirmation; set exactly when a confirmation seat is.
    pub referee: Option<EntityId>,
    /// RSI units one experiment, one measurement and one confirmation reserve.
    pub experiment_units: u64,
    pub measure_units: u64,
    pub confirm_units: u64,
}

/// The bound ruler and resources of one campaign. Written once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchBinding {
    pub root: AttemptId,
    pub run_id: String,
    pub config: CampaignConfig,
    pub config_sha256: String,
    pub target: ResearchTarget,
    pub goal: Option<ResearchGoalPin>,
    pub holder: Option<String>,
    /// Digest of the trusted selection policy in force when bound.
    pub policy_digest: String,
    pub confirmation: Option<ResearchConfirmationSeat>,
    /// The soft or owner-pinned RSI share the campaign's token work draws on.
    pub share: Option<String>,
    /// The cold-start ladder the root's belief seeds from: user, persona,
    /// then global data. Empty starts uniform.
    pub prior_ladder: Vec<PriorSeed>,
    /// The agents the Coach host drives the loop with; `None` leaves the
    /// workflow driving its own record.
    pub execution: Option<ResearchExecution>,
    pub bound_at: u64,
}

/// The bind request: an existing root attempt plus its configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ResearchBindRequest {
    pub root: AttemptId,
    pub config: CampaignConfig,
    pub target: ResearchTarget,
    pub holder: Option<String>,
    pub confirmation: Option<ResearchConfirmationSeat>,
    pub share: Option<String>,
    /// The incumbent configuration, pinned as the root node.
    pub incumbent: CandidateRef,
    pub prior_ladder: Vec<PriorSeed>,
    pub execution: Option<ResearchExecution>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentKind {
    /// The incumbent the campaign starts from.
    Root,
    /// A child variation of one measured parent.
    Variation,
    /// A repair child of a buggy (invalid) parent.
    Debug,
    /// A crossover of several parents with a common ancestor.
    Weave,
}

/// Search-split evidence for one node: the selection signal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchEvidence {
    /// Scores on the campaign's search split under its pinned metric set.
    pub measurement: Measurement,
    pub confirmed_hits: f64,
    /// The attribution check's score in `[0, 1]`; zero earns no reward.
    pub attribution: f64,
    pub hop_cost: f64,
    /// The estimator's predicted gain from trying this branch next.
    pub expected_gain: f64,
    /// The versioned estimator (DGM floor, Beta belief or information gain)
    /// that produced `expected_gain`.
    pub estimator_version: String,
    /// The reliability, in `[0, 1]`, of the knobs this node's change touched:
    /// its belief's prior mean is pulled halfway toward it.
    pub knob_reliability: Option<f64>,
    pub receipt_refs: Vec<String>,
}

impl SearchEvidence {
    /// Confirmed fact hits times the attribution score, less hop cost.
    #[must_use]
    pub fn reward(&self) -> f64 {
        self.confirmed_hits * self.attribution - self.hop_cost
    }
}

/// Held-out evidence for one node, recorded once and read only by promotion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutEvidence {
    pub measurement: Measurement,
    pub receipt_refs: Vec<String>,
    pub recorded_at: u64,
}

/// A buggy node: kept as evidence, eligible for debug children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidReceipt {
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub at: u64,
}

/// Why a branch stopped being explored. There is deliberately no surprise
/// variant: surprise only picks the next experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PruneReason {
    /// Another measured branch beats it on search reward.
    Dominated { by: AttemptId },
    /// A floor axis regressed on its search measurement.
    FloorRegression { axis: String },
    /// Its expected gain stayed below the policy floor.
    GainBelowFloor,
    /// The owner or the responsible role stopped it.
    Stopped { by: EntityId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PruneReceipt {
    pub reason: PruneReason,
    pub evidence_refs: Vec<String>,
    pub at: u64,
}

/// The lineage receipt of a weave: its parents are on the node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaveReceipt {
    pub common_ancestor: AttemptId,
    pub validation_overlap: f64,
    /// The claim the weave landed as, through the gate.
    pub claim: EntityId,
    /// The claim's approval when the weave was recorded: proposed, unless an
    /// owner grant let the gate approve it.
    pub claim_approval: ClaimApprovalStatus,
    pub at: u64,
}

/// One experiment: an existing attempt annotated with its campaign record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentNode {
    pub attempt: AttemptId,
    pub kind: ExperimentKind,
    /// One parent, every parent of a weave, none for the root.
    pub parents: Vec<AttemptId>,
    pub candidate: CandidateRef,
    pub search: Option<SearchEvidence>,
    pub held_out: Option<HeldOutEvidence>,
    pub invalid: Option<InvalidReceipt>,
    pub weave: Option<WeaveReceipt>,
    pub pruned: Option<PruneReceipt>,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkKind {
    Variation,
    Debug,
}

/// A child attempt the workflow already enqueued under `parent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkInput {
    pub parent: AttemptId,
    pub child: AttemptId,
    pub kind: ForkKind,
    pub candidate: CandidateRef,
}

/// A crossover child the workflow already enqueued under one of `parents`,
/// whose candidate landed as `claim`.
#[derive(Debug, Clone, PartialEq)]
pub struct WeaveInput {
    pub parents: Vec<AttemptId>,
    pub child: AttemptId,
    pub common_ancestor: AttemptId,
    pub validation_overlap: f64,
    pub candidate: CandidateRef,
    pub claim: EntityId,
}

/// What one selection round chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchStep {
    Fork { parent: AttemptId, stagnation: bool },
    PausedBudget,
    StoppedPlateau,
    EscalatePlateau,
    StoppedOracle,
}

/// The evidence one branch contributed to a round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchSnapshot {
    pub attempt: AttemptId,
    pub reward: f64,
    pub expected_gain: f64,
    pub estimator_version: String,
    /// The engine estimator's belief, once the incumbent root is measured.
    pub belief: Option<BranchBelief>,
}

/// The durable receipt of one selection round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionReceipt {
    pub root: AttemptId,
    pub round: u64,
    pub step: ResearchStep,
    pub branches: Vec<BranchSnapshot>,
    pub best_quality: f64,
    pub best_gain: f64,
    pub ranking: SelectionRanking,
    pub policy_digest: String,
    pub budget_available: bool,
    pub oracle_goal_met: bool,
    pub at: u64,
}

pub(super) fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

pub(super) fn campaign_error(error: CampaignError) -> Error {
    match error {
        CampaignError::Decision(error) => error,
        other => Error::InvalidConfig(other.to_string()),
    }
}

pub(super) fn hex(attempt: &AttemptId) -> String {
    bytes_to_hex_lower(attempt.as_bytes())
}

fn sha256_json<T: Serialize>(value: &T, what: &str) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid(what))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(super) fn policy_digest(policy: &SelectionPolicy) -> Result<String> {
    sha256_json(policy, "selection policy cannot be serialized")
}

fn bounded(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_REF_BYTES {
        return Err(invalid(what));
    }
    Ok(())
}

pub(super) fn bounded_refs(refs: &[String], required: bool) -> Result<()> {
    if (required && refs.is_empty())
        || refs.len() > MAX_REFS
        || refs
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > MAX_REF_BYTES)
    {
        return Err(invalid("evidence names one to 64 bounded receipt refs"));
    }
    Ok(())
}

impl CandidateRef {
    fn validate(&self) -> Result<()> {
        bounded(&self.config_ref, "a candidate names a bounded config ref")?;
        if self.config_sha256.len() != 64
            || !self
                .config_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("a candidate config is pinned by its sha256"));
        }
        Ok(())
    }
}

impl ResearchExecution {
    /// Every run reserves units, a referee comes exactly with a confirmation
    /// seat, and each agent is an AGENT_DEF the dispatcher would run.
    fn validate(&self, vault: &Vault, confirms: bool) -> Result<()> {
        if self.experiment_units == 0 || self.measure_units == 0 || self.confirm_units == 0 {
            return Err(invalid("an execution spec reserves units for every run"));
        }
        if self.referee.is_some() != confirms {
            return Err(invalid(
                "an execution spec names a referee exactly when the campaign confirms",
            ));
        }
        let dispatcher = AgentDispatcher::new(vault);
        for agent in [Some(self.experimenter), Some(self.scorer), self.referee]
            .into_iter()
            .flatten()
        {
            match dispatcher.dispatchable_definition(&AgentDispatchTarget::Custom(agent)) {
                Ok(_) => {}
                Err(Error::Artifact(_)) => {
                    return Err(invalid(
                        "an execution agent is not a dispatchable AGENT_DEF",
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

/// The ruler of a skill campaign is the skill's goal: the same axes, each in
/// the same role. A campaign cannot add, drop or re-role one.
fn check_ruler(config: &CampaignConfig, goal: &[GoalAxisSpec]) -> Result<()> {
    let role = |kind: GoalAxisKind| match kind {
        GoalAxisKind::Primary => MetricRole::Primary,
        GoalAxisKind::Floor => MetricRole::Floor,
        GoalAxisKind::Cost => MetricRole::Cost,
    };
    let mut want: Vec<(&str, MetricRole)> = goal
        .iter()
        .map(|axis| (axis.name.as_str(), role(axis.kind)))
        .collect();
    let mut have: Vec<(&str, MetricRole)> = config
        .metric_set
        .axes
        .iter()
        .map(|axis| (axis.name.as_str(), axis.role))
        .collect();
    want.sort_by(|a, b| a.0.cmp(b.0));
    have.sort_by(|a, b| a.0.cmp(b.0));
    if want != have {
        return Err(invalid(
            "a skill campaign's metric set must be the skill's goal axes",
        ));
    }
    Ok(())
}

/// The goal a skill campaign was bound under must still be the goal in force.
pub(super) fn check_goal_current(vault: &Vault, binding: &ResearchBinding) -> Result<()> {
    if let (ResearchTarget::Skill { skill }, Some(pin)) = (&binding.target, &binding.goal) {
        let goal = skill_edit_goal(vault, skill)?;
        if goal.goal_id != pin.goal_id || goal.revision != pin.revision {
            return Err(invalid(
                "the skill's goal moved since the campaign was bound; bind a new campaign",
            ));
        }
    }
    Ok(())
}

/// Bind a campaign to an existing root attempt: validate its configuration,
/// pin its ruler, its trusted selection policy and its confirmation cohort,
/// and record the incumbent as the root node. A root binds once.
/// # Errors
/// An invalid config or candidate, a missing root or run, a skill metric set
/// that is not the skill's goal, a missing selection policy, a missing or
/// retired cohort, an execution spec with a zero unit count, a referee
/// without a confirmation seat (or the reverse) or an agent that is not a
/// dispatchable AGENT_DEF, an already-bound root, or storage errors.
pub fn bind_research(
    vault: &Vault,
    request: ResearchBindRequest,
    at: u64,
) -> Result<ResearchBinding> {
    request.config.validate().map_err(campaign_error)?;
    request.incumbent.validate()?;
    if let Some(execution) = &request.execution {
        execution.validate(vault, request.confirmation.is_some())?;
    }
    if let Some(holder) = &request.holder {
        bounded(holder, "a campaign holder is a bounded id")?;
    }
    if let Some(share) = &request.share {
        bounded(share, "a campaign budget share is a bounded key")?;
    }
    estimator::validate_ladder(&request.prior_ladder)?;
    let record = AttemptQueue::new(vault)
        .get(request.root)?
        .ok_or(invalid("the campaign root attempt is missing"))?;
    let run_id = record
        .run_id
        .ok_or(invalid("the campaign root attempt carries no run"))?;
    let goal = match &request.target {
        ResearchTarget::Skill { skill } => {
            let goal = skill_edit_goal(vault, skill)?;
            check_ruler(&request.config, &goal.axes)?;
            Some(ResearchGoalPin {
                goal_id: goal.goal_id,
                revision: goal.revision,
                project: goal.project,
            })
        }
        ResearchTarget::Config { subject } => {
            bounded(subject, "a config campaign names a bounded subject")?;
            None
        }
    };
    let policy = selection_policy_for(
        vault,
        &request.config.campaign_id,
        request.holder.as_deref(),
    )?;
    if let Some(seat) = &request.confirmation {
        let cohort = vault
            .eval_cohorts(&seat.seat)?
            .into_iter()
            .find(|cohort| cohort.id == seat.cohort)
            .ok_or(invalid("the confirmation cohort is not the seat's"))?;
        if cohort.retired_at.is_some() {
            return Err(invalid("a retired cohort cannot confirm a campaign"));
        }
    }
    let binding = ResearchBinding {
        root: request.root,
        run_id,
        config_sha256: sha256_json(&request.config, "campaign config cannot be serialized")?,
        config: request.config,
        target: request.target,
        goal,
        holder: request.holder,
        policy_digest: policy_digest(&policy)?,
        confirmation: request.confirmation,
        share: request.share,
        prior_ladder: request.prior_ladder,
        execution: request.execution,
        bound_at: at,
    };
    let root = ExperimentNode {
        attempt: request.root,
        kind: ExperimentKind::Root,
        parents: Vec::new(),
        candidate: request.incumbent,
        search: None,
        held_out: None,
        invalid: None,
        weave: None,
        pruned: None,
        recorded_at: at,
    };
    vault.with_write_txn_grouped(|txn| {
        if BINDING.contains(&vault.store, txn, request.root.as_bytes())? {
            return Err(invalid(
                "a campaign root binds once; its ruler is never rewritten",
            ));
        }
        BINDING.put(&vault.store, txn, request.root.as_bytes(), &binding)?;
        NODE.put(
            &vault.store,
            txn,
            &(*request.root.as_bytes(), *request.root.as_bytes()),
            &root,
        )?;
        Ok(binding)
    })
}

/// The binding of a campaign root, if bound.
/// # Errors
/// Storage errors.
pub fn research_binding(vault: &Vault, root: AttemptId) -> Result<Option<ResearchBinding>> {
    let txn = vault.store.env.read_txn()?;
    BINDING.get(&vault.store, &txn, root.as_bytes())
}

pub(super) fn binding(vault: &Vault, root: AttemptId) -> Result<ResearchBinding> {
    research_binding(vault, root)?.ok_or(invalid("no campaign is bound to this root"))
}

pub(super) fn nodes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: AttemptId,
) -> Result<BTreeMap<[u8; 16], ExperimentNode>> {
    Ok(NODE
        .scan_from(&vault.store, txn, root.as_bytes())?
        .into_iter()
        .map(|((_, attempt), node)| (attempt, node))
        .collect())
}

/// Every experiment node of a campaign, in attempt order.
/// # Errors
/// Storage errors.
pub fn research_nodes(vault: &Vault, root: AttemptId) -> Result<Vec<ExperimentNode>> {
    let txn = vault.store.env.read_txn()?;
    Ok(nodes_in_txn(vault, &txn, root)?.into_values().collect())
}

/// Every selection round of a campaign, in round order.
/// # Errors
/// Storage errors.
pub fn research_rounds(vault: &Vault, root: AttemptId) -> Result<Vec<SelectionReceipt>> {
    let txn = vault.store.env.read_txn()?;
    Ok(ROUND
        .scan_from(&vault.store, &txn, root.as_bytes())?
        .into_iter()
        .map(|(_, round)| round)
        .collect())
}

/// Every bound campaign's root, in root order: the scheduler's worklist.
/// # Errors
/// Storage errors.
pub fn bound_research_roots(vault: &Vault) -> Result<Vec<AttemptId>> {
    let txn = vault.store.env.read_txn()?;
    BINDING
        .scan(&vault.store, &txn)?
        .into_iter()
        .map(|(root, _)| AttemptId::from_bytes(&root))
        .collect()
}

/// Whether the scheduler should run [`select_next`] for this campaign now:
/// it has an eligible measured branch, no round stopped it, and its last
/// round either paused on budget or saw a different branch set than the
/// campaign holds now. A campaign with nothing new since its last round
/// waits; the scheduler never re-rules unchanged evidence. Under an
/// execution spec, a round's host continuation that is still open or held
/// holds the next round, and one that ended failed releases it.
/// # Errors
/// Storage errors.
pub fn research_round_due(vault: &Vault, root: AttemptId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    let last = ROUND
        .scan_from(&vault.store, &txn, root.as_bytes())?
        .into_iter()
        .map(|(_, round)| round)
        .last();
    let eligible: BTreeSet<[u8; 16]> = nodes
        .values()
        .filter(|node| {
            node.search.is_some()
                && node.invalid.is_none()
                && !pruned_lineage(&nodes, &node.attempt)
        })
        .map(|node| *node.attempt.as_bytes())
        .collect();
    if eligible.is_empty() {
        return Ok(false);
    }
    if let Some(due) = continuation::round_due_gate(vault, &txn, root, last.as_ref())? {
        return Ok(due);
    }
    Ok(match last {
        None => true,
        Some(round) => match round.step {
            ResearchStep::StoppedPlateau | ResearchStep::StoppedOracle => false,
            ResearchStep::PausedBudget => true,
            ResearchStep::Fork { .. } | ResearchStep::EscalatePlateau => {
                round
                    .branches
                    .iter()
                    .map(|branch| *branch.attempt.as_bytes())
                    .collect::<BTreeSet<_>>()
                    != eligible
            }
        },
    })
}

/// Whether this node or any recorded ancestor was pruned.
pub(super) fn pruned_lineage(
    nodes: &BTreeMap<[u8; 16], ExperimentNode>,
    attempt: &AttemptId,
) -> bool {
    let mut stack = vec![*attempt];
    let mut seen = BTreeSet::new();
    while let Some(next) = stack.pop() {
        if !seen.insert(*next.as_bytes()) {
            continue;
        }
        let Some(node) = nodes.get(next.as_bytes()) else {
            continue;
        };
        if node.pruned.is_some() {
            return true;
        }
        stack.extend(node.parents.iter().copied());
    }
    false
}

fn ancestors_or_self(
    nodes: &BTreeMap<[u8; 16], ExperimentNode>,
    attempt: &AttemptId,
) -> BTreeSet<[u8; 16]> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![*attempt];
    while let Some(next) = stack.pop() {
        if seen.insert(*next.as_bytes())
            && let Some(node) = nodes.get(next.as_bytes())
        {
            stack.extend(node.parents.iter().copied());
        }
    }
    seen
}

/// The child must be an existing attempt of the campaign's run, enqueued
/// under one of `parents` on the run tree.
fn check_child(
    vault: &Vault,
    binding: &ResearchBinding,
    child: AttemptId,
    parents: &[AttemptId],
) -> Result<()> {
    let record = AttemptQueue::new(vault)
        .get(child)?
        .ok_or(invalid("the experiment attempt is missing"))?;
    if record.run_id.as_deref() != Some(binding.run_id.as_str()) {
        return Err(invalid(
            "the experiment attempt is not on the campaign's run",
        ));
    }
    let parent = crate::run_tree::effective_parent(&record);
    if !parent.is_some_and(|parent| parents.contains(&parent)) {
        return Err(invalid(
            "the experiment attempt is not a run-tree child of its parent",
        ));
    }
    Ok(())
}

fn put_new_node(
    vault: &Vault,
    root: AttemptId,
    node: &ExperimentNode,
    parents: &[AttemptId],
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let key = (*root.as_bytes(), *node.attempt.as_bytes());
        if NODE.contains(&vault.store, txn, &key)? {
            return Err(invalid("the experiment is already recorded"));
        }
        // A parent pruned while the child was checked cannot take it.
        let nodes = nodes_in_txn(vault, txn, root)?;
        if parents.iter().any(|parent| pruned_lineage(&nodes, parent)) {
            return Err(invalid("a pruned branch takes no new experiments"));
        }
        NODE.put(&vault.store, txn, &key, node)
    })
}

/// Record a fork: a variation of a live parent, or a debug child of a buggy
/// one. The child attempt was enqueued by the workflow; this registers its
/// candidate and calls no worker.
/// # Errors
/// An unbound campaign, an unknown, pruned or wrong-state parent, a child not
/// under that parent on the run, a recorded child, or storage errors.
pub fn record_fork(
    vault: &Vault,
    root: AttemptId,
    input: ForkInput,
    at: u64,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    input.candidate.validate()?;
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    drop(txn);
    let parent = nodes.get(input.parent.as_bytes()).ok_or(invalid(
        "the fork parent is not an experiment of this campaign",
    ))?;
    if pruned_lineage(&nodes, &input.parent) {
        return Err(invalid("a pruned branch takes no new experiments"));
    }
    match (input.kind, parent.invalid.is_some()) {
        (ForkKind::Variation, true) => {
            return Err(invalid("a buggy node takes debug children, not variations"));
        }
        (ForkKind::Debug, false) => {
            return Err(invalid("only a buggy node takes a debug child"));
        }
        _ => {}
    }
    check_child(vault, &binding, input.child, &[input.parent])?;
    let node = ExperimentNode {
        attempt: input.child,
        kind: match input.kind {
            ForkKind::Variation => ExperimentKind::Variation,
            ForkKind::Debug => ExperimentKind::Debug,
        },
        parents: vec![input.parent],
        candidate: input.candidate,
        search: None,
        held_out: None,
        invalid: None,
        weave: None,
        pruned: None,
        recorded_at: at,
    };
    put_new_node(vault, root, &node, &[input.parent])?;
    Ok(node)
}

/// Record a weave: a crossover child of several measured parents with a
/// common ancestor, landed as a claim through the gate. Refused until a
/// held-out win in this campaign turned merge crossover on.
/// # Errors
/// Crossover not requested or not yet earned, fewer than two or duplicate
/// parents, an unmeasured, buggy or pruned parent, an ancestor common to not
/// every parent, an overlap under the floor, a child not under a parent on
/// the run, a missing, retracted or rejected claim, or storage errors.
pub fn record_weave(
    vault: &Vault,
    root: AttemptId,
    input: WeaveInput,
    at: u64,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    input.candidate.validate()?;
    let crossover = binding.config.knobs.merge_crossover;
    if !crossover.requested {
        return Err(invalid("this campaign did not request merge crossover"));
    }
    if !promotion::crossover_earned(vault, root)? {
        return Err(invalid("merge crossover stays off until a held-out win"));
    }
    let distinct: BTreeSet<[u8; 16]> = input.parents.iter().map(|p| *p.as_bytes()).collect();
    if input.parents.len() < 2
        || input.parents.len() > MAX_WEAVE_PARENTS
        || distinct.len() != input.parents.len()
    {
        return Err(invalid("a weave has two to eight distinct parents"));
    }
    if !input.validation_overlap.is_finite()
        || input.validation_overlap < crossover.min_validation_overlap
        || input.validation_overlap > 1.0
    {
        return Err(invalid(
            "the weave's validation overlap is under the campaign floor",
        ));
    }
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    drop(txn);
    for parent in &input.parents {
        let node = nodes.get(parent.as_bytes()).ok_or(invalid(
            "a weave parent is not an experiment of this campaign",
        ))?;
        if node.search.is_none() || node.invalid.is_some() || pruned_lineage(&nodes, parent) {
            return Err(invalid(
                "a weave parent must be measured, sound and unpruned",
            ));
        }
        if !ancestors_or_self(&nodes, parent).contains(input.common_ancestor.as_bytes()) {
            return Err(invalid(
                "the common ancestor is not an ancestor of every parent",
            ));
        }
    }
    check_child(vault, &binding, input.child, &input.parents)?;
    let claim = vault
        .get_claim(&input.claim)?
        .ok_or(invalid("the weave's claim is missing"))?;
    if claim.lifecycle != ClaimLifecycleStatus::Active
        || claim.approval == ClaimApprovalStatus::Rejected
    {
        return Err(invalid("the weave's claim was rejected or closed"));
    }
    let node = ExperimentNode {
        attempt: input.child,
        kind: ExperimentKind::Weave,
        parents: input.parents.clone(),
        candidate: input.candidate,
        search: None,
        held_out: None,
        invalid: None,
        weave: Some(WeaveReceipt {
            common_ancestor: input.common_ancestor,
            validation_overlap: input.validation_overlap,
            claim: input.claim,
            claim_approval: claim.approval,
            at,
        }),
        pruned: None,
        recorded_at: at,
    };
    put_new_node(vault, root, &node, &input.parents)?;
    Ok(node)
}

fn check_measurement(
    config: &CampaignConfig,
    measurement: &Measurement,
    split: &CampaignDatasetRef,
) -> Result<()> {
    if measurement.dataset != *split
        || measurement.metric_set_id != config.metric_set.set_id
        || measurement.metric_set_revision != config.metric_set.revision
        || measurement.scores.len() != config.metric_set.axes.len()
        || config.metric_set.axes.iter().any(|axis| {
            !measurement
                .scores
                .get(&axis.name)
                .is_some_and(|value| value.is_finite())
        })
    {
        return Err(invalid(
            "the measurement's split or metric set does not match the campaign",
        ));
    }
    Ok(())
}

fn update_node(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    change: impl FnOnce(&mut ExperimentNode) -> Result<()>,
) -> Result<ExperimentNode> {
    vault.with_write_txn_grouped(|txn| {
        let key = (*root.as_bytes(), *attempt.as_bytes());
        let mut node = NODE
            .get(&vault.store, txn, &key)?
            .ok_or(invalid("the attempt is not an experiment of this campaign"))?;
        change(&mut node)?;
        NODE.put(&vault.store, txn, &key, &node)?;
        Ok(node)
    })
}

/// Record a node's search-split evidence, its selection signal. Recorded once.
/// # Errors
/// An unbound campaign or unknown node, evidence off the search split or
/// ruler, non-finite or out-of-range numbers, a buggy or already-measured
/// node, or storage errors.
pub fn record_search_measurement(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    evidence: SearchEvidence,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    check_measurement(
        &binding.config,
        &evidence.measurement,
        &binding.config.splits.search,
    )?;
    bounded(
        &evidence.estimator_version,
        "search evidence names its estimator",
    )?;
    bounded_refs(&evidence.receipt_refs, true)?;
    if !evidence.confirmed_hits.is_finite()
        || evidence.confirmed_hits < 0.0
        || !evidence.attribution.is_finite()
        || !(0.0..=1.0).contains(&evidence.attribution)
        || !evidence.hop_cost.is_finite()
        || evidence.hop_cost < 0.0
        || !evidence.expected_gain.is_finite()
        || evidence.expected_gain < 0.0
        || !evidence.reward().is_finite()
        || evidence
            .knob_reliability
            .is_some_and(|reliability| !(0.0..=1.0).contains(&reliability))
    {
        return Err(invalid("search evidence is out of range"));
    }
    update_node(vault, root, attempt, |node| {
        if node.search.is_some() || node.invalid.is_some() {
            return Err(invalid("the node is already measured or buggy"));
        }
        node.search = Some(evidence);
        Ok(())
    })
}

/// Record a node's held-out evidence. It is read only by the promotion basis,
/// and recorded once: a second held-out look would be search feedback.
/// # Errors
/// An unbound campaign or unknown node, evidence off the held-out split or
/// ruler, a buggy node or one already held out, or storage errors.
pub fn record_held_out_measurement(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    measurement: Measurement,
    receipt_refs: Vec<String>,
    at: u64,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    check_measurement(
        &binding.config,
        &measurement,
        &binding.config.splits.held_out,
    )?;
    bounded_refs(&receipt_refs, true)?;
    update_node(vault, root, attempt, |node| {
        if node.held_out.is_some() || node.invalid.is_some() {
            return Err(invalid("the node is already held out or buggy"));
        }
        node.held_out = Some(HeldOutEvidence {
            measurement,
            receipt_refs,
            recorded_at: at,
        });
        Ok(())
    })
}

/// Mark a node buggy. It stays in the tree as evidence and takes debug
/// children; it never supplies selection signal.
/// # Errors
/// An unbound campaign or unknown node, the root, an unbounded reason or
/// refs, a node already measured or buggy, or storage errors.
pub fn record_invalid_experiment(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    reason: &str,
    evidence_refs: Vec<String>,
    at: u64,
) -> Result<ExperimentNode> {
    binding(vault, root)?;
    if attempt == root {
        return Err(invalid(
            "the incumbent root is not an experiment to mark buggy",
        ));
    }
    bounded(reason, "a buggy node names a bounded reason")?;
    bounded_refs(&evidence_refs, true)?;
    update_node(vault, root, attempt, |node| {
        if node.search.is_some() || node.invalid.is_some() {
            return Err(invalid("the node is already measured or buggy"));
        }
        node.invalid = Some(InvalidReceipt {
            reason: reason.to_owned(),
            evidence_refs,
            at,
        });
        Ok(())
    })
}

/// Stop exploring a branch for a stated cause. Its attempts, claims and
/// outputs are untouched; the node and its descendants leave selection.
/// # Errors
/// An unbound campaign or unknown node, the root, a dominating node that is
/// not a measured, unpruned experiment beating it, a floor axis not in the
/// ruler, a node already pruned, or storage errors.
pub fn prune_branch(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    reason: PruneReason,
    evidence_refs: Vec<String>,
    at: u64,
) -> Result<ExperimentNode> {
    let binding = binding(vault, root)?;
    if attempt == root {
        return Err(invalid("the incumbent root is never pruned"));
    }
    bounded_refs(&evidence_refs, true)?;
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    drop(txn);
    let node = nodes
        .get(attempt.as_bytes())
        .ok_or(invalid("the attempt is not an experiment of this campaign"))?;
    match &reason {
        PruneReason::Dominated { by } => {
            let reward = |n: &ExperimentNode| n.search.as_ref().map(SearchEvidence::reward);
            let winner = nodes
                .get(by.as_bytes())
                .filter(|_| *by != attempt && !pruned_lineage(&nodes, by));
            let beats = winner
                .and_then(reward)
                .zip(reward(node))
                .is_some_and(|(winner, loser)| winner > loser);
            if !beats {
                return Err(invalid(
                    "the dominating branch must be measured, live and better",
                ));
            }
        }
        PruneReason::FloorRegression { axis } => {
            if !binding
                .config
                .metric_set
                .axes
                .iter()
                .any(|row| row.name == *axis && row.role == MetricRole::Floor)
            {
                return Err(invalid(
                    "a floor regression names a floor axis of the ruler",
                ));
            }
        }
        PruneReason::GainBelowFloor | PruneReason::Stopped { .. } => {}
    }
    update_node(vault, root, attempt, |node| {
        if node.pruned.is_some() {
            return Err(invalid("the branch is already pruned"));
        }
        node.pruned = Some(PruneReceipt {
            reason,
            evidence_refs,
            at,
        });
        Ok(())
    })
}

fn find_node<'a>(nodes: &'a [RunTreeNode], attempt: &str) -> Option<&'a RunTreeNode> {
    nodes.iter().find_map(|node| {
        if node.attempt_id == attempt {
            Some(node)
        } else {
            find_node(&node.children, attempt)
        }
    })
}

/// The campaign's branch of its run tree, rendered from the attempt queue.
/// # Errors
/// A root absent from its run, or storage and render errors.
pub fn research_tree(vault: &Vault, root: AttemptId) -> Result<RunTree> {
    let binding = binding(vault, root)?;
    let tree = render_run_tree(AttemptQueue::new(vault).list_run(&binding.run_id)?)?;
    let node = find_node(&tree.roots, &hex(&root))
        .ok_or(invalid("the campaign root is absent from its run tree"))?
        .clone();
    Ok(RunTree {
        roots: vec![node],
        repairs: tree.repairs,
    })
}

/// Choose the next experiment through the trusted selection floor and record
/// the round. Branches are the measured, sound, unpruned nodes, scored by
/// search reward; the budget reads the campaign lease and the RSI line, and
/// exhaustion pauses rather than fails.
/// # Errors
/// An unbound campaign, no measured branch, a missing selection policy,
/// ungrounded evidence, a concurrent round, or storage errors.
pub fn select_next(
    vault: &Vault,
    root: AttemptId,
    oracle: OracleSignal,
    at: u64,
) -> Result<SelectionReceipt> {
    let binding = binding(vault, root)?;
    let tree = research_tree(vault, root)?;
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    let rounds: Vec<SelectionReceipt> = ROUND
        .scan_from(&vault.store, &txn, root.as_bytes())?
        .into_iter()
        .map(|(_, round)| round)
        .collect();
    drop(txn);
    let beliefs = estimator::branch_beliefs(&nodes, root, &binding.prior_ladder);
    let mut by_hex = BTreeMap::new();
    let mut branches = Vec::new();
    let mut snapshots = Vec::new();
    let mut gains = BTreeMap::new();
    for node in nodes.values() {
        let Some(search) = &node.search else { continue };
        if node.invalid.is_some() || pruned_lineage(&nodes, &node.attempt) {
            continue;
        }
        let id = hex(&node.attempt);
        by_hex.insert(id.clone(), node.attempt);
        let belief = beliefs
            .as_ref()
            .and_then(|beliefs| beliefs.get(node.attempt.as_bytes()))
            .copied();
        if let Some(belief) = belief {
            gains.insert(id.clone(), belief.information_gain);
        }
        branches.push(MeasuredBranch {
            attempt_id: id,
            quality: search.reward(),
            expected_gain: search.expected_gain,
        });
        snapshots.push(BranchSnapshot {
            attempt: node.attempt,
            reward: search.reward(),
            expected_gain: search.expected_gain,
            estimator_version: search.estimator_version.clone(),
            belief,
        });
    }
    // Information gain ranks only under an admitted version, and only when
    // every branch has a belief; otherwise the DGM floor ranks.
    let ranked = gains.len() == branches.len()
        && estimator::estimator_admitted(vault, ENGINE_ESTIMATOR_VERSION)?;
    let (ranking, parent_ranking) = if ranked {
        (
            SelectionRanking::InformationGain {
                estimator_version: ENGINE_ESTIMATOR_VERSION.to_owned(),
            },
            ParentRanking::InformationGain(gains),
        )
    } else {
        (SelectionRanking::Dgm, ParentRanking::Dgm)
    };
    let prior_qualities: Vec<f64> = rounds.iter().map(|round| round.best_quality).collect();
    let prior_gains: Vec<f64> = rounds.iter().map(|round| round.best_gain).collect();
    let budget_available = budget::work_available(vault, &binding)?;
    let decision = decide_experiment_for(
        vault,
        &binding.config.campaign_id,
        binding.holder.as_deref(),
        &tree,
        &branches,
        &prior_qualities,
        &prior_gains,
        budget_available,
        oracle,
        &parent_ranking,
    )?;
    let step = match decision {
        SelectionDecision::Fork {
            parent_id,
            stagnation,
        } => ResearchStep::Fork {
            parent: *by_hex
                .get(&parent_id)
                .ok_or(invalid("the selected parent is not a campaign branch"))?,
            stagnation,
        },
        SelectionDecision::PausedBudget => ResearchStep::PausedBudget,
        SelectionDecision::StoppedPlateau => ResearchStep::StoppedPlateau,
        SelectionDecision::EscalatePlateau => ResearchStep::EscalatePlateau,
        SelectionDecision::StoppedOracle => ResearchStep::StoppedOracle,
    };
    let policy = selection_policy_for(
        vault,
        &binding.config.campaign_id,
        binding.holder.as_deref(),
    )?;
    let round = u64::try_from(rounds.len()).map_err(|_| invalid("round count overflow"))?;
    let receipt = SelectionReceipt {
        root,
        round,
        step,
        best_quality: branches
            .iter()
            .map(|branch| branch.quality)
            .fold(f64::NEG_INFINITY, f64::max),
        best_gain: branches
            .iter()
            .map(|branch| branch.expected_gain)
            .fold(0.0_f64, f64::max),
        branches: snapshots,
        ranking,
        policy_digest: policy_digest(&policy)?,
        budget_available,
        oracle_goal_met: oracle == OracleSignal::GoalMet,
        at,
    };
    vault.with_write_txn_grouped(|txn| {
        if ROUND.contains(&vault.store, txn, &(*root.as_bytes(), round))? {
            return Err(invalid(
                "another selection round committed first; select again",
            ));
        }
        ROUND.put(&vault.store, txn, &(*root.as_bytes(), round), &receipt)?;
        Ok(receipt)
    })
}
