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
//! - Every weave names the claim it landed through the gate, the gate's own
//!   record of that landing, its common ancestor and its validation overlap,
//!   and is refused until a held-out win in this campaign turned merge
//!   crossover on. A controller weaves only a claim it wrote; one past
//!   Proposed stands only on the gate's Allow for it under the owner's Grant.
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

mod binding;
mod budget;
mod children;
mod continuation;
mod estimator;
mod promotion;
mod recording;
mod source_erase;

pub use budget::{
    ResearchBudgetRead, ResearchReservation, ResearchReservationLine, refund_research_work,
    research_budget, research_reservations, reserve_research_exploration, reserve_research_work,
    settle_research_work,
};
pub use children::create_research_child;
pub use continuation::{
    ResearchContinuation, ResearchContinuationState, ResearchRunning, ResearchSplit, ResearchTask,
    ResearchWork, advance_research_continuations, ensure_research_continuations,
    research_work_pending,
};
pub use estimator::{
    BranchBelief, ENGINE_ESTIMATOR_VERSION, MIN_SELECTION_BENCHMARK_CASES, PriorRung, PriorSeed,
    SelectionBenchmark, SelectionRanking, record_selection_benchmark, selection_benchmark,
};
pub(crate) use promotion::{promotion_basis_in_txn, research_incumbent_in_txn};

pub use promotion::{
    CampaignPromotionReceipt, ConfirmationOutcome, ConfirmationReceipt, HeldOutCall,
    PromotionBasis, PromotionDisposition, promote_measured, promotion_basis, research_incumbent,
    research_promotions, reserve_confirmation,
};

use recording::find_node;

pub use binding::{
    ResearchGoalBasis, bind_research, bound_research_roots, research_binding, research_goal_basis,
    research_nodes, research_rounds,
};
pub(super) use binding::{binding, check_goal_current, check_goal_current_in_txn, nodes_in_txn};
pub(crate) use binding::{binding_in_txn, has_binding_in_txn};
pub use recording::{
    prune_branch, record_fork, record_held_out_measurement, record_invalid_experiment,
    record_search_measurement, record_weave,
};
pub(crate) use source_erase::erase_release_source_rows_in_txn;

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
/// The gate's recorded content kind and outcomes a weave claim is read by.
const WEAVE_CONTENT_KIND: &str = "claim";
const OUTCOME_ALLOW: &str = "allow";
const OUTCOME_DENY: &str = "deny";

/// What a campaign improves, and so which ruler it is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchGoalPin {
    pub goal_id: EntityId,
    pub revision: String,
    /// The joined project and its goal claim, when the goal has one.
    pub project: Option<(EntityId, EntityId)>,
}

/// The sealed cohort a campaign confirms on: OF-578's exposure ledger, not a
/// campaign twin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchConfirmationSeat {
    pub seat: EvalSeat,
    pub cohort: EntityId,
}

/// A candidate configuration the sandbox wrote: a content reference and the
/// digest of its bytes. The loop never reads or runs the config itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateRef {
    pub config_ref: String,
    pub config_sha256: String,
}

/// The agents the host runs a campaign's work with (FIX 886). Each is an
/// AGENT_DEF running its own workflow skill; each answers with one JSON
/// object and never writes the campaign record itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeldOutEvidence {
    pub measurement: Measurement,
    pub receipt_refs: Vec<String>,
    pub recorded_at: u64,
}

/// A buggy node: kept as evidence, eligible for debug children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvalidReceipt {
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub at: u64,
}

/// Why a branch stopped being explored. There is deliberately no surprise
/// variant: surprise only picks the next experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PruneReceipt {
    pub reason: PruneReason,
    pub evidence_refs: Vec<String>,
    pub at: u64,
}

/// The lineage receipt of a weave: its parents are on the node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveReceipt {
    pub common_ancestor: AttemptId,
    pub validation_overlap: f64,
    /// The claim the weave landed as, through the gate.
    pub claim: EntityId,
    /// The claim's approval when the weave was recorded: proposed, unless an
    /// owner grant let the gate approve it.
    pub claim_approval: ClaimApprovalStatus,
    /// The gate's recorded decision on the claim's landing, by hex id: the
    /// claim door's record of its writer's write.
    pub gate_decision: String,
    pub at: u64,
}

/// Who records a weave, as `vault.research.weave` authenticated them: the
/// vault owner, or the campaign's controller agent by its actor entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeaveWriter {
    Owner,
    Controller { actor: EntityId },
}

/// One experiment: an existing attempt annotated with its campaign record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchStep {
    Fork { parent: AttemptId, stagnation: bool },
    PausedBudget,
    StoppedPlateau,
    EscalatePlateau,
    StoppedOracle,
}

/// The evidence one branch contributed to a round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BranchSnapshot {
    pub attempt: AttemptId,
    pub reward: f64,
    pub expected_gain: f64,
    pub estimator_version: String,
    /// The engine estimator's belief, once the incumbent is measured.
    pub belief: Option<BranchBelief>,
}

/// The durable receipt of one selection round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionReceipt {
    pub root: AttemptId,
    pub round: u64,
    /// The incumbent whose search reward the round's beliefs beat against.
    pub incumbent: AttemptId,
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

/// The staged skill proposal a skill candidate names: `skill_proposal:<32 hex>`.
pub(crate) fn proposal_of(candidate: &CandidateRef) -> Option<EntityId> {
    let id = candidate.config_ref.strip_prefix("skill_proposal:")?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    EntityId::from_hex(id).ok()
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
    let incumbent = research_incumbent(vault, root)?;
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    let rounds: Vec<SelectionReceipt> = ROUND
        .scan_from(&vault.store, &txn, root.as_bytes())?
        .into_iter()
        .map(|(_, round)| round)
        .collect();
    drop(txn);
    let beliefs = estimator::branch_beliefs(&nodes, root, incumbent, &binding.prior_ladder);
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
        incumbent,
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
