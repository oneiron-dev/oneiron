//! Type-tree upkeep (ARCH-0079 #task-type, OF-541, OF-420): "Splits, merges
//! and names task types from the receipts."
//!
//! The vault tree's counts are rebuilt from the team receipts placed in it, so
//! a night that sees the same receipts writes the same tree. A decision is
//! read only from an anchored comparison: one TASK run by several teams whose
//! settled outcomes differ, where every run that succeeded chose one value on
//! an axis and a run that chose another value failed. Completion, a team's
//! model mix and a model's mere presence are never wins, and agreement between
//! agents is not an outcome. A live leaf splits when its tasks disagree on a
//! decision; split siblings merge back only when both carry their own receipts
//! and read a clear winner alike. A changed shape must read the held-out
//! tasks' decisions no worse than the tree in force, or only its counts are
//! kept. The tree is data inside the team-shape skill, so a changed tree is
//! proposed as a revision of that skill's in-force head, through the same
//! optimizer birth and gate as an instruction edit; it goes in force only
//! when the gate admits it.
//!
//! Each settled team fills the reserve of the in-force team-shape revision
//! its leader loaded, and the reshape never fits on a run that reserve holds.
//! When the host lends a judge, the pass puts the open revision to the gate
//! with a judge that reads both versions' trees, and an admitting verdict
//! puts it in force.
use std::collections::{BTreeMap, BTreeSet};

use super::coach::COACH_TYPE_TREE_UPKEEP_FACET;
use super::type_tree_gate::{ReserveWrite, drive, record_team_shape_outcomes};
use crate::agent_dispatch::{
    TASK_TYPE_TREE_FILE, load_team_type_tree, team_shape_skill, team_shape_skill_in_force,
};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::entity_id::EntityId;
use crate::skill_hub::HubFile;
use crate::skill_optimize::{
    HeldOutReplayNotes, SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE, SkillEditDisposition, SkillRepairStamp,
    propose_skill_package_revision, proven_cycle, receipt_is_held_out,
};
use crate::task_type::{
    DecisionAxis, DecisionObservation, TaskTypeNode, TaskTypeRef, TaskTypeTree,
};
use crate::team::run_binding::team_run_tasks;
use crate::team::{TeamReceipt, team_receipts};
use crate::temporal::TimeRange;
use crate::{Error, Result, Vault};

/// Split types one pass puts to the host for a readable name; the rest keep
/// their generated names until a later night.
pub const TYPE_NAMES_PER_PASS: usize = 8;
/// Longest readable type name kept, in characters.
pub const MAX_TYPE_NAME_CHARS: usize = 80;
/// A team that settles failed charges a loss to the team-shape revision its
/// leader's pack loaded, with no attribution verdict; a team that settles
/// succeeded credits a win through the ordinary contributing-win door.
/// `false`: wins only.
pub const TEAM_SHAPE_CHARGES_FAILED_TEAMS: bool = true;
/// An admitting gate verdict on a team-shape revision puts it in force at
/// once (admission and supersession in one transaction), with no owner step.
/// `false` leaves the admitting verdict standing for an owner door.
pub const TEAM_SHAPE_GATE_ADMITS: bool = true;

/// One team receipt as the vault tree counts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeEvidence {
    pub team_ref: String,
    pub type_ref: TaskTypeRef,
    /// The TASK the team ran, when the host recorded its start.
    pub task: Option<String>,
    /// What this run won in an anchored comparison on its task.
    pub decisions: Vec<DecisionObservation>,
}

/// What the host lends the Coach: a readable name for a split type.
pub trait TypeNamer {
    /// A short name for `node`, which a split made out of `parent`; `None`
    /// keeps the generated one.
    ///
    /// # Errors
    ///
    /// Host-defined.
    fn name(&self, parent: &TaskTypeNode, node: &TaskTypeNode) -> Result<Option<String>>;
}

/// Settled teams one pass offered to the in-force team-shape revision's
/// ledger. Every pass offers every settled team again; the ledger keeps one
/// row per leader receipt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TeamShapeReserve {
    pub wins: u32,
    pub losses: u32,
    /// Teams the outcome door refused: an unfinished leader for a win, or a
    /// leader receipt with no task type or executor.
    pub skipped: u32,
}

/// What the gate did with the open team-shape revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeGateOutcome {
    /// Nothing to rule on yet (the head reserves no run) or the snapshot
    /// moved; a later pass asks again.
    Retry,
    /// The gate's ruling, which put nothing in force.
    Ruled(SkillEditDisposition),
    /// The revision is in force and supersedes the head it revised.
    Admitted(EntityId),
    /// The gate admitted it and the admission door then refused it; the
    /// proposal is closed.
    Refused(SkillEditDisposition),
}

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypeTreeUpkeepReport {
    /// Receipts counted into the vault tree.
    pub receipts: u32,
    /// Decisions read from anchored comparisons.
    pub decisions: u32,
    /// Receipts naming a node outside the tree in force.
    pub skipped: u32,
    pub splits: u32,
    pub merges: u32,
    pub named: u32,
    /// Held-out decisions read right by the tree in force and by the
    /// reshaped tree, when the pass reshaped it.
    pub held_out_hits: Option<(u64, u64)>,
    /// The reshaped tree read the held-out decisions worse; only its counts
    /// were kept.
    pub reshape_refused: bool,
    /// The team-shape revision proposed with the new tree.
    pub proposed: Option<EntityId>,
    /// The tree changed, but an earlier proposed revision is still open.
    pub pending: bool,
    /// Settled teams charged to the in-force team-shape revision.
    pub reserve: TeamShapeReserve,
    /// The gate's answer on the open revision, when the host lent a judge
    /// and a revision was open.
    pub gate: Option<TreeGateOutcome>,
}

/// The value a run chose on one decision axis, when its receipt names one.
fn axis_value(receipt: &TeamReceipt, axis: DecisionAxis) -> Option<String> {
    match axis {
        DecisionAxis::WinningPattern => Some(receipt.pattern.as_str().to_owned()),
        // A mix is not one model's win: only a single-model team decides it.
        DecisionAxis::WinningModel => {
            let models: BTreeSet<&str> = receipt
                .models
                .iter()
                .map(|id| id.rsplit_once('@').map_or(id.as_str(), |(model, _)| model))
                .collect();
            match models.len() {
                1 => models.into_iter().next().map(str::to_owned),
                _ => None,
            }
        }
        // A team receipt names no critic; its decision needs its own anchored
        // source.
        DecisionAxis::TrustedCritic => None,
    }
}

/// What one task's settled runs decided on `axis`: the one value every run
/// that succeeded chose, when no run that chose it failed and some run that
/// chose another value did. The decision counts once, on the latest winning
/// run (its index in `receipts`).
fn task_decision(
    receipts: &[TeamReceipt],
    runs: &[usize],
    axis: DecisionAxis,
) -> Option<(String, usize)> {
    let mut won = BTreeSet::new();
    let mut lost = BTreeSet::new();
    let mut latest: Option<usize> = None;
    for &index in runs {
        let receipt = &receipts[index];
        let (Some(outcome), Some(value)) = (&receipt.outcome, axis_value(receipt, axis)) else {
            continue;
        };
        if outcome.success {
            won.insert(value);
            if latest.is_none_or(|prior| {
                (receipts[prior].at, &receipts[prior].team_ref) < (receipt.at, &receipt.team_ref)
            }) {
                latest = Some(index);
            }
        } else {
            lost.insert(value);
        }
    }
    let mut won = won.into_iter();
    let (Some(winner), None) = (won.next(), won.next()) else {
        return None;
    };
    if lost.is_empty() || lost.contains(&winner) {
        return None;
    }
    latest.map(|index| (winner, index))
}

/// Every receipt in `receipts` with the decisions its task's anchored
/// comparison gave it; `tasks` names each team's TASK.
#[must_use]
pub fn type_evidence(
    receipts: Vec<TeamReceipt>,
    tasks: &BTreeMap<String, String>,
) -> Vec<TypeEvidence> {
    let mut by_task: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, receipt) in receipts.iter().enumerate() {
        if receipt.outcome.is_some()
            && let Some(task) = tasks.get(&receipt.team_ref)
        {
            by_task.entry(task.as_str()).or_default().push(index);
        }
    }
    let mut decisions: BTreeMap<usize, Vec<DecisionObservation>> = BTreeMap::new();
    for runs in by_task.values() {
        for axis in DecisionAxis::ALL {
            if let Some((winner, index)) = task_decision(&receipts, runs, axis) {
                decisions
                    .entry(index)
                    .or_default()
                    .push(DecisionObservation::new(axis, winner));
            }
        }
    }
    receipts
        .into_iter()
        .enumerate()
        .map(|(index, receipt)| TypeEvidence {
            task: tasks.get(&receipt.team_ref).cloned(),
            type_ref: TaskTypeRef::from(&receipt.type_ref),
            team_ref: receipt.team_ref,
            decisions: decisions.remove(&index).unwrap_or_default(),
        })
        .collect()
}

/// `tree`'s shape with its receipt and decision counts rebuilt from
/// `evidence`; the merge-back's held-out counts are kept. Returns the tree and
/// how many receipts named a node outside it.
#[must_use]
pub fn recount(tree: &TaskTypeTree, evidence: &[&TypeEvidence]) -> (TaskTypeTree, u32) {
    let mut tree = tree.clone();
    for node in tree.nodes.values_mut() {
        node.receipt_count = 0;
        node.decision_wins.clear();
    }
    let mut skipped = 0_u32;
    for row in evidence {
        if tree.record_receipt(&row.type_ref, &row.decisions).is_err() {
            skipped = skipped.saturating_add(1);
        }
    }
    (tree, skipped)
}

/// Splits and merges one pass made.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Reshape {
    splits: u32,
    merges: u32,
}

/// Splits each live leaf on the first decision its tasks disagree on, then
/// merges split siblings that [`merge_supported`] allows, each node at most
/// once a pass.
fn reshape(tree: &mut TaskTypeTree) -> Reshape {
    let mut changes = Reshape::default();
    let mut split = BTreeSet::new();
    for candidate in tree.split_candidates() {
        if split.contains(&candidate.node_id) || !tree.is_leaf(&candidate.node_id) {
            continue;
        }
        // A refusal (children of an earlier split merged away under the same
        // ids) leaves the node as it is.
        if tree.split(&candidate.node_id, candidate.axis).is_ok() {
            changes.splits += 1;
            split.insert(candidate.node_id);
        }
    }
    let parents: Vec<String> = tree
        .nodes
        .values()
        .filter(|node| node.is_live())
        .map(|node| node.node_id.clone())
        .collect();
    for parent in parents {
        let siblings: Vec<String> = tree
            .children(&parent)
            .into_iter()
            .filter(|node| node.split_axis.is_some() && !node.is_thin())
            .map(|node| node.node_id.clone())
            .filter(|node_id| tree.is_leaf(node_id))
            .collect();
        let mut merged = BTreeSet::new();
        for (index, a) in siblings.iter().enumerate() {
            for b in &siblings[index + 1..] {
                if merged.contains(a) || merged.contains(b) || !merge_supported(tree, a, b) {
                    continue;
                }
                if tree.merge_siblings(a, b).is_ok() {
                    changes.merges += 1;
                    merged.insert(a.clone());
                    merged.insert(b.clone());
                }
            }
        }
    }
    changes
}

/// Siblings merge on evidence, not on silence: [`TaskTypeTree::siblings_agree`]
/// holds wherever either lacks a clear winner, so they must also read a clear
/// winner alike on at least one decision.
fn merge_supported(tree: &TaskTypeTree, a: &str, b: &str) -> bool {
    let (Some(left), Some(right)) = (tree.node(a), tree.node(b)) else {
        return false;
    };
    tree.siblings_agree(a, b)
        && DecisionAxis::ALL.iter().any(|axis| {
            matches!(
                (left.clear_winner(*axis), right.clear_winner(*axis)),
                (Some(mine), Some(theirs)) if mine == theirs
            )
        })
}

/// Held-out decisions `tree` reads right: the winner it reads for the run's
/// type on that axis is the value that won.
fn held_out_hits(tree: &TaskTypeTree, held_out: &[&TypeEvidence]) -> u64 {
    let mut hits = 0_u64;
    for row in held_out {
        let Some(node) = tree.resolve_ref(&row.type_ref) else {
            continue;
        };
        for decision in &row.decisions {
            if tree.effective_winner(&node.node_id, decision.axis) == Some(decision.winner.as_str())
            {
                hits += 1;
            }
        }
    }
    hits
}

/// The name [`TaskTypeTree::split`] gives a child, which a readable one
/// replaces.
fn generated_name(node: &TaskTypeNode) -> Option<String> {
    Some(format!(
        "{} where {} is {}",
        node.parent.as_deref()?,
        node.split_axis?.as_str(),
        node.split_winner.as_deref()?
    ))
}

/// Puts up to [`TYPE_NAMES_PER_PASS`] live split types that still carry a
/// generated name to `namer`. A name that is empty, multi-line or already
/// another type's is dropped.
fn name_types(tree: &mut TaskTypeTree, namer: &dyn TypeNamer) -> Result<u32> {
    let unnamed: Vec<String> = tree
        .nodes
        .values()
        .filter(|node| node.is_live() && generated_name(node).is_some_and(|name| name == node.name))
        .map(|node| node.node_id.clone())
        .take(TYPE_NAMES_PER_PASS)
        .collect();
    let mut named = 0_u32;
    for node_id in unnamed {
        let Some(node) = tree.node(&node_id) else {
            continue;
        };
        let Some(parent) = node.parent.as_deref().and_then(|parent| tree.node(parent)) else {
            continue;
        };
        let Some(answer) = namer.name(parent, node)? else {
            continue;
        };
        let name: String = answer.trim().chars().take(MAX_TYPE_NAME_CHARS).collect();
        if name.is_empty()
            || name.chars().any(char::is_control)
            || tree.nodes.values().any(|other| other.name == name)
        {
            continue;
        }
        if let Some(node) = tree.nodes.get_mut(&node_id) {
            node.name = name;
            named += 1;
        }
    }
    Ok(named)
}

/// The proposal's rationale: what the pass changed and what the held-out
/// check read.
fn rationale(report: &TypeTreeUpkeepReport, version: u64) -> String {
    let held_out = report
        .held_out_hits
        .map_or_else(String::new, |(before, after)| {
            format!("; held-out decisions read right {before} -> {after}")
        });
    format!(
        "type-tree upkeep to tree version {version}: {} receipts, {} anchored decisions, {} splits, \
{} merges, {} named{held_out}",
        report.receipts, report.decisions, report.splits, report.merges, report.named
    )
}

impl Vault {
    /// Type-tree upkeep as the Coach, under a leased `coach.type_tree_upkeep`
    /// attempt: charge each settled team to the in-force team-shape revision
    /// its leader loaded, recount the vault tree from its receipts, split and
    /// merge on the fit tasks' decisions, keep the new shape only when it
    /// reads the held-out tasks' decisions no worse, name new split types
    /// through `namer` (outside any vault transaction), and propose a changed
    /// tree as a revision of the in-force team-shape skill. With a `scorer`,
    /// the open revision then goes to the held-out gate, and an admitting
    /// verdict puts it in force.
    ///
    /// # Errors
    ///
    /// A lease that is not this facet's Coach attempt; storage errors; the
    /// namer's and the scorer's errors; the outcome, proposal and gate
    /// doors' refusals.
    pub fn run_coach_type_tree_upkeep(
        &self,
        attempt: &DreamerAdmittedAttempt,
        namer: &dyn TypeNamer,
        scorer: Option<&dyn HeldOutReplayNotes>,
        now: u64,
    ) -> Result<TypeTreeUpkeepReport> {
        self.require_coach_attempt(attempt, COACH_TYPE_TREE_UPKEEP_FACET)?;
        let receipts = team_receipts(self, None)?;
        let reserve = match team_shape_skill_in_force(self, None)? {
            Some(head) => {
                let record = self.get_skill_record(&head)?.ok_or(Error::EntityNotFound)?;
                record_team_shape_outcomes(self, &head, &record, &receipts)?
            }
            None => ReserveWrite::default(),
        };
        let mut report =
            self.reshape_and_propose(attempt, namer, &receipts, &reserve.held_out_teams, now)?;
        report.reserve = reserve.report;
        if let Some(scorer) = scorer {
            report.gate = drive(self, attempt, scorer, &receipts, now)?;
        }
        Ok(report)
    }

    /// The recount, reshape and proposal of [`Self::run_coach_type_tree_upkeep`]
    /// over `teams`. A run whose team `reserved` names (the gate's reserve)
    /// is never fit on.
    fn reshape_and_propose(
        &self,
        attempt: &DreamerAdmittedAttempt,
        namer: &dyn TypeNamer,
        teams: &[TeamReceipt],
        reserved: &BTreeSet<String>,
        now: u64,
    ) -> Result<TypeTreeUpkeepReport> {
        let base = load_team_type_tree(self, None)?;
        let evidence = self.vault_type_evidence(teams)?;
        let skill = team_shape_skill()?;
        let (held_out, mut fit): (Vec<&TypeEvidence>, Vec<&TypeEvidence>) =
            evidence.iter().partition(|row| {
                !row.decisions.is_empty()
                    && row
                        .task
                        .as_deref()
                        .is_some_and(|task| receipt_is_held_out(&skill, task))
            });
        fit.retain(|row| !reserved.contains(&row.team_ref));
        let mut report = TypeTreeUpkeepReport {
            receipts: u32::try_from(evidence.len()).unwrap_or(u32::MAX),
            decisions: u32::try_from(
                evidence
                    .iter()
                    .map(|row| row.decisions.len())
                    .sum::<usize>(),
            )
            .unwrap_or(u32::MAX),
            ..TypeTreeUpkeepReport::default()
        };
        let (in_force, _) = recount(&base, &fit);
        let mut shaped = in_force.clone();
        let changes = reshape(&mut shaped);
        if changes != Reshape::default() {
            let hits = (
                held_out_hits(&in_force, &held_out),
                held_out_hits(&shaped, &held_out),
            );
            report.held_out_hits = Some(hits);
            if hits.1 < hits.0 {
                report.reshape_refused = true;
                shaped = base.clone();
            } else {
                report.splits = changes.splits;
                report.merges = changes.merges;
            }
        }
        let all: Vec<&TypeEvidence> = evidence.iter().collect();
        let (mut tree, skipped) = recount(&shaped, &all);
        report.skipped = skipped;
        report.named = name_types(&mut tree, namer)?;
        if tree == base {
            return Ok(report);
        }
        let Some(head) = team_shape_skill_in_force(self, None)? else {
            return Ok(report);
        };
        let version = self
            .get_skill_record(&head)?
            .ok_or(Error::EntityNotFound)?
            .version;
        let content = serde_json::to_vec_pretty(&tree)
            .map_err(|_| Error::InvariantViolation("type tree does not encode"))?;
        let mut receipts: Vec<String> = fit
            .iter()
            .filter(|row| !row.decisions.is_empty())
            .map(|row| row.team_ref.clone())
            .collect();
        receipts.reverse();
        receipts.truncate(SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE);
        let id = attempt.status.attempt.id;
        let cycle = proven_cycle(self, id)?;
        let stamp = SkillRepairStamp {
            actor: self.dreamer_actor_for_attempt(id)?,
            facet: COACH_TYPE_TREE_UPKEEP_FACET,
            attempt: id,
            cycle: &cycle,
            owner: None,
            resident: None,
        };
        let proposed = propose_skill_package_revision(
            self,
            &head,
            &version,
            &[HubFile::new(TASK_TYPE_TREE_FILE, content)],
            &rationale(&report, tree.version),
            &receipts,
            &stamp,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        report.pending = proposed.is_none();
        report.proposed = proposed;
        Ok(report)
    }

    /// Every team receipt in `teams` placed in the vault tree (no project, or
    /// a project with no team-shape fork of its own in force), with its
    /// decisions.
    fn vault_type_evidence(&self, teams: &[TeamReceipt]) -> Result<Vec<TypeEvidence>> {
        let vault_head = team_shape_skill_in_force(self, None)?;
        let mut shares: BTreeMap<EntityId, bool> = BTreeMap::new();
        let mut receipts = Vec::new();
        for receipt in teams {
            let shared = match receipt.project {
                None => true,
                Some(project) => match shares.get(&project) {
                    Some(shared) => *shared,
                    None => {
                        let shared = team_shape_skill_in_force(self, Some(project))? == vault_head;
                        shares.insert(project, shared);
                        shared
                    }
                },
            };
            if shared {
                receipts.push(receipt.clone());
            }
        }
        Ok(type_evidence(receipts, &team_run_tasks(self)?))
    }
}
