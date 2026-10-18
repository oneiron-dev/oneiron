//! The held-out gate on a team-shape tree revision (ARCH-0079 #task-type,
//! OF-420): "revised by the loop from receipts".
//!
//! A team that settles is charged to the team-shape revision its leader's
//! pack loaded, through the skill's own outcome ledger, so the in-force head
//! holds a reserve the gate can rule over. The open revision is put to that
//! gate with a judge that reads, beside each reserved run, what each
//! version's task-type tree would have placed and picked for it; an
//! admitting verdict puts the revision in force.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::type_tree_upkeep::{
    TEAM_SHAPE_CHARGES_FAILED_TEAMS, TEAM_SHAPE_GATE_ADMITS, TeamShapeReserve, TreeGateOutcome,
};
use crate::agent_dispatch::{TASK_TYPE_TREE_FILE, TEAM_SHAPE_SKILL_NAME, load_team_type_tree};
use crate::attempt_queue::{AttemptId, ManifestEntry};
use crate::autoreason_campaign::coverage::CoverageFloorComparison;
use crate::claim::ClaimApprovalStatus;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::error::ArtifactError;
use crate::llm::decision::{DecisionQuestion, TypedDecision};
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::skill_optimize::{
    GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes, HonestyReplay,
    PROVENANCE_OPTIMIZE_OF_ENTITY_KEY, SKILL_OPTIMIZE_BIRTH_PATH, SkillOptimizeDecisions,
    SkillReplayPair, receipt_is_held_out, score_gate_skill_edit_in_cycle,
};
use crate::task_type::{DecisionAxis, TaskTypeRef, TaskTypeTree};
use crate::team::TeamReceipt;
use crate::{EntityId, Error, Result, TimeRange, Vault};

/// Skill records read per page while looking for the open revision.
const SKILL_PAGE: usize = 128;

/// What the judge is told moves between the two versions of a tree revision.
const TREE_MOVES: &str = "What differs between the two versions is this task-type tree inside \
the team-shape skill, which places each run under a type and picks its pattern and model; their \
instructions are the same.";
/// What the judge is told when the open revision edits the instructions.
const INSTRUCTIONS_MOVE: &str = "The two versions' instructions differ; each places and picks \
for runs with the task-type tree shown here.";

/// What [`record_team_shape_outcomes`] wrote.
#[derive(Debug, Default)]
pub(super) struct ReserveWrite {
    pub(super) report: TeamShapeReserve,
    /// The teams whose leader receipt now sits in the head's gate reserve.
    pub(super) held_out_teams: BTreeSet<String>,
}

/// The leader attempt of a led team, from its `team:<hex>:<key>` ref.
fn team_leader(team_ref: &str) -> Option<AttemptId> {
    let (hex, _) = team_ref.strip_prefix("team:")?.split_once(':')?;
    let id = EntityId::from_hex(hex).ok()?;
    AttemptId::from_bytes(id.as_bytes()).ok()
}

/// Charges each settled team in `receipts` to `head` (the in-force
/// team-shape revision, `record`) when the host recorded the team's start
/// and its leader's terminal pack loaded exactly this revision: a success
/// is a contributing win, a failure a loss when
/// [`TEAM_SHAPE_CHARGES_FAILED_TEAMS`]. A team whose leader is not yet
/// terminal is left for a later pass. Idempotent: the ledger keys by
/// (skill, executor, receipt), and a loss outranks a win.
///
/// # Errors
///
/// Storage errors, and the outcome doors' errors other than a refusal of
/// the receipt (which counts as skipped).
pub(super) fn record_team_shape_outcomes(
    vault: &Vault,
    head: &EntityId,
    record: &SkillRecord,
    receipts: &[TeamReceipt],
) -> Result<ReserveWrite> {
    let mut write = ReserveWrite::default();
    for receipt in receipts {
        let Some(outcome) = &receipt.outcome else {
            continue;
        };
        let Some(leader) = team_leader(&receipt.team_ref) else {
            continue;
        };
        if crate::team::run_binding::team_run_binding(vault, leader, &receipt.team_ref)?.is_none() {
            continue;
        }
        let receipt_ref = crate::receipt::attempt_pack_receipt_id(&leader);
        let Some(pack) = crate::receipt::attempt_pack_receipt(vault, &receipt_ref)? else {
            continue;
        };
        let loaded = pack.pack_manifest_skills().is_some_and(|manifest| {
            manifest.iter().any(|entry| {
                ManifestEntry::parse_wire_form(entry)
                    == Some((record.skill_id.as_str(), record.version.as_str()))
            })
        });
        if !loaded {
            continue;
        }
        let recorded = if outcome.success {
            crate::skill_reliability::record_skill_contributing_win(
                vault,
                head,
                &receipt_ref,
                outcome.at,
            )
        } else if TEAM_SHAPE_CHARGES_FAILED_TEAMS {
            crate::skill_reliability::record_skill_settled_loss(
                vault,
                head,
                &receipt_ref,
                outcome.at,
            )
        } else {
            continue;
        };
        match recorded {
            Ok(()) if outcome.success => write.report.wins += 1,
            Ok(()) => write.report.losses += 1,
            Err(Error::Artifact(ArtifactError::InvalidSkillBody(_))) => {
                write.report.skipped += 1;
                continue;
            }
            Err(error) => return Err(error),
        }
        if receipt_is_held_out(head, &receipt_ref) {
            write.held_out_teams.insert(receipt.team_ref.clone());
        }
    }
    Ok(write)
}

/// The lent judge, with each version's task-type tree read beside its
/// replay: the judge's own replay reads attempts, never package files, so
/// without this both versions of a tree revision would read alike.
struct TreeReplayScorer<'a> {
    inner: &'a dyn HeldOutReplayNotes,
    moves: &'static str,
    /// (version, the tree that version places with): the incumbent's and
    /// the proposal's.
    arms: [(String, TaskTypeTree); 2],
    /// Settled team receipts, keyed by their leader's pack receipt.
    teams: BTreeMap<String, Vec<TeamReceipt>>,
}

impl<'a> TreeReplayScorer<'a> {
    /// The scorer for `proposal`, a revision of `predecessor`. A proposal
    /// package with no tree file places with the seed tree, as the tree
    /// loader reads it once in force.
    fn new(
        vault: &Vault,
        inner: &'a dyn HeldOutReplayNotes,
        proposal: &EntityId,
        predecessor: &EntityId,
        receipts: &[TeamReceipt],
    ) -> Result<Self> {
        let incumbent = vault
            .get_skill_record(predecessor)?
            .ok_or(Error::EntityNotFound)?;
        let in_force = load_team_type_tree(vault, None)?;
        let (record, tree) = {
            let txn = vault.store.env.read_txn()?;
            let record = vault.read_skill_record_in_txn(&txn, proposal)?;
            let file = vault
                .runtime_skill_package_in_txn(&txn, proposal, &record)?
                .and_then(|package| {
                    package
                        .files
                        .into_iter()
                        .find(|file| file.path == TASK_TYPE_TREE_FILE)
                });
            let tree = match file {
                Some(file) => {
                    serde_json::from_slice::<TaskTypeTree>(&file.content).map_err(|_| {
                        Error::InvariantViolation(
                            "a team-shape revision's type tree does not decode",
                        )
                    })?
                }
                None => TaskTypeTree::seeded(),
            };
            (record, tree)
        };
        let mut teams: BTreeMap<String, Vec<TeamReceipt>> = BTreeMap::new();
        for receipt in receipts.iter().filter(|receipt| receipt.outcome.is_some()) {
            if let Some(leader) = team_leader(&receipt.team_ref) {
                teams
                    .entry(crate::receipt::attempt_pack_receipt_id(&leader))
                    .or_default()
                    .push(receipt.clone());
            }
        }
        Ok(Self {
            inner,
            moves: if record.desc == incumbent.desc {
                TREE_MOVES
            } else {
                INSTRUCTIONS_MOVE
            },
            arms: [(incumbent.version, in_force), (record.version, tree)],
            teams,
        })
    }

    /// What `tree` places and picks for each of `receipts`' teams. No
    /// outcome is read: the judge never sees a success label.
    fn view(&self, tree: &TaskTypeTree, receipts: &[String]) -> Value {
        let runs: Vec<Value> = receipts
            .iter()
            .map(|receipt| {
                let teams: Vec<Value> = self
                    .teams
                    .get(receipt)
                    .into_iter()
                    .flatten()
                    .map(|team| team_view(tree, team))
                    .collect();
                json!({"receipt": receipt, "teams": teams})
            })
            .collect();
        json!({"moves": self.moves, "tree_version": tree.version, "runs": runs})
    }
}

/// The winner `tree` reads on each decision for `node`; null where it reads
/// none, or for a run outside the tree.
fn picks(tree: &TaskTypeTree, node: Option<&str>) -> Value {
    Value::Object(
        DecisionAxis::ALL
            .into_iter()
            .map(|axis| {
                let winner = node.and_then(|node| tree.effective_winner(node, axis));
                (axis.as_str().to_owned(), json!(winner))
            })
            .collect(),
    )
}

/// One team as `tree` reads it: the type it falls under, that type's picks,
/// and the subtypes a split made under it.
fn team_view(tree: &TaskTypeTree, team: &TeamReceipt) -> Value {
    let node = tree.resolve_ref(&TaskTypeRef::from(&team.type_ref));
    let subtypes: Vec<Value> = node
        .map_or_else(Vec::new, |node| tree.children(&node.node_id))
        .into_iter()
        .map(|child| {
            json!({
                "type": child.name,
                "split_on": child.split_axis.map(DecisionAxis::as_str),
                "picks": picks(tree, Some(child.node_id.as_str())),
            })
        })
        .collect();
    json!({
        "pattern": team.pattern.as_str(),
        "models": team.models,
        "type": node.map(|node| node.name.as_str()),
        "picks": picks(tree, node.map(|node| node.node_id.as_str())),
        "subtypes": subtypes,
    })
}

impl HeldOutReplayNotes for TreeReplayScorer<'_> {
    fn judge_revision(&self) -> &str {
        self.inner.judge_revision()
    }

    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        self.inner.decisions()
    }

    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<Value> {
        let Some((_, tree)) = self
            .arms
            .iter()
            .find(|(version, _)| version == case.version)
        else {
            return Err(Error::InvariantViolation(
                "a replay case names neither version of the team-shape revision",
            ));
        };
        let view = self.view(tree, case.held_out_receipts);
        Ok(match self.inner.replay_state(case)? {
            Value::Object(mut state) => {
                state.insert("type_tree".to_owned(), view);
                Value::Object(state)
            }
            replay => json!({"replay": replay, "type_tree": view}),
        })
    }

    fn blind_pairs(&self, task: &str, receipts: &[String]) -> Result<Vec<SkillReplayPair>> {
        self.inner.blind_pairs(task, receipts)
    }

    fn record_decision(
        &self,
        question: &DecisionQuestion,
        decision: &TypedDecision,
        state: &Value,
    ) -> Result<()> {
        self.inner.record_decision(question, decision, state)
    }

    fn honesty_replays(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<HonestyReplay>> {
        self.inner.honesty_replays(case)
    }

    fn human_minutes(&self, case: &HeldOutReplayCase<'_>) -> Result<f64> {
        self.inner.human_minutes(case)
    }

    fn coverage_floor(&self) -> Option<&CoverageFloorComparison> {
        self.inner.coverage_floor()
    }

    fn goal_axes(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<GoalAxisSpec>> {
        self.inner.goal_axes(case)
    }
}

/// The open optimizer-born vault revision of the team-shape skill, with the
/// head it revises.
fn open_revision(vault: &Vault) -> Result<Option<(EntityId, EntityId)>> {
    let mut after = None;
    loop {
        let page = vault.entities_by_type_page(
            crate::registry::ENTITY_TYPE_SKILL,
            after.as_ref(),
            SKILL_PAGE,
        )?;
        for id in &page {
            let Some(record) = vault.get_skill_record(id)? else {
                continue;
            };
            if record.lifecycle_status != SkillLifecycle::Candidate
                || record.approval_status != ClaimApprovalStatus::Proposed
                || record.skill_id != TEAM_SHAPE_SKILL_NAME
                || crate::skill::resident_of(&record)?.is_some()
            {
                continue;
            }
            let rmpv::Value::Map(fields) = &record.provenance else {
                continue;
            };
            let field = |name: &str| {
                fields.iter().find_map(|(key, value)| {
                    (key.as_str() == Some(name))
                        .then(|| value.as_str())
                        .flatten()
                })
            };
            if field(crate::skill_convert::PROVENANCE_BIRTH_KEY) != Some(SKILL_OPTIMIZE_BIRTH_PATH)
            {
                continue;
            }
            if let Some(predecessor) = field(PROVENANCE_OPTIMIZE_OF_ENTITY_KEY)
                .and_then(|hex| EntityId::from_hex(hex).ok())
            {
                return Ok(Some((*id, predecessor)));
            }
        }
        if page.len() < SKILL_PAGE {
            return Ok(None);
        }
        after = page.last().copied();
    }
}

/// Puts the open team-shape revision to the held-out gate under the
/// upkeep's own attempt, with `scorer` reading both trees. An empty reserve
/// or a moved snapshot is [`TreeGateOutcome::Retry`]. A scored verdict is a
/// held-out outcome for the Coach's own edit record; an admitting one, when
/// [`TEAM_SHAPE_GATE_ADMITS`], admits the revision and supersedes the head
/// in one transaction. `None` when no revision is open.
///
/// # Errors
///
/// Storage errors, the scorer's errors and the gate's refusals (each of
/// which wrote its verdict row and closed the proposal).
pub(super) fn drive(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    scorer: &dyn HeldOutReplayNotes,
    receipts: &[TeamReceipt],
    now: u64,
) -> Result<Option<TreeGateOutcome>> {
    let Some((proposal, predecessor)) = open_revision(vault)? else {
        return Ok(None);
    };
    let scorer = TreeReplayScorer::new(vault, scorer, &proposal, &predecessor, receipts)?;
    let verdict = match score_gate_skill_edit_in_cycle(
        vault,
        &proposal,
        &scorer,
        attempt.status.attempt.id,
        now,
    ) {
        Ok(verdict) => verdict,
        Err(Error::Artifact(ArtifactError::SkillEditGateRetry(_))) => {
            return Ok(Some(TreeGateOutcome::Retry));
        }
        Err(error) => return Err(error),
    };
    if !verdict.goal_axes.is_empty() {
        super::coach_learning::record_coach_outcome(
            vault,
            super::coach_learning::COACH_SKILL_EDIT_AXIS,
            format!("skill_edit:{}", proposal.to_hex()),
            now,
            crate::learning::Anchor::HeldOut,
            verdict.after > verdict.before,
            now,
        )?;
    }
    if !(verdict.disposition.admits() && TEAM_SHAPE_GATE_ADMITS) {
        return Ok(Some(TreeGateOutcome::Ruled(verdict.disposition)));
    }
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let refused = vault.with_write_txn_grouped(|txn| {
        if let Some(refusal) = vault.admit_optimized_skill_in_txn(txn, &proposal, occurred, now)? {
            return Ok(Some(refusal));
        }
        vault.supersede_skill_record_in_txn(txn, &predecessor, &proposal, occurred, now)?;
        Ok(None)
    })?;
    Ok(Some(refused.map_or(
        TreeGateOutcome::Admitted(proposal),
        TreeGateOutcome::Refused,
    )))
}
