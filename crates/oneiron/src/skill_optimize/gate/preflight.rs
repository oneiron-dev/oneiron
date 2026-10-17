//! A proposal's offline floors, judged on the held-out set before any live
//! run is routed to it (ARCH-0053: "Offline axes run on the held-out set
//! first. Online axes run through the bandit slice with a confidence bound.").
//!
//! [`preflight_skill_edit_offline_floors`] scores the offline part of the
//! goal's plan (each floor and cost axis but human minutes) and the honesty
//! floor on the same reserved evidence, and keeps the result bound to both
//! bodies, that evidence and the goal revision. It passes when no floor's
//! proposal score is below the incumbent's: the gate's own floor test. An
//! exploration trial opens only on a passed preflight. A failed one is the
//! gate's evidence in place of a live report, so a regressing floor rejects
//! before any live run is spent on it.
use super::*;
use crate::learning::honesty::HONESTY_AXIS;
use crate::side_table::Named;
use crate::skill_optimize::AxisScores;
use crate::workspace_roster::GoalExplorationBudget;
use serde::{Deserialize, Serialize};

const PREFLIGHTS: SideTable<EntityId, PreflightRow, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_PREFLIGHT);

const fn retry(reason: &'static str) -> Error {
    Error::Artifact(crate::error::ArtifactError::SkillEditGateRetry(reason))
}

/// What a preflight was judged on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightBasis {
    proposal_digest: String,
    target_digest: String,
    evidence_digest: String,
    goal_revision: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightRow {
    basis: PreflightBasis,
    offline: Vec<(String, AxisScores)>,
    honesty: AxisScores,
    passed: bool,
}

/// A proposal's offline preflight on its current basis.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillEditPreflight {
    /// No floor regressed, the honesty floor included.
    pub passed: bool,
    /// The goal revision the floors were judged under.
    pub goal_revision: String,
    /// Each offline floor and cost axis, scored on the held-out set.
    pub offline: Vec<(String, AxisScores)>,
    /// The honesty floor, from the same held-out replays.
    pub honesty: AxisScores,
}

impl From<PreflightRow> for SkillEditPreflight {
    fn from(row: PreflightRow) -> Self {
        Self {
            passed: row.passed,
            goal_revision: row.basis.goal_revision,
            offline: row.offline,
            honesty: row.honesty,
        }
    }
}

/// What a live trial of an open proposal binds, read in one snapshot: the
/// proposal, the skill it revises, both body digests, the goal revision and
/// the project goal record the goal joins, whose budget funds the trial.
#[derive(Debug, Clone)]
pub(crate) struct SkillEditTrialBasis {
    pub(crate) proposal: SkillRecord,
    pub(crate) target: EntityId,
    pub(crate) proposal_digest: String,
    pub(crate) target_digest: String,
    pub(crate) goal_revision: String,
    pub(crate) project: EntityId,
    pub(crate) goal_claim: EntityId,
    pub(crate) budget: GoalExplorationBudget,
}

/// A score validated into 0..=1, which an f32 holds: the precision the
/// gate's floor test compares in.
#[allow(clippy::cast_possible_truncation)]
fn narrow(score: f64) -> f32 {
    score as f32
}

fn basis_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    staged: &SkillRecord,
    target: &EntityId,
    current: &SkillRecord,
) -> Result<(PreflightBasis, GoalDefinition, Vec<String>)> {
    let definition = goal_definition_in_txn(vault, txn, target)?;
    let held_out = held_out_receipts_in_txn(vault, txn, target)?;
    let basis = PreflightBasis {
        proposal_digest: skill_body_binding_digest(staged)?,
        target_digest: skill_body_binding_digest(current)?,
        evidence_digest: evidence_identity(&held_out).1,
        goal_revision: definition.revision.clone(),
    };
    Ok((basis, definition, held_out))
}

/// Judge `proposal`'s offline floors on the held-out set and keep the result,
/// or return the kept result while it still binds both bodies, the reserved
/// evidence and the goal revision. No live run is pulled here.
/// # Errors
/// A proposal that is not an open optimizer proposal of the current skill it
/// revises, missing held-out evidence, scorer errors, and the retryable
/// outcome when a body, the evidence or the goal moved while scoring.
pub fn preflight_skill_edit_offline_floors(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
) -> Result<SkillEditPreflight> {
    let txn = vault.store.env.read_txn()?;
    let staged = vault.read_skill_record_in_txn(&txn, proposal)?;
    require_open_optimizer_proposal(&staged)?;
    let target = target_of(&staged)?;
    let current = vault.read_skill_record_in_txn(&txn, &target)?;
    if !target_is_current(&staged, &current) {
        return Err(invalid(
            "an offline preflight needs the current skill the proposal revises",
        ));
    }
    let (basis, definition, held_out) = basis_in_txn(vault, &txn, &staged, &target, &current)?;
    if let Some(row) = PREFLIGHTS.get(&vault.store, &txn, proposal)?
        && row.basis == basis
    {
        return Ok(row.into());
    }
    drop(txn);
    if held_out.is_empty() {
        return Err(invalid("an offline preflight requires held-out evidence"));
    }
    let plan = super::live::goal_axis_plan(&definition, 0);
    let offline = crate::skill_optimize::goal_axes::score_offline_goal_axes(
        target,
        &current,
        &staged,
        &plan.offline,
        &held_out,
        scorer,
    )?;
    let before = HeldOutReplayCase {
        skill: target,
        skill_id: &current.skill_id,
        version: &current.version,
        instructions: &current.desc,
        held_out_receipts: &held_out,
    };
    let after = HeldOutReplayCase {
        skill: target,
        skill_id: &staged.skill_id,
        version: &staged.version,
        instructions: &staged.desc,
        held_out_receipts: &held_out,
    };
    let honesty = super::measurement::measure_honesty(scorer, &before, &after)?;
    let floor = |name: &str| {
        definition
            .axes
            .iter()
            .any(|axis| axis.name == name && axis.kind == GoalAxisKind::Floor)
    };
    let passed = honesty.after >= honesty.before
        && offline.iter().all(|(name, scores)| {
            !floor(name.as_str()) || narrow(scores.after) >= narrow(scores.before)
        });
    let row = PreflightRow {
        basis,
        offline,
        honesty: AxisScores {
            before: f64::from(honesty.before),
            after: f64::from(honesty.after),
        },
        passed,
    };
    vault.with_write_txn_grouped(|txn| {
        let staged_now = vault.read_skill_record_in_txn(txn, proposal)?;
        let current_now = vault.read_skill_record_in_txn(txn, &target)?;
        let (now, _, _) = basis_in_txn(vault, txn, &staged_now, &target, &current_now)?;
        if now != row.basis {
            return Err(retry(
                "a body, the reserved evidence or the goal moved while the offline floors were judged",
            ));
        }
        PREFLIGHTS.put(&vault.store, txn, proposal, &row)
    })?;
    Ok(row.into())
}

/// The trial basis of `proposal` in the caller's snapshot. `None` unless it
/// is an open optimizer proposal that still revises its current skill
/// (active, same skill and resident, the version it was drafted against, a
/// version of its own) and its goal joins a project's goal record.
/// # Errors
/// An unreadable skill, goal or project goal record, or storage errors.
pub(crate) fn skill_edit_trial_basis_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: &EntityId,
) -> Result<Option<SkillEditTrialBasis>> {
    let staged = vault.read_skill_record_in_txn(txn, proposal)?;
    if require_open_optimizer_proposal(&staged).is_err() {
        return Ok(None);
    }
    let target = target_of(&staged)?;
    let current = vault.read_skill_record_in_txn(txn, &target)?;
    if !target_is_current(&staged, &current) || staged.version == current.version {
        return Ok(None);
    }
    let definition = goal_definition_in_txn(vault, txn, &target)?;
    let Some(join) = definition.project else {
        return Ok(None);
    };
    Ok(Some(SkillEditTrialBasis {
        proposal_digest: skill_body_binding_digest(&staged)?,
        target_digest: skill_body_binding_digest(&current)?,
        proposal: staged,
        target,
        goal_revision: definition.revision,
        project: join.project,
        goal_claim: join.goal_claim,
        budget: join.record.exploration_budget,
    }))
}

/// Whether `proposal`'s kept preflight passed on `basis` and on the reserved
/// evidence of the skill it revises in this snapshot.
/// # Errors
/// An unreadable row, or storage errors.
pub(crate) fn skill_edit_preflight_passed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal: &EntityId,
    basis: &SkillEditTrialBasis,
) -> Result<bool> {
    let Some(row) = PREFLIGHTS.get(&vault.store, txn, proposal)? else {
        return Ok(false);
    };
    let evidence = evidence_identity(&held_out_receipts_in_txn(vault, txn, &basis.target)?).1;
    Ok(row.passed
        && row.basis
            == PreflightBasis {
                proposal_digest: basis.proposal_digest.clone(),
                target_digest: basis.target_digest.clone(),
                evidence_digest: evidence,
                goal_revision: basis.goal_revision.clone(),
            })
}

/// A failed preflight's scores for the gate's vector, while it binds the
/// scored `basis`: each offline floor and cost axis and the honesty floor.
/// No trial ran, so its regressing floor is the gate's rejection with no
/// live report to wait on.
/// # Errors
/// An unreadable row, a row naming an axis the goal lacks, or storage errors.
pub(super) fn failed_preflight_axes(
    vault: &Vault,
    proposal: &EntityId,
    basis: &ScoredBasis,
    definition: &GoalDefinition,
) -> Result<Option<BTreeMap<String, GoalAxisScore>>> {
    let txn = vault.store.env.read_txn()?;
    let row = PREFLIGHTS.get(&vault.store, &txn, proposal)?;
    drop(txn);
    let Some(row) = row.filter(|row| {
        !row.passed
            && row.basis
                == PreflightBasis {
                    proposal_digest: basis.proposal_digest.clone(),
                    target_digest: basis.target_digest.clone(),
                    evidence_digest: basis.evidence_digest.clone(),
                    goal_revision: basis.goal_revision.clone(),
                }
    }) else {
        return Ok(None);
    };
    let mut measured = BTreeMap::new();
    let honesty = (HONESTY_AXIS.to_owned(), row.honesty);
    for (name, scores) in row.offline.iter().chain(std::iter::once(&honesty)) {
        let kind = definition
            .axes
            .iter()
            .find(|axis| &axis.name == name)
            .map(|axis| axis.kind)
            .ok_or(Error::CorruptedIndex("skill offline preflight row"))?;
        measured.insert(
            name.clone(),
            GoalAxisScore {
                kind,
                before: narrow(scores.before),
                after: narrow(scores.after),
            },
        );
    }
    Ok(Some(measured))
}
