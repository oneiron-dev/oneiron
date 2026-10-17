//! The payoff table and the planner card (ARCH-0003 #learning-views,
//! ARCH-0079 #scoring, #works-well-for).
//!
//! The payoff table is a view over team receipts, keyed by task type,
//! pattern, model ids, team shape and who decided, with coverage and
//! confession counts. Confessions are control evidence beside the row, never
//! a payoff input. The coordination-cost breakdown sits beside elapsed time
//! and calls as a diagnostic. The planner card is the view the planner reads
//! at spawn: this task type's payoff rows and each candidate pattern skill's
//! estimate, own runs, origin and UNTESTED mark, ranked by the shared
//! posterior's mean plus its exploration bonus.

use std::collections::BTreeMap;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::{LearningRead, TypeRef, coordination_cost, read_learning};

use super::pattern::{PatternSkill, TeamPattern, model_mix, pattern_cell, pattern_skill};
use super::receipt::{TeamReceipt, team_receipts};

/// The exploration weight of the planner card's ranking, the same derivation
/// the skill selector uses.
pub const PATTERN_EXPLORATION: f64 = 0.25;

/// One payoff row.
#[derive(Debug, Clone, PartialEq)]
pub struct PayoffRow {
    pub type_ref: TypeRef,
    pub pattern: TeamPattern,
    pub pattern_skill: Option<EntityId>,
    pub models: String,
    pub shape: String,
    pub decided_by: String,
    pub teams: u64,
    /// Teams whose anchored outcome succeeded or failed; the rest are open.
    pub wins: u64,
    pub losses: u64,
    pub mean_spend: Option<f64>,
    pub mean_elapsed_secs: f64,
    /// Mean calls, over teams whose calls the host counted.
    pub mean_calls: Option<f64>,
    /// Mean share of cells covered, over teams that report coverage.
    pub mean_coverage: Option<f64>,
    /// Confessions, summed over teams whose confessions the host counted.
    pub confessions: u64,
    /// Agent-seconds waiting, by reason, summed over the row's teams.
    pub wait_by_reason: BTreeMap<String, u64>,
    pub mean_reuse_delay_secs: Option<f64>,
    pub duplicate_work: u64,
}

#[derive(Default)]
struct Acc {
    teams: u64,
    wins: u64,
    losses: u64,
    spend_sum: f64,
    spend_n: u64,
    elapsed_sum: f64,
    calls_sum: f64,
    calls_n: u64,
    coverage_sum: f64,
    coverage_n: u64,
    confessions: u64,
    wait: BTreeMap<String, u64>,
    reuse_sum: f64,
    reuse_n: u64,
    duplicates: u64,
}

type RowKey = (
    TypeRef,
    TeamPattern,
    Option<EntityId>,
    String,
    String,
    String,
);

fn row_key(receipt: &TeamReceipt) -> RowKey {
    (
        receipt.type_ref.clone(),
        receipt.pattern,
        receipt.pattern_skill.as_ref().map(|s| s.skill),
        model_mix(&receipt.models),
        receipt.shape.signature(),
        receipt.decided_by.kind().to_owned(),
    )
}

/// The payoff table, optionally for one task type.
///
/// # Errors
///
/// Storage errors.
pub fn payoff_table(vault: &Vault, type_ref: Option<&TypeRef>) -> Result<Vec<PayoffRow>> {
    let mut rows: BTreeMap<RowKey, Acc> = BTreeMap::new();
    for receipt in team_receipts(vault, type_ref)? {
        let acc = rows.entry(row_key(&receipt)).or_default();
        acc.teams += 1;
        match receipt.outcome.as_ref().map(|o| o.success) {
            Some(true) => acc.wins += 1,
            Some(false) => acc.losses += 1,
            None => {}
        }
        if let Some(spend) = receipt.spend {
            acc.spend_sum += spend;
            acc.spend_n += 1;
        }
        #[allow(clippy::cast_precision_loss)]
        let elapsed = receipt.elapsed_secs as f64;
        acc.elapsed_sum += elapsed;
        if let Some(calls) = receipt.calls {
            #[allow(clippy::cast_precision_loss)]
            let calls = calls as f64;
            acc.calls_sum += calls;
            acc.calls_n += 1;
        }
        if let Some(coverage) = receipt.coverage
            && coverage.cells_total > 0
        {
            acc.coverage_sum += f64::from(coverage.cells_filled) / f64::from(coverage.cells_total);
            acc.coverage_n += 1;
        }
        acc.confessions += receipt.confessions.map_or(0, u64::from);
        if let Some(cost) = coordination_cost(vault, &receipt.team_ref)? {
            for (reason, secs) in cost.wait_by_reason {
                *acc.wait.entry(reason).or_insert(0) += secs;
            }
            for delay in &cost.reuse_delays {
                #[allow(clippy::cast_precision_loss)]
                let secs = delay.delay as f64;
                acc.reuse_sum += secs;
                acc.reuse_n += 1;
            }
            acc.duplicates += cost.duplicate_work.len() as u64;
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let mean = |sum: f64, n: u64| (n > 0).then(|| sum / n as f64);
    Ok(rows
        .into_iter()
        .map(
            |((type_ref, pattern, pattern_skill, models, shape, decided_by), acc)| {
                #[allow(clippy::cast_precision_loss)]
                let teams = acc.teams.max(1) as f64;
                PayoffRow {
                    type_ref,
                    pattern,
                    pattern_skill,
                    models,
                    shape,
                    decided_by,
                    teams: acc.teams,
                    wins: acc.wins,
                    losses: acc.losses,
                    mean_spend: mean(acc.spend_sum, acc.spend_n),
                    mean_elapsed_secs: acc.elapsed_sum / teams,
                    mean_calls: mean(acc.calls_sum, acc.calls_n),
                    mean_coverage: mean(acc.coverage_sum, acc.coverage_n),
                    confessions: acc.confessions,
                    wait_by_reason: acc.wait,
                    mean_reuse_delay_secs: mean(acc.reuse_sum, acc.reuse_n),
                    duplicate_work: acc.duplicates,
                }
            },
        )
        .collect())
}

/// One candidate pattern on the planner card.
#[derive(Debug, Clone, PartialEq)]
pub struct PatternCardEntry {
    pub skill: EntityId,
    pub binding: Option<PatternSkill>,
    /// The estimate in force: own runs, else a parent type's or another
    /// executor mix's, else the `works well for` prior, else shipped.
    pub read: LearningRead,
    /// Mean plus the exploration bonus over the card's total own runs.
    pub score: f64,
}

/// What the planner reads at spawn for one task type.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannerCard {
    pub type_ref: TypeRef,
    pub executor_mix: String,
    pub rows: Vec<PayoffRow>,
    /// Highest score first; ties by skill id.
    pub patterns: Vec<PatternCardEntry>,
}

/// Builds the planner card for `type_ref` and an executor mix, ranking the
/// candidate pattern skills by the shared posterior. `type_parents` is the
/// type's ancestry from its parent up to the root.
///
/// # Errors
///
/// Storage errors.
pub fn planner_card(
    vault: &Vault,
    type_ref: &TypeRef,
    type_parents: &[TypeRef],
    models: &[String],
    candidates: &[EntityId],
) -> Result<PlannerCard> {
    let executor_mix = model_mix(models);
    let mut entries = Vec::with_capacity(candidates.len());
    for skill in candidates {
        let cell = pattern_cell(*skill, &executor_mix, type_ref);
        let read = read_learning(vault, &cell, type_parents)?;
        entries.push(PatternCardEntry {
            skill: *skill,
            binding: pattern_skill(vault, skill)?,
            read,
            score: 0.0,
        });
    }
    let total: f64 = entries.iter().map(|e| e.read.estimate.runs).sum();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let total = (total.ceil() as u64).max(1);
    for entry in &mut entries {
        entry.score =
            entry.read.estimate.mean() + entry.read.estimate.bonus(total, PATTERN_EXPLORATION);
    }
    entries.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.skill.cmp(&b.skill))
    });
    Ok(PlannerCard {
        type_ref: type_ref.clone(),
        executor_mix,
        rows: payoff_table(vault, Some(type_ref))?,
        patterns: entries,
    })
}
