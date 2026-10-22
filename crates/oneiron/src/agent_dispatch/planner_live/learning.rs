//! The measured reads the live planner weighs, and what a thin project leaf
//! borrows into them (FIX 5496; ARCH-0079 #task-type: thin leaves borrow).
//!
//! On a spawn stamped on a thin live leaf of a project's own tree, on a path
//! the vault's stored tree in force holds exactly, each measured cell the
//! plan reads (solo reliability, each pattern skill's reliability, each
//! width's anchored team outcomes) reads its own evidence plus `q` times the
//! same cell keyed at the vault tree's type for that node, with `q` the
//! shared fade ([`donor_weight`]). The primary read keeps its prior once,
//! a borrowed backoff included; only the donor cell's measured outcomes are
//! added, never its prior, and never as own runs. The blend lives in the
//! plan's evidence alone: nothing is stored. A donor read that fails drops
//! the whole overlay, and the plan reads what it read before.

use std::collections::BTreeMap;

use crate::Vault;
use crate::dreamer_runner::maintenance::type_tree_prior::donor_weight;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::read::measured_outcomes_in_txn;
use crate::learning::{EstimateValue, LearningCell, LearningRead, TypeRef};
use crate::llm::ModelId;
use crate::posterior::beta_mean;
use crate::task_type::{TaskTypeTree, TreeScope};
use crate::team::{PlannerCard, pattern_cell};

use super::super::planner::{MeasuredRate, PatternCandidate};
use super::super::task_type_tree::load_team_type_tree_in_txn;
use super::width_outcomes::WidthOutcomes;

/// What a spawn's stamp borrows: the vault tree's learning type for the same
/// node, and the weight its measured outcomes carry.
pub(super) struct Donor {
    type_ref: TypeRef,
    weight: f64,
}

impl Donor {
    /// The donor `own`, a stamp current in `tree`, borrows from in `txn`:
    /// the vault's stored tree in force, wherever [`donor_weight`] lends.
    /// `None` on a vault tree, a node that is not a thin live leaf on the
    /// donor's exact live path, or a vault tree that does not read; the plan
    /// then reads its own cells alone.
    ///
    /// Key alias: when the project's type for the node and the vault tree's
    /// are one learning type (the same node at the same version), the own
    /// cell and the donor cell are one key, and the own read already holds
    /// every run the donor would lend. Nothing is lent, so no run counts
    /// twice.
    pub(super) fn for_stamp(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        tree: &TaskTypeTree,
        own: &TypeRef,
    ) -> Option<Self> {
        // A vault tree borrows from nothing; it needs no second load.
        if !matches!(tree.scope, TreeScope::Project { .. }) {
            return None;
        }
        let donor = load_team_type_tree_in_txn(vault, txn, None).ok()?;
        let weight = donor_weight(tree, &own.node_id, &donor).filter(|weight| *weight > 0.0)?;
        let type_ref = TypeRef::from(&donor.type_ref(&own.node_id));
        (type_ref != *own).then_some(Self { type_ref, weight })
    }

    /// The solo rates and pattern candidates with the donor lent, staged
    /// over the primary reads: `solo` per seat model with its cell, `cards`
    /// per seat model, and `patterns` as they read. Only admitted pattern
    /// skills and the seats' own executor mixes borrow. Width outcomes come
    /// from `outcomes`, the plan's one receipt snapshot, folded at its one
    /// evaluation time (FIX 9568), then taken at the borrow weight.
    ///
    /// # Errors
    ///
    /// Any donor read that fails; the caller keeps its primary reads.
    pub(super) fn lend(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        solo: &[(ModelId, LearningCell, LearningRead)],
        cards: &[(ModelId, PlannerCard)],
        patterns: &[PatternCandidate],
        outcomes: &WidthOutcomes,
    ) -> Result<(BTreeMap<ModelId, MeasuredRate>, Vec<PatternCandidate>)> {
        let mut rates = BTreeMap::new();
        for (model, cell, read) in solo {
            let rate = self.rate(vault, txn, cell, read)?;
            rates.insert(model.clone(), rate.unwrap_or_else(|| measured(read)));
        }
        let mut patterns = patterns.to_vec();
        if cards.is_empty() {
            return Ok((rates, patterns));
        }
        for (model, card) in cards {
            for entry in &card.patterns {
                let cell = pattern_cell(entry.skill, &card.executor_mix, &card.type_ref);
                if let Some(rate) = self.rate(vault, txn, &cell, &entry.read)?
                    && let Some(candidate) = admitted(&mut patterns, entry.skill)
                {
                    candidate.rates.insert(model.clone(), rate);
                }
            }
            for ((skill, width), (wins, losses)) in outcomes.folded(&self.type_ref, card) {
                if let Some(candidate) = admitted(&mut patterns, skill) {
                    let lent = candidate
                        .borrowed_widths
                        .entry(width)
                        .or_default()
                        .entry(model.clone())
                        .or_insert((0.0, 0.0));
                    lent.0 += self.weight * wins;
                    lent.1 += self.weight * losses;
                }
            }
        }
        Ok((rates, patterns))
    }

    /// `read`, the primary read of `cell`, with the donor cell's measured
    /// outcomes added at the borrow weight: `mean = (a + q*w) / (a + b +
    /// q*(w + l))` over the read's Beta `(a, b)`, own runs unchanged, and
    /// `q*(w + l)` more weight. `None` where the donor cell has no own head,
    /// or `read` is no success estimate; the primary read then stands.
    fn rate(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        cell: &LearningCell,
        read: &LearningRead,
    ) -> Result<Option<MeasuredRate>> {
        let EstimateValue::Beta { alpha, beta } = &read.estimate.value else {
            return Ok(None);
        };
        let donor = cell.with_type(Some(self.type_ref.clone()));
        let Some((wins, losses)) = measured_outcomes_in_txn(vault, txn, &donor)? else {
            return Ok(None);
        };
        let (wins, losses) = (self.weight * wins, self.weight * losses);
        Ok(Some(MeasuredRate {
            mean: beta_mean(alpha + wins, beta + losses),
            own_runs: if read.own { read.estimate.runs } else { 0.0 },
            weight_runs: read.estimate.runs + read.estimate.prior.weight_runs + wins + losses,
        }))
    }
}

/// A learning read as the planner weighs it.
pub(super) fn measured(read: &LearningRead) -> MeasuredRate {
    MeasuredRate {
        mean: read.estimate.mean(),
        own_runs: if read.own { read.estimate.runs } else { 0.0 },
        weight_runs: read.estimate.runs + read.estimate.prior.weight_runs,
    }
}

/// The admitted candidate for `skill`, if the plan admitted it.
pub(super) fn admitted(
    patterns: &mut [PatternCandidate],
    skill: EntityId,
) -> Option<&mut PatternCandidate> {
    patterns
        .iter_mut()
        .find(|candidate| candidate.skill.skill == skill)
}
