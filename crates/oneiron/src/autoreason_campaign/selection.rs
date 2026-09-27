//! Read-only DECIDE floor for an experiment campaign over the durable run tree.
//!
//! The caller pins externally measured quality and expected gain to attempt IDs.
//! This module neither runs experiments nor judges/promotes a candidate: a
//! selected parent is a proposal to fork under the existing grant and gate.

use std::collections::{BTreeMap, BTreeSet};

use crate::run_tree::{RunTree, RunTreeNode};

/// An external measurement of one experiment node. Quality is on a
/// campaign-pinned scale (the DGM sigmoid acts on this supplied score).
#[derive(Debug, Clone, PartialEq)]
pub struct MeasuredBranch {
    pub attempt_id: String,
    pub quality: f64,
    /// Predicted gain from trying this branch next, on the campaign's scale.
    pub expected_gain: f64,
}

/// Campaign-specific policy knobs. The caller pins these outside the search.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelectionPolicy {
    pub expected_gain_floor: f64,
    /// Consecutive below-floor rounds before a cause-based stop.
    pub plateau_rounds: usize,
    /// Consecutive rounds without a new top-1 quality before a diversity fork.
    pub stagnation_rounds: usize,
    /// Escalate instead of stopping on a confirmed plateau.
    pub escalate_plateau: bool,
}

/// Fresh, externally anchored evidence for one DECIDE step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleSignal {
    NoSignal,
    /// The external oracle confirms the campaign goal is met.
    GoalMet,
}

/// No writes or resource reservations occur in this decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionDecision {
    /// Select a measured parent by sigmoid(quality) / (1 + direct children).
    Fork { parent_id: String, stagnation: bool },
    /// Resource exhaustion pauses work; it never claims the search failed.
    PausedBudget,
    /// Expected gain remained below the floor for the pinned number of rounds.
    StoppedPlateau,
    /// The same plateau requires an owner decision instead of a stop.
    EscalatePlateau,
    /// An externally confirmed goal, not a self-reported model success.
    StoppedOracle,
}

/// Invalid or ungrounded selection evidence is refused before choosing a parent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    #[error("invalid experiment selection: {0}")]
    Invalid(&'static str),
}

type SelectionResult<T> = std::result::Result<T, SelectionError>;

/// Chooses the next experiment parent or a typed pause/stop outcome.
///
/// `tree` is the already scoped run-tree of this campaign; `branches` names
/// externally measured nodes within it. `prior_best_qualities` and
/// `prior_best_gains` hold earlier completed rounds in chronological order,
/// *excluding* this round. The current bests are derived from `branches`.
/// A caller persists its own measurements/rounds beside the durable attempts;
/// this function never invents an experiment store or treats a cap as a
/// terminal result. Equal weights use attempt ID order, independent of input
/// or tree traversal order.
///
/// # Errors
///
/// Refuses duplicate/unknown nodes, non-finite measurements and histories,
/// missing measurements, or invalid policy bounds.
pub fn decide_experiment(
    tree: &RunTree,
    branches: &[MeasuredBranch],
    prior_best_qualities: &[f64],
    prior_best_gains: &[f64],
    policy: SelectionPolicy,
    budget_available: bool,
    oracle: OracleSignal,
) -> SelectionResult<SelectionDecision> {
    if !policy.expected_gain_floor.is_finite()
        || policy.expected_gain_floor < 0.0
        || policy.plateau_rounds == 0
        || policy.stagnation_rounds == 0
    {
        return Err(SelectionError::Invalid(
            "invalid policy floor or round count",
        ));
    }
    if !tree.repairs.is_empty() {
        return Err(SelectionError::Invalid("repaired run-tree ancestry"));
    }
    if branches.is_empty() {
        return Err(SelectionError::Invalid("no measured branches"));
    }
    if prior_best_qualities.iter().any(|v| !v.is_finite())
        || prior_best_gains.iter().any(|v| !v.is_finite() || *v < 0.0)
    {
        return Err(SelectionError::Invalid(
            "non-finite or negative round history",
        ));
    }
    let mut children = BTreeMap::new();
    for root in &tree.roots {
        collect_children(root, &mut children)?;
    }
    let mut seen = BTreeSet::new();
    for branch in branches {
        if !seen.insert(branch.attempt_id.as_str()) {
            return Err(SelectionError::Invalid("duplicate measured branch"));
        }
        if !children.contains_key(branch.attempt_id.as_str()) {
            return Err(SelectionError::Invalid(
                "measured branch absent from run tree",
            ));
        }
        if !branch.quality.is_finite()
            || !branch.expected_gain.is_finite()
            || branch.expected_gain < 0.0
        {
            return Err(SelectionError::Invalid("invalid branch measurement"));
        }
    }
    let best_quality = branches
        .iter()
        .map(|b| b.quality)
        .fold(f64::NEG_INFINITY, f64::max);
    let best_gain = branches
        .iter()
        .map(|b| b.expected_gain)
        .fold(0.0_f64, f64::max);
    // An explicit external success is a cause; resource depletion is not.
    if oracle == OracleSignal::GoalMet {
        return Ok(SelectionDecision::StoppedOracle);
    }
    if !budget_available {
        return Ok(SelectionDecision::PausedBudget);
    }
    let below_floor = best_gain < policy.expected_gain_floor;
    let previous_below = prior_best_gains
        .iter()
        .rev()
        .take_while(|gain| **gain < policy.expected_gain_floor)
        .count();
    if below_floor && previous_below >= policy.plateau_rounds - 1 {
        return Ok(if policy.escalate_plateau {
            SelectionDecision::EscalatePlateau
        } else {
            SelectionDecision::StoppedPlateau
        });
    }
    // A top-1 plateau forces a fork from a different measured parent where
    // possible; failures remain in the tree and count toward child pressure.
    let mut previous_best = best_quality;
    let stagnant = prior_best_qualities
        .iter()
        .rev()
        .take_while(|quality| {
            let no_improvement = previous_best <= **quality;
            previous_best = **quality;
            no_improvement
        })
        .count()
        >= policy.stagnation_rounds;
    let top_id = branches
        .iter()
        .filter(|b| b.quality == best_quality)
        .map(|b| b.attempt_id.as_str())
        .min()
        .ok_or(SelectionError::Invalid("no top branch"))?;
    let alternate_exists = branches.iter().any(|b| b.attempt_id != top_id);
    let parent = branches
        .iter()
        .filter(|b| !stagnant || !alternate_exists || b.attempt_id != top_id)
        .max_by(|a, b| {
            let weight = |branch: &MeasuredBranch| {
                // 1/(1+child_count) is computed in f64 to avoid integer overflow.
                sigmoid(branch.quality) / (1.0 + children[branch.attempt_id.as_str()] as f64)
            };
            weight(a)
                .total_cmp(&weight(b))
                .then_with(|| b.attempt_id.cmp(&a.attempt_id))
        })
        .ok_or(SelectionError::Invalid("no selectable branch"))?;
    Ok(SelectionDecision::Fork {
        parent_id: parent.attempt_id.clone(),
        stagnation: stagnant,
    })
}

fn collect_children<'a>(
    node: &'a RunTreeNode,
    counts: &mut BTreeMap<&'a str, usize>,
) -> SelectionResult<()> {
    if counts
        .insert(&node.attempt_id, node.children.len())
        .is_some()
    {
        return Err(SelectionError::Invalid("duplicate run-tree node"));
    }
    for child in &node.children {
        collect_children(child, counts)?;
    }
    Ok(())
}

fn sigmoid(value: f64) -> f64 {
    // This form keeps large negative quality finite without exp overflow.
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let exp = value.exp();
        exp / (1.0 + exp)
    }
}

#[cfg(test)]
mod tests;
