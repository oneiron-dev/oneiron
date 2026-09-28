//! Read-only DECIDE floor for an experiment campaign over the durable run tree.
//!
//! The caller pins externally measured quality and expected gain to attempt IDs.
//! This module neither runs experiments nor judges/promotes a candidate: a
//! selected parent is a proposal to fork under the existing grant and gate.

use std::collections::{BTreeMap, BTreeSet};

use crate::run_tree::{RunTree, RunTreeNode};
use serde::{Deserialize, Serialize};

/// An external measurement of one experiment node. Quality is on a
/// campaign-pinned scale (the DGM sigmoid acts on this supplied score).
#[derive(Debug, Clone, PartialEq)]
pub struct MeasuredBranch {
    pub attempt_id: String,
    pub quality: f64,
    /// Predicted gain from trying this branch next, on the campaign's scale.
    pub expected_gain: f64,
}

/// Campaign-specific policy knobs resolved from trusted vault manifest rows.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPolicy {
    pub expected_gain_floor: f64,
    /// Consecutive below-floor rounds before a cause-based stop.
    pub plateau_rounds: usize,
    /// Consecutive rounds without a new top-1 quality before a diversity fork.
    pub stagnation_rounds: usize,
    /// The action on top-1 stagnation, chosen by resolved vault policy.
    pub stagnation_action: StagnationAction,
    /// Escalate instead of stopping on a confirmed plateau.
    pub escalate_plateau: bool,
}

/// Row-selected response to a top-1 quality plateau.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagnationAction {
    /// Choose the DGM maximum even if it is the current top-quality branch.
    Dgm,
    /// Exclude the top-quality branch when another parent is measured.
    Diversify,
}

/// Scope of a manifest decision row: vault, campaign, or holder in a campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPolicyScope {
    pub campaign_id: Option<String>,
    pub holder_id: Option<String>,
}

/// Vault-row choice of how campaign and holder policies compose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionPrecedence {
    /// Campaign narrows vault, holder narrows campaign (shipped default).
    #[default]
    NestedNarrowing,
    /// Holder supersedes the campaign row, but cannot widen the vault row.
    HolderUnderVault,
}

/// A policy-manifest row. Every row is capped by the vault row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPolicyRow {
    pub scope: SelectionPolicyScope,
    pub policy: SelectionPolicy,
    /// Only the vault row may select precedence; absent means nested narrowing.
    #[serde(default)]
    pub precedence: SelectionPrecedence,
}

impl SelectionPolicyRow {
    pub(crate) fn valid(&self) -> bool {
        self.scope
            .campaign_id
            .as_ref()
            .is_none_or(|id| !id.trim().is_empty())
            && self
                .scope
                .holder_id
                .as_ref()
                .is_none_or(|id| !id.trim().is_empty())
            && (self.scope.holder_id.is_none() || self.scope.campaign_id.is_some())
            && (self.scope.campaign_id.is_none()
                || self.precedence == SelectionPrecedence::NestedNarrowing)
            && self.policy.valid()
    }
}

impl SelectionPolicy {
    pub(crate) fn valid(self) -> bool {
        self.expected_gain_floor.is_finite()
            && self.expected_gain_floor >= 0.0
            && self.plateau_rounds > 0
            && self.stagnation_rounds > 0
    }

    /// Narrower rows cannot lower the gain floor or delay a check. A vault
    /// request to diversify cannot be undone by a holder-scoped row.
    pub(crate) fn narrow(self, row: Self) -> Self {
        Self {
            expected_gain_floor: self.expected_gain_floor.max(row.expected_gain_floor),
            plateau_rounds: self.plateau_rounds.min(row.plateau_rounds),
            stagnation_rounds: self.stagnation_rounds.min(row.stagnation_rounds),
            stagnation_action: if self.stagnation_action == StagnationAction::Diversify
                || row.stagnation_action == StagnationAction::Diversify
            {
                StagnationAction::Diversify
            } else {
                StagnationAction::Dgm
            },
            escalate_plateau: self.escalate_plateau || row.escalate_plateau,
        }
    }
}

/// Reads the trusted, scoped campaign policy through the same manifest fold
/// that governs other vault policy. Missing/malformed rows fail closed.
///
/// # Errors
///
/// Propagates storage and manifest errors or refuses an absent vault row.
pub fn selection_policy_for(
    vault: &crate::Vault,
    campaign_id: &str,
    holder_id: Option<&str>,
) -> crate::Result<SelectionPolicy> {
    if campaign_id.trim().is_empty() || holder_id.is_some_and(|id| id.trim().is_empty()) {
        return Err(crate::Error::InvalidConfig(
            "invalid experiment policy scope".into(),
        ));
    }
    let txn = vault.store.env.read_txn()?;
    crate::gate::resolve_policy_manifest(&vault.store, &txn)?
        .experiment_selection_policy(campaign_id, holder_id)
        .ok_or_else(|| crate::Error::InvalidConfig("missing experiment selection policy".into()))
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

/// The public DECIDE door. Reads the policy from trusted, vault-resident
/// manifest rows rather than accepting a caller-supplied action or floor.
/// The caller supplies measured evidence and a campaign-scoped run tree;
/// neither an oracle signal nor a choice returned here authorizes a write.
///
/// # Errors
///
/// Refuses missing/malformed policy, storage errors and ungrounded evidence.
#[expect(clippy::too_many_arguments)]
pub fn decide_experiment_for(
    vault: &crate::Vault,
    campaign_id: &str,
    holder_id: Option<&str>,
    tree: &RunTree,
    branches: &[MeasuredBranch],
    prior_best_qualities: &[f64],
    prior_best_gains: &[f64],
    budget_available: bool,
    oracle: OracleSignal,
) -> crate::Result<SelectionDecision> {
    let policy = selection_policy_for(vault, campaign_id, holder_id)?;
    decide_experiment(
        tree,
        branches,
        prior_best_qualities,
        prior_best_gains,
        policy,
        budget_available,
        oracle,
    )
    .map_err(|error| crate::Error::InvalidConfig(error.to_string()))
}

/// Pure DECIDE mechanism over an already-resolved policy.
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
pub(crate) fn decide_experiment(
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
        .filter(|b| {
            !stagnant
                || policy.stagnation_action == StagnationAction::Dgm
                || !alternate_exists
                || b.attempt_id != top_id
        })
        .max_by(|a, b| {
            let log_weight = |branch: &MeasuredBranch| {
                // Compare in log space: finite negative quality can make the
                // sigmoid underflow to zero, but the order must remain exact.
                log_sigmoid(branch.quality)
                    - (1.0 + children[branch.attempt_id.as_str()] as f64).ln()
            };
            log_weight(a)
                .total_cmp(&log_weight(b))
                // At saturation, equal children still rank by quality;
                // equal quality still ranks by inverse child count.
                .then_with(|| {
                    if a.quality == b.quality {
                        children[b.attempt_id.as_str()].cmp(&children[a.attempt_id.as_str()])
                    } else if children[a.attempt_id.as_str()] == children[b.attempt_id.as_str()] {
                        a.quality.total_cmp(&b.quality)
                    } else {
                        std::cmp::Ordering::Equal
                    }
                })
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

fn log_sigmoid(value: f64) -> f64 {
    if value >= 0.0 {
        -(-value).exp().ln_1p()
    } else {
        value - value.exp().ln_1p()
    }
}

#[cfg(test)]
mod tests;
