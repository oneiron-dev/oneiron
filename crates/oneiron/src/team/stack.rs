//! Stacking (ARCH-0079 #stacking): a sub-project may run a different pattern
//! from its parent, and every node with children has a referee that picks
//! among the children's results. Each node is scored at equal budget against
//! its alternatives, never the whole stack at once. A losing branch rolls
//! back but stays archived, so its outputs remain available: this module
//! names the winner and the losers; the project owner rolls back and the
//! output archive keeps them.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// One child branch's refereed result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BranchResult {
    pub project: EntityId,
    /// What the branch spent, in the parent's budget unit.
    pub spend: f64,
    /// The node referee's score.
    pub score: f64,
}

/// The node's decision.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeComparison {
    pub winner: EntityId,
    /// Branches to roll back and archive, best first.
    pub losers: Vec<EntityId>,
    /// The budget every compared branch ran at.
    pub budget: f64,
}

/// Compares sibling branches at equal budget. Branches whose spend differs
/// from the largest by more than `tolerance` (a share, such as 0.05) are not
/// comparable and are refused rather than silently scored against richer
/// siblings. Ties go to the smaller project id, so the call is deterministic.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for fewer than two branches, a non-finite
/// number, a negative tolerance or unequal budgets.
pub fn compare_at_equal_budget(branches: &[BranchResult], tolerance: f64) -> Result<NodeComparison> {
    if branches.len() < 2 {
        return Err(Error::InvalidClaimBody("a node compares at least two branches"));
    }
    if !tolerance.is_finite() || tolerance < 0.0 {
        return Err(Error::InvalidClaimBody("a budget tolerance is a non-negative share"));
    }
    if branches
        .iter()
        .any(|b| !b.spend.is_finite() || b.spend < 0.0 || !b.score.is_finite())
    {
        return Err(Error::InvalidClaimBody("branch spend and score are finite"));
    }
    let budget = branches.iter().map(|b| b.spend).fold(0.0_f64, f64::max);
    if branches
        .iter()
        .any(|b| budget - b.spend > budget * tolerance)
    {
        return Err(Error::InvalidClaimBody(
            "siblings are compared at equal budget; rerun the short branch",
        ));
    }
    let mut ranked: Vec<&BranchResult> = branches.iter().collect();
    ranked.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.project.cmp(&b.project)));
    Ok(NodeComparison {
        winner: ranked[0].project,
        losers: ranked[1..].iter().map(|b| b.project).collect(),
        budget,
    })
}
