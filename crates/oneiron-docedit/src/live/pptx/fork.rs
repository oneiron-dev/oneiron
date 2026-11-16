//! A machine fork of the live deck and its landing: the fork's base and
//! stamped operations (`DeckFork`), the preflight report over the candidate
//! a landing would make, the approval scope, and the landing itself
//! (`land`).

use super::{DeckDiff, LiveDeck, NodeId, StampedOp, merge, unit_changed};
use crate::live::LiveError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A machine fork: the base it opened at and its actual stamped operations.
/// The fork joins a proposal by the shared proposal id; the proposer (and
/// its lineage) never settles it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckFork {
    pub proposal: String,
    pub proposer: String,
    /// The run that opened the fork, for the run approve-all scope.
    pub run_root: Option<String>,
    pub base_version: u64,
    pub base: LiveDeck,
    pub ops: Vec<StampedOp>,
}

impl LiveDeck {
    /// Open a fork at the current head. The agent writes the fork, never
    /// the live document.
    pub fn fork_at(&self, proposal: &str, proposer: &str, run_root: Option<&str>) -> DeckFork {
        DeckFork {
            proposal: proposal.to_owned(),
            proposer: proposer.to_owned(),
            run_root: run_root.map(str::to_owned),
            base_version: self.version,
            base: self.clone(),
            ops: Vec::new(),
        }
    }
}

impl DeckFork {
    pub fn record(&mut self, op: StampedOp) {
        self.ops.push(op);
    }

    /// The proposal state: the base with the fork's own operations applied.
    pub fn candidate(&self) -> Result<LiveDeck, LiveError> {
        let mut deck = self.base.clone();
        for op in &self.ops {
            deck.apply(op)?;
        }
        Ok(deck)
    }

    /// Nodes this fork touches that the head changed since the base: the
    /// units whose answers the race rule withdraws (ARCH-0075 section 4).
    pub fn stale_units(&self, head: &LiveDeck) -> Vec<NodeId> {
        let touched: BTreeSet<NodeId> = self.ops.iter().filter_map(|op| op.op.target()).collect();
        touched
            .into_iter()
            .filter(|node| unit_changed(&self.base, head, *node))
            .collect()
    }
}

/// The scratch-candidate check before any merge: the fork's actual
/// operations replayed onto the current head. Operations are never
/// cherry-picked and merging is never replaced with a rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    /// The head version this preflight ran against; landing requires it.
    pub head_version: u64,
    pub candidate: LiveDeck,
    pub diff: DeckDiff,
    pub replay_refusals: Vec<String>,
    pub ok: bool,
}

/// The three ruled approve-all scopes. A finer scope is a later addition
/// and does not delay these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApproveScope {
    /// The named actor's bundle.
    ThisActor(String),
    /// The run root and everything its children proposed.
    ThisRunAndChildren(String),
    /// One item within the reviewed set, by its proposal id.
    OneItem(String),
}

impl ApproveScope {
    /// Whether this approval covers `fork`. Later forks never inherit an
    /// earlier approval: the scope names its set exactly.
    pub fn covers(&self, fork: &DeckFork) -> bool {
        match self {
            ApproveScope::ThisActor(actor) => fork.proposer == *actor,
            ApproveScope::ThisRunAndChildren(run) => fork.run_root.as_deref() == Some(run),
            ApproveScope::OneItem(proposal) => fork.proposal == *proposal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Landing {
    Merge,
    Switch,
}

/// The receipt a landing mints: decision scope, versions and actual
/// affected units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandingReceipt {
    pub proposal: String,
    pub proposer: String,
    pub settler: String,
    pub scope: ApproveScope,
    pub landing: Landing,
    pub automatic: bool,
    pub reviewed_version: u64,
    pub landed_version: u64,
    pub affected: Vec<NodeId>,
    /// Head-only nodes a switch removed; empty for a merge.
    pub switched_away: Vec<NodeId>,
}

/// Land a preflighted fork. The proposer never settles its own proposal,
/// and the head must be the one the preflight ran against.
pub fn land(
    head: &mut LiveDeck,
    fork: &DeckFork,
    report: &PreflightReport,
    settler: &str,
    scope: ApproveScope,
    landing: Landing,
    automatic: bool,
) -> Result<LandingReceipt, LiveError> {
    if settler == fork.proposer {
        return Err(LiveError::SelfSettle);
    }
    if head.version != report.head_version {
        return Err(LiveError::HeadAdvanced);
    }
    if !report.ok {
        return Err(LiveError::Invalid("preflight conflicts are unresolved"));
    }
    if !scope.covers(fork) {
        return Err(LiveError::Invalid(
            "the approval scope does not cover this fork",
        ));
    }
    let reviewed_version = head.version;
    let mut affected: BTreeSet<NodeId> = BTreeSet::new();
    affected.extend(report.diff.added.iter().copied());
    affected.extend(report.diff.removed.iter().copied());
    affected.extend(report.diff.moved.iter().map(|moved| moved.node));
    affected.extend(report.diff.text_changed.iter().copied());
    affected.extend(report.diff.formatting_changed.iter().copied());
    affected.extend(report.diff.geometry_changed.iter().copied());
    affected.extend(report.diff.payload_changed.iter().copied());
    let switched_away = match landing {
        Landing::Merge => {
            *head = report.candidate.clone();
            Vec::new()
        }
        Landing::Switch => {
            let mut proposal = fork.candidate()?;
            // Bindings and the hashes of opaque parts the proposal left alone
            // are evidence of the head's retained package, which a landed
            // export may have moved past the fork's base.
            for (id, node) in &mut proposal.nodes {
                if let Some(held) = head.nodes.get(id) {
                    node.binding = held.binding.clone();
                }
            }
            for (part, hash) in &mut proposal.opaque_parts {
                if fork.base.opaque_parts.get(part) == Some(hash)
                    && let Some(held) = head.opaque_parts.get(part)
                {
                    *hash = *held;
                }
            }
            let (version, next_node) = (head.version, head.next_node);
            proposal.id_marks.join(&head.id_marks);
            // What this switch takes off the head, read from the deck it lands.
            let lost = merge::switch_losses(&fork.base, head, &proposal);
            *head = proposal;
            // Identity allocation stays monotonic across the switch.
            head.next_node = head.next_node.max(next_node);
            head.version = version + 1;
            lost
        }
    };
    Ok(LandingReceipt {
        proposal: fork.proposal.clone(),
        proposer: fork.proposer.clone(),
        settler: settler.to_owned(),
        scope,
        landing,
        automatic,
        reviewed_version,
        landed_version: head.version,
        affected: affected.into_iter().collect(),
        switched_away,
    })
}
