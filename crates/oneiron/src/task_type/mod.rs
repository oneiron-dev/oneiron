//! ONE TASK TYPE (OF-543, ARCH-0079 #task-type): the one learned type tree.
//!
//! "What kind of task is this?" has one answer, read by everyone: the model
//! router, the planner, critic records and the `learning.*` task-type key all
//! read the same [`TaskTypeRef`] stamp. Every spawn and task receipt carries
//! a `typeRef` — `{node_id, tree_version}` — a missing type is invalid, never
//! untyped, and an unsure placement uses the root.
//!
//! The tree is learned data (it rides inside the team-shape skill, OF-541, so
//! it forks and merges like one; this module is the value vocabulary and the
//! upkeep operations over it). Seven seed types start it. A type splits only
//! when its tasks disagree on a decision read from the tree — the winning
//! pattern, the winning model, or the critic to trust — never by topic.
//! Siblings that agree merge back. A thin leaf borrows its parent's prior.
//! One vault tree is shared until a project's receipts diverge from the
//! vault's winners, then the project forks; a domain known to be different
//! seeds a fork at birth, and a leaf that holds up on held-out receipts
//! elsewhere is promoted upstream through the merge-back.
//!
//! Retrieval's `intent_class` is a different question and stays with
//! retrieval — nothing here reads or writes it.

mod placement;

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

pub use placement::{
    HEURISTIC_PLACEMENT_EXECUTOR, HEURISTIC_PLACEMENT_VERSION, PLACEMENT_QUESTION,
    PLACEMENT_SKILL_ID, PlacementDecisions, PlacementOutcome, PlacementRequest, ensure_type_ref,
    place_task, require_type_ref,
};

/// The one wire/value type for a type stamp (L08 contract, OF-540/OF-184/
/// OF-397): re-exported from `learning`, never redefined here.
/// [`TaskTypeRef`] is the spawn/task/receipt stamp spelling of the same
/// `{node_id, tree_version}` pair; the `From` impls below convert between
/// them (the receipt stamp keeps a `u64` version, the learning cell a
/// `u32`).
pub use crate::learning::{ROOT_TYPE_NODE, TypeRef};

/// The seven seed node ids, all children of the root, in canon order.
pub const SEED_TYPES: [&str; 7] = [
    "generate",
    "refine",
    "solve",
    "research",
    "judge",
    "build",
    "negotiate",
];

/// The root node id: every unsure placement lands here.
pub const ROOT_NODE_ID: &str = "root";

/// The derived-id domain of a node's [`EntityId`] spelling
/// ([`TaskTypeNode::entity_id`]). Parts: the node id.
const TYPE_NODE_ID_DOMAIN: &[u8] = b"oneiron.task_type.node.v1";

/// The tree version [`TaskTypeTree::seeded`] starts at.
pub const SEEDED_TREE_VERSION: u64 = 1;

/// A leaf with fewer receipts than this borrows its parent's prior.
pub const THIN_LEAF_MIN_RECEIPTS: u64 = 8;

/// Decision runs each side needs before a disagreement can split a type.
pub const SPLIT_MIN_RUNS_PER_WINNER: u64 = 3;

/// Held-out runs a leaf needs before it can be promoted upstream.
pub const PROMOTE_MIN_HELD_OUT_RUNS: u64 = 8;

/// The seven hand seed types that start the tree (ARCH-0079).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedTaskType {
    Generate,
    Refine,
    Solve,
    Research,
    Judge,
    Build,
    Negotiate,
}

impl SeedTaskType {
    /// Every seed type, in canon order.
    pub const ALL: [Self; 7] = [
        Self::Generate,
        Self::Refine,
        Self::Solve,
        Self::Research,
        Self::Judge,
        Self::Build,
        Self::Negotiate,
    ];

    /// Stable node-id / wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::Refine => "refine",
            Self::Solve => "solve",
            Self::Research => "research",
            Self::Judge => "judge",
            Self::Build => "build",
            Self::Negotiate => "negotiate",
        }
    }

    /// Parses a seed token; `None` for the root and for learned nodes.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|seed| seed.as_str() == token)
    }

    /// The seed node's id in any seeded tree.
    #[must_use]
    pub const fn node_id(self) -> &'static str {
        self.as_str()
    }
}

impl fmt::Display for SeedTaskType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The one stamp: a node in one version of the type tree.
///
/// Carried by every spawn (`agent_dispatch`) and every task/spawn receipt.
/// Wire form is `"<node_id>@<tree_version>"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TaskTypeRef {
    pub node_id: String,
    pub tree_version: u64,
}

impl TaskTypeRef {
    /// A ref to `node_id` at `tree_version`.
    #[must_use]
    pub fn new(node_id: impl Into<String>, tree_version: u64) -> Self {
        Self {
            node_id: node_id.into(),
            tree_version,
        }
    }

    /// The unsure answer: the root at `tree_version`.
    #[must_use]
    pub fn root(tree_version: u64) -> Self {
        Self::new(ROOT_NODE_ID, tree_version)
    }

    /// The root of a freshly seeded tree.
    #[must_use]
    pub fn seeded_root() -> Self {
        Self::root(SEEDED_TREE_VERSION)
    }

    /// A seed node at `tree_version`.
    #[must_use]
    pub fn seed(seed: SeedTaskType, tree_version: u64) -> Self {
        Self::new(seed.node_id(), tree_version)
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.node_id == ROOT_NODE_ID
    }

    /// The seed this ref names, when it names one.
    #[must_use]
    pub fn seed_type(&self) -> Option<SeedTaskType> {
        SeedTaskType::parse(&self.node_id)
    }

    /// Canonical wire form: `"<node_id>@<tree_version>"`.
    #[must_use]
    pub fn wire_form(&self) -> String {
        format!("{}@{}", self.node_id, self.tree_version)
    }

    /// Parses the [`Self::wire_form`]. A bare node id (no `@version`) is
    /// refused: an unversioned stamp cannot be read against any tree.
    pub fn parse_wire(wire: &str) -> Result<Self> {
        let Some((node_id, version)) = wire.rsplit_once('@') else {
            return Err(invalid_type_ref("typeRef must be node_id@tree_version"));
        };
        if node_id.is_empty() {
            return Err(invalid_type_ref("typeRef node_id must not be empty"));
        }
        let tree_version = version
            .parse::<u64>()
            .map_err(|_| invalid_type_ref("typeRef tree_version must be an integer"))?;
        Ok(Self::new(node_id, tree_version))
    }
}

impl Default for TaskTypeRef {
    fn default() -> Self {
        Self::seeded_root()
    }
}

impl fmt::Display for TaskTypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.wire_form())
    }
}

pub(crate) fn invalid_type_ref(reason: &'static str) -> Error {
    Error::InvariantViolation(reason)
}

/// A decision read from the tree. Splits follow disagreement on one of
/// these axes — never topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAxis {
    WinningPattern,
    WinningModel,
    TrustedCritic,
}

impl DecisionAxis {
    pub const ALL: [Self; 3] = [
        Self::WinningPattern,
        Self::WinningModel,
        Self::TrustedCritic,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WinningPattern => "winning_pattern",
            Self::WinningModel => "winning_model",
            Self::TrustedCritic => "trusted_critic",
        }
    }

    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|axis| axis.as_str() == token)
    }
}

/// One observed decision outcome under a type: `winner` won on `axis`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionObservation {
    pub axis: DecisionAxis,
    pub winner: String,
}

impl DecisionObservation {
    #[must_use]
    pub fn new(axis: DecisionAxis, winner: impl Into<String>) -> Self {
        Self {
            axis,
            winner: winner.into(),
        }
    }
}

/// Which tree this is: the one vault tree, or one project's fork of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TreeScope {
    Vault,
    Project {
        /// Lower-hex project entity id, when the fork names one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project_ref: Option<String>,
        /// The vault tree version this fork was cut from.
        forked_from_version: u64,
        /// True when the fork was seeded at the project's birth (a domain
        /// known to be different), false when divergent receipts earned it.
        seeded_at_birth: bool,
    },
}

/// One node of the learned tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskTypeNode {
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<SeedTaskType>,
    /// The decision this node was split out on, when a split made it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_axis: Option<DecisionAxis>,
    /// The winner value this split child collects, when a split made it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_winner: Option<String>,
    /// Set when this node merged away; old receipts resolve through it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merged_into: Option<String>,
    #[serde(default)]
    pub receipt_count: u64,
    #[serde(default)]
    pub held_out_runs: u64,
    #[serde(default)]
    pub held_out_wins: u64,
    /// Observed decision wins: axis token -> winner -> run count.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub decision_wins: BTreeMap<String, BTreeMap<String, u64>>,
}

impl TaskTypeNode {
    fn new(node_id: &str, parent: Option<&str>, name: &str, seed: Option<SeedTaskType>) -> Self {
        Self {
            node_id: node_id.to_owned(),
            parent: parent.map(str::to_owned),
            name: name.to_owned(),
            seed,
            split_axis: None,
            split_winner: None,
            merged_into: None,
            receipt_count: 0,
            held_out_runs: 0,
            held_out_wins: 0,
            decision_wins: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn is_live(&self) -> bool {
        self.merged_into.is_none()
    }

    /// This node's [`EntityId`] spelling, the one a TASK brief's `type_ref`
    /// names it by: derived from the node id, so the vault tree and every
    /// fork that holds the node spell it alike.
    pub fn entity_id(&self) -> Result<EntityId> {
        EntityId::derive(TYPE_NODE_ID_DOMAIN, &[self.node_id.as_bytes()])
    }

    /// True while this leaf's own data is too thin to read decisions from.
    #[must_use]
    pub fn is_thin(&self) -> bool {
        self.receipt_count < THIN_LEAF_MIN_RECEIPTS
    }

    /// Run count recorded for one winner on one axis.
    #[must_use]
    pub fn wins(&self, axis: DecisionAxis, winner: &str) -> u64 {
        self.decision_wins
            .get(axis.as_str())
            .and_then(|by_winner| by_winner.get(winner))
            .copied()
            .unwrap_or(0)
    }

    /// The clear winner on an axis: a strict leader with at least
    /// [`SPLIT_MIN_RUNS_PER_WINNER`] runs. Ties and thin data read `None`.
    #[must_use]
    pub fn clear_winner(&self, axis: DecisionAxis) -> Option<&str> {
        let by_winner = self.decision_wins.get(axis.as_str())?;
        let mut best: Option<(&str, u64)> = None;
        let mut tied = false;
        for (winner, runs) in by_winner {
            match best {
                Some((_, best_runs)) if *runs == best_runs => tied = true,
                Some((_, best_runs)) if *runs < best_runs => {}
                _ => {
                    best = Some((winner, *runs));
                    tied = false;
                }
            }
        }
        match best {
            Some((winner, runs)) if !tied && runs >= SPLIT_MIN_RUNS_PER_WINNER => Some(winner),
            _ => None,
        }
    }

    /// True when two winners on one axis each carry enough runs that the
    /// node's tasks genuinely disagree on that decision.
    #[must_use]
    pub fn disagrees_on(&self, axis: DecisionAxis) -> bool {
        self.decision_wins
            .get(axis.as_str())
            .is_some_and(|by_winner| {
                by_winner
                    .values()
                    .filter(|runs| **runs >= SPLIT_MIN_RUNS_PER_WINNER)
                    .count()
                    >= 2
            })
    }
}

/// A node whose receipts disagree on one decision: the upkeep split input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitCandidate {
    pub node_id: String,
    pub axis: DecisionAxis,
    pub winners: Vec<String>,
}

/// The outcome of offering a project leaf back upstream (merge-back).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PromotionOutcome {
    /// Held-out wins carried it; the upstream tree now has the leaf.
    Promoted(TaskTypeRef),
    /// Not enough held-out runs to judge yet; the fork keeps the leaf.
    HeldOutInsufficient,
    /// Held-out runs did not hold up elsewhere; the fork keeps the leaf.
    NotUsefulUpstream,
}

/// The shared, versioned, learned task-type tree.
///
/// Bumps `version` on every structural change (split, merge, fork,
/// promotion) so a receipt's `tree_version` names the exact tree its
/// placement was read from. Receipt/decision counts are evidence, not
/// structure, and do not bump the version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskTypeTree {
    pub version: u64,
    pub scope: TreeScope,
    pub nodes: BTreeMap<String, TaskTypeNode>,
}

impl Default for TaskTypeTree {
    fn default() -> Self {
        Self::seeded()
    }
}

impl TaskTypeTree {
    /// The vault tree as shipped: the root plus the seven seed types.
    #[must_use]
    pub fn seeded() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            ROOT_NODE_ID.to_owned(),
            TaskTypeNode::new(ROOT_NODE_ID, None, "any task", None),
        );
        for seed in SeedTaskType::ALL {
            nodes.insert(
                seed.node_id().to_owned(),
                TaskTypeNode::new(
                    seed.node_id(),
                    Some(ROOT_NODE_ID),
                    seed.as_str(),
                    Some(seed),
                ),
            );
        }
        Self {
            version: SEEDED_TREE_VERSION,
            scope: TreeScope::Vault,
            nodes,
        }
    }

    /// A birth fork for a domain known to be different: the seeded shape,
    /// scoped to one project from its first receipt.
    #[must_use]
    pub fn seeded_for_project(project_ref: Option<String>) -> Self {
        let mut tree = Self::seeded();
        tree.scope = TreeScope::Project {
            project_ref,
            forked_from_version: SEEDED_TREE_VERSION,
            seeded_at_birth: true,
        };
        tree
    }

    /// The root stamp at this tree's current version.
    #[must_use]
    pub fn root_ref(&self) -> TaskTypeRef {
        TaskTypeRef::root(self.version)
    }

    /// A stamp for `node_id` at this tree's current version.
    #[must_use]
    pub fn type_ref(&self, node_id: &str) -> TaskTypeRef {
        TaskTypeRef::new(node_id, self.version)
    }

    #[must_use]
    pub fn node(&self, node_id: &str) -> Option<&TaskTypeNode> {
        self.nodes.get(node_id)
    }

    /// The node an [`EntityId`] spelling names, resolved through this tree
    /// ([`TaskTypeNode::entity_id`]); `None` when this tree holds no such
    /// node.
    #[must_use]
    pub fn node_by_entity(&self, id: EntityId) -> Option<&TaskTypeNode> {
        self.nodes
            .values()
            .find(|node| node.entity_id().is_ok_and(|node_id| node_id == id))
    }

    /// Resolves a stamped ref to its live node, following `merged_into`
    /// links so a receipt written before a merge still reads. Version is
    /// deliberately not checked here: old receipts keep their old version.
    #[must_use]
    pub fn resolve_ref(&self, type_ref: &TaskTypeRef) -> Option<&TaskTypeNode> {
        let mut node = self.nodes.get(&type_ref.node_id)?;
        while let Some(into) = &node.merged_into {
            node = self.nodes.get(into)?;
        }
        Some(node)
    }

    /// Validates a ref being stamped NOW: the node must be live in this
    /// tree and the version must be this tree's current version.
    pub fn validate_current_ref(&self, type_ref: &TaskTypeRef) -> Result<()> {
        if type_ref.node_id.is_empty() {
            return Err(invalid_type_ref("typeRef node_id must not be empty"));
        }
        if type_ref.tree_version != self.version {
            return Err(invalid_type_ref(
                "typeRef tree_version is not the current tree version",
            ));
        }
        match self.nodes.get(&type_ref.node_id) {
            Some(node) if node.is_live() => Ok(()),
            Some(_) => Err(invalid_type_ref("typeRef names a merged-away node")),
            None => Err(invalid_type_ref("typeRef names a node outside the tree")),
        }
    }

    /// Live children of a node, in node-id order.
    #[must_use]
    pub fn children(&self, node_id: &str) -> Vec<&TaskTypeNode> {
        self.nodes
            .values()
            .filter(|node| node.is_live() && node.parent.as_deref() == Some(node_id))
            .collect()
    }

    #[must_use]
    pub fn is_leaf(&self, node_id: &str) -> bool {
        self.children(node_id).is_empty()
    }

    /// The node whose priors a decision read should use: the node itself
    /// once it has enough receipts, else the nearest non-thin ancestor
    /// (the root when every ancestor is thin). Thin leaves borrow parents.
    #[must_use]
    pub fn effective_prior_ref(&self, node_id: &str) -> TaskTypeRef {
        let mut cursor = self.nodes.get(node_id);
        while let Some(node) = cursor {
            if !node.is_thin() || node.parent.is_none() {
                return self.type_ref(&node.node_id);
            }
            cursor = node
                .parent
                .as_ref()
                .and_then(|parent| self.nodes.get(parent));
        }
        self.root_ref()
    }

    /// The winner to read for one decision under `node_id`, borrowing the
    /// effective prior node's winner while the leaf is thin.
    #[must_use]
    pub fn effective_winner(&self, node_id: &str, axis: DecisionAxis) -> Option<&str> {
        let prior = self.effective_prior_ref(node_id);
        self.nodes.get(&prior.node_id)?.clear_winner(axis)
    }

    /// Records one placed task receipt and the decisions it observed.
    pub fn record_receipt(
        &mut self,
        type_ref: &TaskTypeRef,
        decisions: &[DecisionObservation],
    ) -> Result<()> {
        let node_id = self
            .resolve_ref(type_ref)
            .map(|node| node.node_id.clone())
            .ok_or_else(|| invalid_type_ref("receipt typeRef names a node outside the tree"))?;
        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or_else(|| invalid_type_ref("receipt typeRef names a node outside the tree"))?;
        node.receipt_count = node.receipt_count.saturating_add(1);
        for decision in decisions {
            *node
                .decision_wins
                .entry(decision.axis.as_str().to_owned())
                .or_default()
                .entry(decision.winner.clone())
                .or_default() += 1;
        }
        Ok(())
    }

    /// Records one held-out check of a leaf elsewhere (merge-back evidence).
    pub fn record_held_out(&mut self, node_id: &str, won: bool) -> Result<()> {
        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| invalid_type_ref("held-out node is outside the tree"))?;
        node.held_out_runs = node.held_out_runs.saturating_add(1);
        if won {
            node.held_out_wins = node.held_out_wins.saturating_add(1);
        }
        Ok(())
    }

    /// Every live node whose tasks disagree on a decision — the Coach
    /// type-tree-upkeep recipe's split work list.
    #[must_use]
    pub fn split_candidates(&self) -> Vec<SplitCandidate> {
        let mut candidates = Vec::new();
        for node in self.nodes.values() {
            if !node.is_live() {
                continue;
            }
            for axis in DecisionAxis::ALL {
                if node.disagrees_on(axis) {
                    let winners = node
                        .decision_wins
                        .get(axis.as_str())
                        .map(|by_winner| {
                            by_winner
                                .iter()
                                .filter(|(_, runs)| **runs >= SPLIT_MIN_RUNS_PER_WINNER)
                                .map(|(winner, _)| winner.clone())
                                .collect()
                        })
                        .unwrap_or_default();
                    candidates.push(SplitCandidate {
                        node_id: node.node_id.clone(),
                        axis,
                        winners,
                    });
                }
            }
        }
        candidates
    }

    /// Splits one node on a decision its tasks disagree on: one child per
    /// qualifying winner. Bumps the tree version. Refused when the node
    /// does not actually disagree on `axis` — splits follow decisions,
    /// never topic, so there is no split-by-name path.
    pub fn split(&mut self, node_id: &str, axis: DecisionAxis) -> Result<Vec<TaskTypeRef>> {
        let winners: Vec<String> = {
            let node = self
                .nodes
                .get(node_id)
                .ok_or_else(|| invalid_type_ref("split node is outside the tree"))?;
            if !node.is_live() {
                return Err(invalid_type_ref("split node has merged away"));
            }
            if !node.disagrees_on(axis) {
                return Err(invalid_type_ref(
                    "a type splits only when its tasks disagree on a decision",
                ));
            }
            node.decision_wins
                .get(axis.as_str())
                .map(|by_winner| {
                    by_winner
                        .iter()
                        .filter(|(_, runs)| **runs >= SPLIT_MIN_RUNS_PER_WINNER)
                        .map(|(winner, _)| winner.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut created = Vec::new();
        for winner in winners {
            let child_id = format!("{node_id}/{}={}", axis.as_str(), slug(&winner));
            if self.nodes.contains_key(&child_id) {
                continue;
            }
            let mut child = TaskTypeNode::new(
                &child_id,
                Some(node_id),
                &format!("{node_id} where {} is {winner}", axis.as_str()),
                None,
            );
            child.split_axis = Some(axis);
            child.split_winner = Some(winner);
            self.nodes.insert(child_id.clone(), child);
            created.push(child_id);
        }
        if created.is_empty() {
            return Err(invalid_type_ref("split produced no new child type"));
        }
        self.version = self.version.saturating_add(1);
        Ok(created
            .iter()
            .map(|child_id| self.type_ref(child_id))
            .collect())
    }

    /// True when two live siblings read the same on every decision axis:
    /// wherever both have a clear winner, the winners match.
    #[must_use]
    pub fn siblings_agree(&self, a: &str, b: &str) -> bool {
        let (Some(a), Some(b)) = (self.nodes.get(a), self.nodes.get(b)) else {
            return false;
        };
        if !a.is_live() || !b.is_live() || a.parent.is_none() || a.parent != b.parent {
            return false;
        }
        DecisionAxis::ALL.iter().all(
            |axis| match (a.clear_winner(*axis), b.clear_winner(*axis)) {
                (Some(left), Some(right)) => left == right,
                _ => true,
            },
        )
    }

    /// Merges two agreeing siblings back into their parent: counts fold up,
    /// both children stay as `merged_into` tombstones so old receipts keep
    /// resolving. Bumps the tree version and returns the parent's ref.
    pub fn merge_siblings(&mut self, a: &str, b: &str) -> Result<TaskTypeRef> {
        if !self.siblings_agree(a, b) {
            return Err(invalid_type_ref(
                "siblings merge only when they agree on every decision",
            ));
        }
        let parent_id = self
            .nodes
            .get(a)
            .and_then(|node| node.parent.clone())
            .ok_or_else(|| invalid_type_ref("merge siblings have no parent"))?;
        for child_id in [a, b] {
            let folded = self
                .nodes
                .get(child_id)
                .map(|node| {
                    (
                        node.receipt_count,
                        node.held_out_runs,
                        node.held_out_wins,
                        node.decision_wins.clone(),
                    )
                })
                .ok_or_else(|| invalid_type_ref("merge sibling is outside the tree"))?;
            let parent = self
                .nodes
                .get_mut(&parent_id)
                .ok_or_else(|| invalid_type_ref("merge parent is outside the tree"))?;
            parent.receipt_count = parent.receipt_count.saturating_add(folded.0);
            parent.held_out_runs = parent.held_out_runs.saturating_add(folded.1);
            parent.held_out_wins = parent.held_out_wins.saturating_add(folded.2);
            for (axis, by_winner) in folded.3 {
                let target = parent.decision_wins.entry(axis).or_default();
                for (winner, runs) in by_winner {
                    *target.entry(winner).or_default() += runs;
                }
            }
            let child = self
                .nodes
                .get_mut(child_id)
                .ok_or_else(|| invalid_type_ref("merge sibling is outside the tree"))?;
            child.merged_into = Some(parent_id.clone());
        }
        self.version = self.version.saturating_add(1);
        Ok(self.type_ref(&parent_id))
    }

    /// True when this (project) tree's clear winners diverge from the
    /// vault tree's on any shared live node — the fork trigger.
    #[must_use]
    pub fn diverges_from(&self, vault: &Self) -> bool {
        self.nodes
            .values()
            .filter(|node| node.is_live())
            .any(|node| {
                let Some(upstream) = vault.nodes.get(&node.node_id) else {
                    return false;
                };
                DecisionAxis::ALL.iter().any(|axis| {
                    matches!(
                        (node.clear_winner(*axis), upstream.clear_winner(*axis)),
                        (Some(mine), Some(theirs)) if mine != theirs
                    )
                })
            })
    }

    /// Forks this tree for one project. The fork carries the current shape
    /// and evidence; from here its versions advance independently.
    #[must_use]
    pub fn fork_for_project(&self, project_ref: Option<String>, seeded_at_birth: bool) -> Self {
        Self {
            version: self.version.saturating_add(1),
            scope: TreeScope::Project {
                project_ref,
                forked_from_version: self.version,
                seeded_at_birth,
            },
            nodes: self.nodes.clone(),
        }
    }

    /// Offers one leaf of this project fork back to `upstream`: promoted
    /// only when its held-out wins outnumber its held-out losses over at
    /// least [`PROMOTE_MIN_HELD_OUT_RUNS`] runs ("useful upstream?").
    pub fn promote_leaf_to(&self, upstream: &mut Self, node_id: &str) -> Result<PromotionOutcome> {
        let leaf = self
            .nodes
            .get(node_id)
            .filter(|node| node.is_live())
            .ok_or_else(|| invalid_type_ref("promotion leaf is outside the fork"))?;
        if leaf.held_out_runs < PROMOTE_MIN_HELD_OUT_RUNS {
            return Ok(PromotionOutcome::HeldOutInsufficient);
        }
        if leaf.held_out_wins.saturating_mul(2) <= leaf.held_out_runs {
            return Ok(PromotionOutcome::NotUsefulUpstream);
        }
        if upstream.nodes.contains_key(node_id) {
            return Ok(PromotionOutcome::Promoted(upstream.type_ref(node_id)));
        }
        upstream.nodes.insert(node_id.to_owned(), leaf.clone());
        upstream.version = upstream.version.saturating_add(1);
        Ok(PromotionOutcome::Promoted(upstream.type_ref(node_id)))
    }
}

impl From<&TaskTypeRef> for TypeRef {
    fn from(stamp: &TaskTypeRef) -> Self {
        Self {
            node_id: stamp.node_id.clone(),
            tree_version: u32::try_from(stamp.tree_version).unwrap_or(u32::MAX),
        }
    }
}

impl From<&TypeRef> for TaskTypeRef {
    fn from(type_ref: &TypeRef) -> Self {
        Self::new(type_ref.node_id.clone(), u64::from(type_ref.tree_version))
    }
}

/// The decision a split keys on, in the vocabulary OF-540's payoff
/// projector reports per-type winner disagreement in. Splits and merges
/// key on this, never on topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitDecision {
    Pattern,
    Model,
    Critic,
}

impl SplitDecision {
    pub const ALL: [Self; 3] = [Self::Pattern, Self::Model, Self::Critic];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pattern => "pattern",
            Self::Model => "model",
            Self::Critic => "critic",
        }
    }

    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == token)
    }

    /// The tree-internal decision axis this names.
    #[must_use]
    pub const fn axis(self) -> DecisionAxis {
        match self {
            Self::Pattern => DecisionAxis::WinningPattern,
            Self::Model => DecisionAxis::WinningModel,
            Self::Critic => DecisionAxis::TrustedCritic,
        }
    }
}

impl From<DecisionAxis> for SplitDecision {
    fn from(axis: DecisionAxis) -> Self {
        match axis {
            DecisionAxis::WinningPattern => Self::Pattern,
            DecisionAxis::WinningModel => Self::Model,
            DecisionAxis::TrustedCritic => Self::Critic,
        }
    }
}

/// The type tree in force, in the `learning` [`TypeRef`] spelling OF-540,
/// OF-184 and OF-397 read. Wraps the learned [`TaskTypeTree`] value; its
/// owner is the wrapped tree's [`TreeScope`] (the vault, or one project's
/// fork keyed by that project's `EntityId` hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeTree {
    inner: TaskTypeTree,
}

impl TypeTree {
    /// The seeded vault tree (version 1): root plus [`SEED_TYPES`].
    #[must_use]
    pub fn seeded() -> Self {
        Self {
            inner: TaskTypeTree::seeded(),
        }
    }

    #[must_use]
    pub fn version(&self) -> u32 {
        u32::try_from(self.inner.version).unwrap_or(u32::MAX)
    }

    /// The unsure placement in this tree: its root.
    #[must_use]
    pub fn root(&self) -> TypeRef {
        TypeRef::root(self.version())
    }

    /// Whether `r` names a node of this tree at this tree's version.
    #[must_use]
    pub fn contains(&self, r: &TypeRef) -> bool {
        r.tree_version == self.version() && self.inner.nodes.contains_key(&r.node_id)
    }

    /// Parents of `r`, parent first, up to and including the root, all at
    /// this tree's version. `r` itself is excluded, so the result feeds
    /// `learning::read_learning(.., type_parents)` directly. An unknown
    /// node has no ancestors here.
    #[must_use]
    pub fn ancestors(&self, r: &TypeRef) -> Vec<TypeRef> {
        let mut chain = Vec::new();
        let mut cursor = self
            .inner
            .nodes
            .get(&r.node_id)
            .and_then(|node| node.parent.clone());
        while let Some(node_id) = cursor {
            let Some(node) = self.inner.nodes.get(&node_id) else {
                break;
            };
            chain.push(TypeRef {
                node_id: node_id.clone(),
                tree_version: self.version(),
            });
            cursor = node.parent.clone();
        }
        chain
    }

    /// Live children of `r`'s node, in node-id order.
    #[must_use]
    pub fn children(&self, r: &TypeRef) -> Vec<TypeRef> {
        self.inner
            .children(&r.node_id)
            .into_iter()
            .map(|node| TypeRef {
                node_id: node.node_id.clone(),
                tree_version: self.version(),
            })
            .collect()
    }

    /// The wrapped learned tree (split/merge/fork/promote live there).
    #[must_use]
    pub const fn task_type_tree(&self) -> &TaskTypeTree {
        &self.inner
    }
}

impl From<TaskTypeTree> for TypeTree {
    fn from(inner: TaskTypeTree) -> Self {
        Self { inner }
    }
}

impl From<TypeTree> for TaskTypeTree {
    fn from(tree: TypeTree) -> Self {
        tree.inner
    }
}

/// The tree in force for a project (OF-541): the one live tree task
/// create, spawn dispatch and the planner read, stored as data inside the
/// team-shape skill ([`crate::agent_dispatch::load_team_type_tree`]): the
/// project's admitted fork, else the vault skill's newest admitted
/// revision, else the seed tree. `None` is the vault tree.
pub fn type_tree(vault: &crate::Vault, project: Option<EntityId>) -> Result<TypeTree> {
    Ok(TypeTree::from(crate::agent_dispatch::load_team_type_tree(
        vault, project,
    )?))
}

/// Missing is invalid, never untyped; an unknown node, a merged-away one,
/// or a version past the tree in force is invalid. A stamp keeps the
/// version it was placed at, so one read at an earlier version of the live
/// tree still validates while the tree holds its node. (The argument is a
/// required [`TypeRef`], so a caller with no stamp cannot call this at
/// all.)
pub fn validate_type_ref(
    vault: &crate::Vault,
    project: Option<EntityId>,
    r: &TypeRef,
) -> Result<()> {
    r.validate()?;
    let tree = type_tree(vault, project)?;
    let stamp = TaskTypeRef::from(r);
    if stamp.tree_version >= tree.inner.version {
        return tree.inner.validate_current_ref(&stamp);
    }
    match tree.inner.node(&stamp.node_id) {
        Some(_) => Ok(()),
        None => Err(invalid_type_ref("typeRef names a node outside the tree")),
    }
}

/// One routed typed judgment at spawn: places `request` against the tree
/// in force and returns the stamp in the learning spelling. Unsure
/// resolves to the tree root, never to `None`. With the host's
/// `decisions`, the placement ladder routes past the skill's rule rung;
/// without them, the rule rung reads alone ([`place_task`]).
pub fn place_type_ref(
    vault: &crate::Vault,
    project: Option<EntityId>,
    request: &PlacementRequest,
    decisions: Option<&PlacementDecisions<'_>>,
) -> Result<TypeRef> {
    let tree = type_tree(vault, project)?;
    let outcome = place_task(&tree.inner, request, decisions);
    Ok(TypeRef::from(&outcome.type_ref))
}

/// Node-id-safe spelling of a decision winner.
fn slug(winner: &str) -> String {
    winner
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}
