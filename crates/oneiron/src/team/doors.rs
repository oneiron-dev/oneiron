//! The owner's task-type tree doors (DOOR-111, OF-541): store an authored
//! tree on an open team-shape fork, and read the tree in force or one kept
//! version.
//!
//! Storing is candidate storage only. The fork keeps its lifecycle and goes
//! in force when the ordinary admission gate admits it; the receipt says
//! whether it is in force for the scope the pin names, and nothing here
//! admits, flips a lifecycle or registers a fork.
//!
//! The owner also reads one spawned agent by its attempt (S6): what the
//! stores hold for it, every stamp as stored. A stamp that disagrees is an
//! issue on the observation, never a correction.

mod spawn;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::{
    SkillRevisionRef, load_team_type_tree_at_in_txn, load_team_type_tree_in_txn,
    store_team_type_tree, team_shape_skill_in_force_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Error;
use crate::memory::{MemoryError, MemoryResult};
use crate::model_decision::{DecisionRung, ProviderPin};
use crate::receipt::task_type_ref::TypeRef;
use crate::task_type::{ROOT_NODE_ID, TaskTypeNode, TaskTypeRef, TaskTypeTree, TreeScope};
use crate::team::team_shape::CoordinationPattern;
use crate::team::{PatternSkillRef, SpawnErasure, SpawnPhase, TeamAxis, TeamPattern};
use crate::{EntityId, Vault};
use oneiron_model::llm::ReasoningEffort;

pub use spawn::{SpawnAskKnob, SpawnIntentReply, SpawnIntentRequest, spawn_as_owner};

/// The highest version an authored tree may carry: the fixture format's
/// bound (Engine 10-19 e). Learning stamps keep a `u64` version (FIX 4432),
/// so this bounds authored fixtures alone, never a placed stamp.
pub const FIXTURE_TREE_VERSION_MAX: u64 = u32::MAX as u64;

/// What an authored structure must be, said on every refusal of one.
const STRUCTURE_FIX: &str = "Author one root node `root` with no parent, unique non-empty node ids, and every other node's parent an authored node.";

#[doc(hidden)]
pub use oneiron_verb_wire::team::doors::{
    BorrowedCellView, CriticAssociation, CriticObservation, LaunchedMember, LearningCellView,
    LearningEvidenceView, LearningObservation, ObservationIssue, PlannedSpawnRead, ProviderPinView,
    RouteObservation, SkillRevisionView, TaskTypeNodeSpec, TaskTypeNodeView, TaskTypeTreePin,
    TaskTypeTreePinReceipt, TaskTypeTreeRead, TaskTypeTreeReadReply, TaskTypeTreeView, TypeStamp,
};

impl From<&TaskTypeRef> for TypeStamp {
    fn from(stamp: &TaskTypeRef) -> Self {
        Self {
            node_id: stamp.node_id.clone(),
            tree_version: stamp.tree_version,
        }
    }
}

/// A learning, team or critic stamp holds the same `u64` version (FIX
/// 4432): it reads exactly as stored.
impl From<&TypeRef> for TypeStamp {
    fn from(stamp: &TypeRef) -> Self {
        Self {
            node_id: stamp.node_id.clone(),
            tree_version: stamp.tree_version,
        }
    }
}

impl From<&TaskTypeTree> for TaskTypeTreeView {
    fn from(tree: &TaskTypeTree) -> Self {
        Self {
            tree_version: tree.version,
            root: TypeStamp::from(&tree.root_ref()),
            nodes: tree
                .nodes
                .values()
                .map(|node| TaskTypeNodeView {
                    node_id: node.node_id.clone(),
                    parent: node.parent.clone(),
                    name: node.name.clone(),
                    live: node.is_live(),
                })
                .collect(),
        }
    }
}

/// A coordination pattern by its word, as a plan, a team start or a team
/// receipt stored it.
pub use crate::code_run::SpawnPattern as CoordinationPatternView;

impl From<CoordinationPattern> for CoordinationPatternView {
    fn from(pattern: CoordinationPattern) -> Self {
        match pattern {
            CoordinationPattern::Solo => Self::Solo,
            CoordinationPattern::CeoDecides => Self::CeoDecides,
            CoordinationPattern::Committee => Self::Committee,
            CoordinationPattern::Vote => Self::Vote,
            CoordinationPattern::Market => Self::Market,
            CoordinationPattern::Rotation => Self::Rotation,
        }
    }
}

impl From<TeamPattern> for CoordinationPatternView {
    fn from(pattern: TeamPattern) -> Self {
        match pattern {
            TeamPattern::CeoDecides => Self::CeoDecides,
            TeamPattern::Committee => Self::Committee,
            TeamPattern::Vote => Self::Vote,
            TeamPattern::Market => Self::Market,
            TeamPattern::Rotation => Self::Rotation,
            TeamPattern::Solo => Self::Solo,
        }
    }
}

/// The plan the dispatch froze: the stamp it was asked under, what it
/// resolved and why. Read back, never re-planned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanObservation {
    pub type_ref: TypeStamp,
    /// The selected model; the models actually seated are the routes'.
    pub model: String,
    pub width: u32,
    pub pattern: CoordinationPatternView,
    /// `None`: unmetered by any lease tree.
    #[serde(default)]
    pub hard_cap_units: Option<u64>,
    pub expected_spend_units: u64,
    #[serde(default)]
    pub available_units: Option<u64>,
    pub over_budget: bool,
    pub fitted_to_budget: bool,
    pub why: Vec<String>,
    #[serde(default)]
    pub team_shape: Option<SkillRevisionView>,
    /// The pattern skill revision the plan selected; `None` for solo.
    #[serde(default)]
    pub pattern_skill: Option<SkillRevisionView>,
    #[serde(default)]
    pub rung_skill: Option<SkillRevisionView>,
    pub rung_providers: Vec<ProviderPinView>,
}

/// The team the frozen plan resolved to, given only when the one team the
/// attempt started launched exactly that: the plan's pattern and width in
/// distinct attempts, every stamp the dispatch's, and the selected pattern
/// revision the one the team ran. One queued agent is never a team.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResolvedTeam {
    pub type_ref: TypeStamp,
    pub pattern: CoordinationPatternView,
    pub width: u32,
    /// The plan's selected model.
    pub model: String,
    /// `None` until the team's receipt records it.
    #[serde(default)]
    pub axis: Option<TeamAxis>,
    /// The project the dispatch named; `None` when it named none.
    #[serde(default)]
    pub project_ref: Option<EntityId>,
    pub root_attempt_ref: EntityId,
    pub member_attempt_refs: Vec<EntityId>,
    #[serde(default)]
    pub team_ref: Option<String>,
}

/// The team start the host recorded for the attempt as leader: the members
/// its spawns queued and the widenings they asked instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeamBindingView {
    pub team_ref: String,
    pub pattern: CoordinationPatternView,
    pub leader: EntityId,
    pub member_attempt_refs: Vec<EntityId>,
    /// Never members: a proposal is one only once its approval queues it.
    pub proposal_refs: Vec<String>,
    #[serde(default)]
    pub root_task: Option<String>,
    pub started_at: u64,
}

/// That team's receipt, once the team recorded one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TeamReceiptView {
    pub team_ref: String,
    pub type_ref: TypeStamp,
    pub pattern: CoordinationPatternView,
    /// The pattern skill revision the leader loaded, when it loaded one.
    #[serde(default)]
    pub pattern_skill: Option<SkillRevisionView>,
    pub axis: TeamAxis,
    pub width: u32,
    pub models: Vec<String>,
    /// The receipt the anchored outcome rests on, once one settled the team.
    #[serde(default)]
    pub outcome_receipt: Option<String>,
}

/// What the stores hold for one spawned agent. Each list is what was found;
/// an empty one is none found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlannedSpawnObservation {
    pub spawn_ref: EntityId,
    pub phase: SpawnPhase,
    /// `target_erased` once an erase took the AGENT_DEF the spawn runs as.
    #[serde(default)]
    pub erasure: Option<SpawnErasure>,
    /// The type stamp the dispatch froze, placed once at spawn.
    pub type_ref: TypeStamp,
    /// The frozen plan; `None` for a spawn that was not planned.
    #[serde(default)]
    pub plan: Option<PlanObservation>,
    /// The requested attempt, then each member of the one team it started.
    pub launched: Vec<LaunchedMember>,
    #[serde(default)]
    pub resolved: Option<ResolvedTeam>,
    #[serde(default)]
    pub binding: Option<TeamBindingView>,
    #[serde(default)]
    pub receipt: Option<TeamReceiptView>,
    pub routes: Vec<RouteObservation>,
    /// Critiques keyed under a launched attempt, under a review run that
    /// names one, or of a review its caller declared for one. A declaration
    /// is not proof the review judged that run's output. Not exhaustive: a
    /// review under a run reference the caller chose, declared for no run,
    /// is not discoverable from an attempt, and a stored review that does
    /// not read is an issue rather than a critique.
    pub critics: Vec<CriticObservation>,
    pub learning: Vec<LearningObservation>,
    pub issues: Vec<ObservationIssue>,
}

/// Stores an authored task-type tree on `input.fork_ref`, an open local fork
/// of the team-shape skill, as the owner, through the tree store (which
/// refuses a fork outside the lineage, a fork no longer open and a version
/// behind its parent's tree, and stores a version that already names
/// another structure in its lookup scope at the next free one). The receipt
/// gives the version stored and says whether the fork is in force for the
/// vault or `input.project_ref`.
///
/// # Errors
///
/// `BAD_REQUEST` for a version outside `1..=FIXTURE_TREE_VERSION_MAX` or a
/// malformed structure, naming the offending node; the tree store's
/// refusals; a stale owner proof; storage errors.
pub fn pin_tree_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: TaskTypeTreePin,
) -> MemoryResult<TaskTypeTreePinReceipt> {
    owner.revalidate(vault)?;
    let version = input.tree_version;
    if !(1..=FIXTURE_TREE_VERSION_MAX).contains(&version) {
        return Err(MemoryError::bad_request_with(
            format!("tree_version {version} is outside 1..={FIXTURE_TREE_VERSION_MAX}"),
            &["An authored tree's version is at least 1 and within the fixture format's bound."],
        ));
    }
    check_structure(&input.nodes)?;
    let mut tree = authored_tree(version, &input.nodes);
    tree.version = store_team_type_tree(
        vault,
        input.fork_ref,
        &tree,
        input.project_ref,
        crate::unix_seconds_now(),
    )?;
    Ok(TaskTypeTreePinReceipt {
        fork_ref: input.fork_ref,
        stored: TaskTypeTreeView::from(&tree),
        requested_tree_version: (tree.version != version).then_some(version),
        project_ref: input.project_ref,
        in_force: fork_in_force(vault, input.fork_ref, input.project_ref),
    })
}

/// Whether `fork` is the team-shape skill in force for `project` (`None` is
/// the vault), read once its tree is stored. `None` when that read fails:
/// the tree is stored either way.
fn fork_in_force(vault: &Vault, fork: EntityId, project: Option<EntityId>) -> Option<bool> {
    let in_force = vault
        .store
        .env
        .read_txn()
        .map_err(Error::from)
        .and_then(|txn| team_shape_skill_in_force_in_txn(vault, &txn, project));
    match in_force {
        Ok(skill) => Some(skill == Some(fork)),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "pinned tree's skill in force did not read");
            None
        }
    }
}

/// Reads, as the owner, the task-type tree in force for the vault or
/// `project_ref`, or the kept tree at `tree_version` as it was placed in,
/// never restamped; and the team-shape skill in force there, from the same
/// snapshot.
///
/// # Errors
///
/// A stale owner proof; a stored tree that does not decode; storage errors.
pub fn read_tree_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: TaskTypeTreeRead,
) -> MemoryResult<TaskTypeTreeReadReply> {
    owner.revalidate(vault)?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let tree = match input.tree_version {
        None => Some(load_team_type_tree_in_txn(vault, &txn, input.project_ref)?),
        Some(version) => load_team_type_tree_at_in_txn(vault, &txn, input.project_ref, version)?,
    };
    Ok(TaskTypeTreeReadReply {
        project_ref: input.project_ref,
        in_force_skill_ref: team_shape_skill_in_force_in_txn(vault, &txn, input.project_ref)?,
        tree: tree.as_ref().map(TaskTypeTreeView::from),
    })
}

/// Reads, as the owner, what the stores hold for the agent
/// `input.spawn_ref` runs: its dispatch's type stamp and frozen plan, the
/// one team it started with the members that launched and the team's
/// receipt, each launched run's seat route, the critiques found for those
/// runs and the receipt-backed learning read, all in one snapshot. Every
/// stamp reads as stored.
///
/// # Errors
///
/// `NOT_FOUND` for an attempt the queue does not hold; `BAD_REQUEST` for one
/// that is not an agent's dispatch; a dispatch that does not decode; a stale
/// owner proof; storage errors.
pub fn observe_spawn_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PlannedSpawnRead,
) -> MemoryResult<PlannedSpawnObservation> {
    owner.revalidate(vault)?;
    super::door_reads::observe_spawn(vault, input.spawn_ref)
}

/// An authored structure is whole: unique non-empty ids, the root
/// [`ROOT_NODE_ID`] the one node with no parent, every parent an authored
/// node, and every parent chain reaching the root.
fn check_structure(nodes: &[TaskTypeNodeSpec]) -> MemoryResult<()> {
    let refused = |message: String| MemoryError::bad_request_with(message, &[STRUCTURE_FIX]);
    let mut parents: BTreeMap<&str, Option<&str>> = BTreeMap::new();
    for node in nodes {
        let id = node.node_id.as_str();
        if id.is_empty() {
            return Err(refused("a task-type node id is empty".to_owned()));
        }
        if parents.insert(id, node.parent.as_deref()).is_some() {
            return Err(refused(format!("task-type node {id:?} is authored twice")));
        }
    }
    if !parents.contains_key(ROOT_NODE_ID) {
        return Err(refused(format!(
            "the tree has no root node {ROOT_NODE_ID:?}"
        )));
    }
    for (id, parent) in &parents {
        match parent {
            None if *id != ROOT_NODE_ID => {
                return Err(refused(format!(
                    "task-type node {id:?} has no parent; only {ROOT_NODE_ID:?} is the root"
                )));
            }
            Some(_) if *id == ROOT_NODE_ID => {
                return Err(refused(format!("the root {ROOT_NODE_ID:?} names a parent")));
            }
            Some(parent) if !parents.contains_key(parent) => {
                return Err(refused(format!(
                    "task-type node {id:?} names parent {parent:?}, which is not an authored node"
                )));
            }
            _ => {}
        }
    }
    // A chain that reaches the root takes fewer steps than there are nodes;
    // one that does not loops.
    let mut rooted = BTreeSet::from([ROOT_NODE_ID]);
    for id in parents.keys() {
        let mut chain = Vec::new();
        let mut cursor = *id;
        while !rooted.contains(cursor) {
            if chain.len() == parents.len() {
                return Err(refused(format!(
                    "task-type node {id:?} never reaches the root: its parents loop"
                )));
            }
            chain.push(cursor);
            cursor = parents
                .get(cursor)
                .copied()
                .flatten()
                .unwrap_or(ROOT_NODE_ID);
        }
        rooted.extend(chain);
    }
    Ok(())
}

/// The authored nodes as a vault-scoped tree at `version`: structure only,
/// with no seed, split or merge metadata and every counter at zero.
fn authored_tree(version: u64, nodes: &[TaskTypeNodeSpec]) -> TaskTypeTree {
    TaskTypeTree {
        version,
        scope: TreeScope::Vault,
        nodes: nodes
            .iter()
            .map(|node| {
                let stored = TaskTypeNode {
                    node_id: node.node_id.clone(),
                    parent: node.parent.clone(),
                    name: node.name.clone(),
                    seed: None,
                    split_axis: None,
                    split_winner: None,
                    merged_into: None,
                    receipt_count: 0,
                    held_out_runs: 0,
                    held_out_wins: 0,
                    decision_wins: BTreeMap::new(),
                };
                (node.node_id.clone(), stored)
            })
            .collect(),
    }
}
