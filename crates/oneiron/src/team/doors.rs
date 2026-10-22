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
    CoordinationPattern, SkillRevisionRef, load_team_type_tree_at_in_txn,
    load_team_type_tree_in_txn, store_team_type_tree, team_shape_skill_in_force_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Error;
use crate::learning::TypeRef;
use crate::llm::ReasoningEffort;
use crate::llm::decision::{DecisionRung, ProviderPin};
use crate::memory::{MemoryError, MemoryResult};
use crate::task_type::{ROOT_NODE_ID, TaskTypeNode, TaskTypeRef, TaskTypeTree, TreeScope};
use crate::team::{PatternSkillRef, SpawnErasure, SpawnPhase, TeamAxis, TeamPattern};
use crate::{EntityId, Vault};

pub use spawn::{SpawnAskKnob, SpawnIntentReply, SpawnIntentRequest, spawn_as_owner};

/// The highest version an authored tree may carry: the fixture format's
/// bound (Engine 10-19 e). Learning stamps keep a `u64` version (FIX 4432),
/// so this bounds authored fixtures alone, never a placed stamp.
pub const FIXTURE_TREE_VERSION_MAX: u64 = u32::MAX as u64;

/// What an authored structure must be, said on every refusal of one.
const STRUCTURE_FIX: &str = "Author one root node `root` with no parent, unique non-empty node ids, and every other node's parent an authored node.";

/// A type stamp on the wire: one node in one version of the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TypeStamp {
    pub node_id: String,
    pub tree_version: u64,
}

impl From<&TaskTypeRef> for TypeStamp {
    fn from(stamp: &TaskTypeRef) -> Self {
        Self {
            node_id: stamp.node_id.clone(),
            tree_version: stamp.tree_version,
        }
    }
}

/// A learning, team or critic stamp holds a `u32` version: widened here, it
/// reads exactly as stored, never saturated.
impl From<&TypeRef> for TypeStamp {
    fn from(stamp: &TypeRef) -> Self {
        Self {
            node_id: stamp.node_id.clone(),
            tree_version: u64::from(stamp.tree_version),
        }
    }
}

/// One authored node: structure only. The root is the one node with no
/// parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskTypeNodeSpec {
    pub node_id: String,
    #[serde(default)]
    pub parent: Option<String>,
    pub name: String,
}

/// An authored tree for an open local fork of the team-shape skill, at the
/// version it asks to be stored as. Its measured counters start at zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskTypeTreePin {
    pub fork_ref: EntityId,
    pub tree_version: u64,
    pub nodes: Vec<TaskTypeNodeSpec>,
    /// The project the pin is read in: its kept trees join the vault's in
    /// the version check, and the receipt's `in_force` answers for it.
    /// `None` is the vault. The pin never registers or admits the fork
    /// there.
    #[serde(default)]
    pub project_ref: Option<EntityId>,
}

/// The vault's tree, or a project's: in force, or the kept tree at one
/// version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskTypeTreeRead {
    #[serde(default)]
    pub project_ref: Option<EntityId>,
    #[serde(default)]
    pub tree_version: Option<u64>,
}

/// One node as the tree holds it; not live once it merged away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskTypeNodeView {
    pub node_id: String,
    #[serde(default)]
    pub parent: Option<String>,
    pub name: String,
    pub live: bool,
}

/// A tree's structure: its version, its root stamp and every node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskTypeTreeView {
    pub tree_version: u64,
    pub root: TypeStamp,
    pub nodes: Vec<TaskTypeNodeView>,
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

/// The tree stored on the fork, and whether that fork is the team-shape
/// skill in force for the scope the pin named: a stored tree is a candidate
/// until the gate admits its fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskTypeTreePinReceipt {
    pub fork_ref: EntityId,
    /// The tree as stored, at the version it was stored at.
    pub stored: TaskTypeTreeView,
    /// The version the pin asked for, given only when it differs from the
    /// stored one: the tree was stored at the next free version because the
    /// requested one names another structure in its lookup scope.
    #[serde(default)]
    pub requested_tree_version: Option<u64>,
    /// The scope the pin was read in and `in_force` answers for: a project,
    /// or `None` for the vault head. A project's answer says nothing of
    /// another project's.
    #[serde(default)]
    pub project_ref: Option<EntityId>,
    /// Whether the fork is the team-shape skill in force for that scope.
    /// `None` when that could not be read after the tree was stored: unknown,
    /// not false.
    #[serde(default)]
    pub in_force: Option<bool>,
}

/// The tree read (`None` when no kept tree is at the version asked) and the
/// team-shape skill in force for the scope read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskTypeTreeReadReply {
    #[serde(default)]
    pub project_ref: Option<EntityId>,
    #[serde(default)]
    pub in_force_skill_ref: Option<EntityId>,
    #[serde(default)]
    pub tree: Option<TaskTypeTreeView>,
}

/// One spawned agent, by the root or leader attempt its spawn answered; a
/// child spawn's attempt is one too.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlannedSpawnRead {
    pub spawn_ref: EntityId,
}

/// A coordination pattern by its word, as a plan, a team start or a team
/// receipt stored it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationPatternView {
    Solo,
    CeoDecides,
    Committee,
    Vote,
    Market,
    Rotation,
}

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
        }
    }
}

/// One skill revision a plan read or selected, or a team ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillRevisionView {
    pub skill_ref: EntityId,
    pub version: String,
}

impl From<&SkillRevisionRef> for SkillRevisionView {
    fn from(revision: &SkillRevisionRef) -> Self {
        Self {
            skill_ref: revision.skill,
            version: revision.version.clone(),
        }
    }
}

impl From<&PatternSkillRef> for SkillRevisionView {
    fn from(revision: &PatternSkillRef) -> Self {
        Self {
            skill_ref: revision.skill,
            version: revision.version.clone(),
        }
    }
}

/// One executor that read the planner rung's question, at revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProviderPinView {
    pub rung: DecisionRung,
    pub model: String,
    pub version: String,
}

impl From<&ProviderPin> for ProviderPinView {
    fn from(pin: &ProviderPin) -> Self {
        Self {
            rung: pin.rung,
            model: pin.model.clone(),
            version: pin.version.clone(),
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

/// One attempt that launched: durably queued, not necessarily run. Its
/// state, type stamp and team stamp are its own row's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LaunchedMember {
    pub attempt_ref: EntityId,
    pub state: String,
    pub type_ref: TypeStamp,
    /// The team its dispatch froze, which a leader's may predate.
    #[serde(default)]
    pub team_ref: Option<String>,
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

/// One launched run's agent-run seat, as its choice receipt keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RouteObservation {
    pub run_ref: EntityId,
    /// The stamp the seat was born under (S5), as its row keeps it. The
    /// dispatch's stamp is never copied in: a seat born under another one
    /// is a stamp mismatch.
    pub type_ref: TypeStamp,
    pub model: String,
    pub effort: ReasoningEffort,
    pub why: String,
    pub reused: bool,
}

/// How a critique was found for a launched run.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CriticAssociation {
    /// Keyed under the run's own attempt.
    BranchAttempt,
    /// A review whose run reference is the run's canonical id: it names the
    /// run, which does not prove it reviewed the run's work.
    CanonicalRunRef,
    /// A review its caller declared for the run (`spawn_attempt_ref` on
    /// `vault.critic.review`), under whatever run reference it chose. The
    /// declaration is the caller's word: it does not prove the review judged
    /// the run's output.
    DeclaredSpawnAttempt,
}

/// One critique artifact and its calibration stamp, as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CriticObservation {
    pub run_ref: String,
    pub branch_attempt_ref: EntityId,
    pub association: CriticAssociation,
    /// The launched run's attempt a declared association names; `None` for
    /// the others, whose branch or run reference names the run.
    #[serde(default)]
    pub declared_attempt_ref: Option<EntityId>,
    /// The verdict claim of the review that holds the critique, whichever
    /// association found it (FIX 5252, 6380): the row it derives from, the
    /// review the caller declared for the run when there is one, else the
    /// stored review the critique is in. `None` when no stored review holds
    /// it, or its verdict ref does not read.
    #[serde(default)]
    pub review_verdict_ref: Option<EntityId>,
    pub artifact_id: String,
    pub target_ref: String,
    pub type_ref: TypeStamp,
    pub lens_ref: EntityId,
    pub lens_id: String,
    pub executor: String,
    pub axis: String,
    pub verdict: String,
}

/// The learning cell a team receipt's pattern skill is scored in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningCellView {
    pub predicate: String,
    pub subject: EntityId,
    pub executor: String,
    pub type_ref: TypeStamp,
    pub axis: String,
    /// The receipt's frozen project the cell counts; `None` is the vault.
    #[serde(default)]
    pub project: Option<EntityId>,
}

/// The cell a borrowed prior came from, with its own qualifiers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BorrowedCellView {
    pub predicate: String,
    pub subject: EntityId,
    #[serde(default)]
    pub executor: Option<String>,
    #[serde(default)]
    pub type_ref: Option<TypeStamp>,
    #[serde(default)]
    pub axis: Option<String>,
    /// The scope the borrowed cell counts: a project's, or the vault's.
    #[serde(default)]
    pub project: Option<EntityId>,
}

/// One admitted evidence row of the cell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningEvidenceView {
    pub receipt_ref: String,
    pub at: u64,
    pub anchor_kind: String,
    pub weight: f64,
}

/// The reliability read of a team receipt's pattern skill cell: the estimate
/// in force, its prior and the cell's own evidence. A read; it writes
/// nothing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningObservation {
    pub cell: LearningCellView,
    pub mean: f64,
    /// Whether the estimate rests on the cell's own runs.
    pub own: bool,
    pub own_runs: f64,
    pub prior_origin: String,
    pub prior_weight_runs: f64,
    #[serde(default)]
    pub borrowed_from: Option<BorrowedCellView>,
    pub untested: bool,
    pub window_half_life_secs: u64,
    pub estimator_version: u32,
    pub evidence: Vec<LearningEvidenceView>,
}

/// What the read found that does not add up, or could not read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservationIssue {
    /// A consumer's stamp is not the dispatch's. Both are as stored.
    StampMismatch {
        consumer: String,
        reference: String,
        expected: TypeStamp,
        actual: TypeStamp,
    },
    /// The frozen plan resolved a team, and the attempt started none.
    MissingBinding { reference: String },
    /// The attempt started several teams. None is picked.
    SeveralTeams { team_refs: Vec<String> },
    /// A member the team start bound carries another team stamp.
    TeamMismatch {
        member_ref: EntityId,
        expected: String,
        #[serde(default)]
        actual: Option<String>,
    },
    /// What `consumer` could not report or resolve, and why.
    Unavailable { consumer: String, reason: String },
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
