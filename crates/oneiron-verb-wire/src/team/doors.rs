//! Moved from `crates/oneiron/src/team/doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::agent_dispatch::planner::SkillRevisionRef;
use crate::team::receipt::PatternSkillRef;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::ReasoningEffort;
use oneiron_store::model_decision::DecisionRung;
use oneiron_store::model_decision::ProviderPin;
use serde::Deserialize;
use serde::Serialize;

/// A type stamp on the wire: one node in one version of the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TypeStamp {
    pub node_id: String,
    pub tree_version: u64,
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
    /// A launched attempt the native agent pump would take now (queued or
    /// scheduled and due, no saved workflow's leaf) waits on a host with no
    /// engine-native executor to run it (FIX 4929): it stays as the queue
    /// holds it, and runs where an executor serves the vault. Status only:
    /// the host adds it to its read; nothing is refused or held.
    NoExecutor {
        attempt_ref: EntityId,
        state: String,
    },
}
