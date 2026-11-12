//! Moved from `crates/oneiron/src/code_run/run_verbs.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The largest integer a JavaScript number carries exactly.
pub const JS_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// `vault.search`: a bounded text search over the run's storage route.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemorySearchInput {
    pub query: String,
    #[schemars(range(max = "u32::MAX"))]
    pub limit: Option<u32>,
    /// The caller's retrieval filter (FIX 3977): it only narrows what the
    /// run's reader key admits.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

/// `vault.claims.put`: one claim candidate through the run's gate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemoryClaimInput {
    /// The claim's entity id, hex.
    pub id: String,
    pub predicate: String,
    /// The subject entity's id, hex.
    pub subject: String,
    pub value: serde_json::Value,
    /// An `f32`: a number past its range is refused, never rounded.
    #[schemars(range(min = "f32::MIN", max = "f32::MAX"))]
    pub confidence: Option<f64>,
    /// When the claim held, unix seconds; the run's clock when absent.
    pub occurred: Option<MemoryTimeRange>,
    /// When it was learned, unix seconds; the run's clock when absent.
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub learned_at: Option<u64>,
}

/// A closed `[start, end]` span in unix seconds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryTimeRange {
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub start: u64,
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub end: u64,
}

/// `vault.edges.put`: one typed edge through the run's edge gate.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryEdgeInput {
    pub src: String,
    /// The edge kind's snake_case name.
    pub kind: String,
    pub tgt: String,
    /// The kind's default weight when absent; an `f32`, as `confidence` is.
    #[schemars(range(min = "f32::MIN", max = "f32::MAX"))]
    pub weight: Option<f64>,
}

/// The wire name of a refusal domain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskRefuseDomain {
    Bond,
    Logistics,
}

/// `self.skills.call`: one agent-callable skill, run under the run's own
/// attempt lease (OF-353).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillCallInput {
    /// The callable skill's entity id, hex, as `self.skills.callables` lists
    /// it.
    pub skill: String,
    /// The call's arguments, in the shape its contract's `arguments` names.
    pub args: serde_json::Value,
}

/// How much the parent cares: the five reasoning-effort words.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SpawnCare {
    Light,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
    Max,
}

pub fn spawn_invalid(detail: &'static str) -> oneiron_base::error::Error {
    oneiron_base::error::Error::Artifact(
        oneiron_base::error::ArtifactError::InvalidAgentDispatchInput(detail),
    )
}

/// `self.leader.advice`: the bound leader's top team shapes for her TASK,
/// on the host's planner (OF-389). Advice only: no work starts.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeaderAdviceInput {
    /// How many shapes to return; the host's count when absent.
    pub top: Option<u32>,
}

/// `self.leader.pattern`: load the pattern workflow the leader picked from
/// her advice, by the skill id its `pattern_skill` names (OF-389).
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeaderPatternInput {
    /// The pattern skill's entity id, hex.
    pub skill: String,
}

/// `self.leader.split`: the bound leader splits her TASK into a subproject
/// inside the TASK's wrapper (OF-389). The parent still sees one checkbox.
/// The TASK and the parent project are the host's, from her lease.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeaderSplitInput {
    /// The child's leader, hex; herself when absent.
    pub leader: Option<String>,
    /// What the child sees: a scope that narrows the parent's
    /// (`world`, `facet`, `relationship`, `project`, `readable`,
    /// `writable`); the parent's own when absent.
    #[schemars(with = "Option<BranchScopeSchema>")]
    pub slice: Option<oneiron_model::llm::Scope>,
}

/// `self.spawn`: one reader child over a result of the run (ARCH-0079
/// #reader-forks). The child is queued and answers through its task; it
/// never runs inline.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReaderSpawnInput {
    /// The result the child reads: a name, a handle or a range ref, or a
    /// card by its `ref` or `handle`.
    pub source: serde_json::Value,
    /// What the child is asked about its source.
    pub ask: String,
    /// The spawn's key in the run: the same key spawns the same child.
    pub intent_key: String,
    /// The powers the child holds (SPAWN-KNOB): an absent power is the
    /// parent's, `false` switches it off for the child. Asking `true` for a
    /// power the parent does not hold is refused.
    #[serde(default)]
    pub powers: Option<crate::agent_def::powers::ChildPowerRequest>,
}

/// `summarize(r, {effort?, group?, defer?})`: one model call over a result
/// and the results after it, made by a host job, never inside a step, and
/// memoised by its members' occurrences and its recipe: the same call again
/// answers the same summary.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummarizeInput {
    /// The result to summarize: a name, a handle or a range ref.
    #[serde(rename = "ref")]
    pub r#ref: String,
    /// How hard the summary works; `medium` by default.
    pub effort: Option<SummarizeInputEffort>,
    /// More results summarized with it, after it, in order.
    pub group: Option<Vec<String>>,
    /// Answer `{task, state}` at once instead of waiting for the summary;
    /// wait for it with `tasks.wait`.
    pub defer: Option<bool>,
}

/// The wire name of a summary's effort.
#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SummarizeInputEffort {
    Low,
    Medium,
    High,
}

/// `tasks.wait`: one wait over reader children the run spawned, answered
/// once all of them, or `n_of` of them, have a finding, or at `until`.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskWaitSetRequest {
    /// The children's task ids, hex, as `self.spawn` returned them.
    pub tasks: Vec<String>,
    /// Wait for every child; the default.
    pub all: Option<bool>,
    /// Wait for this many children with a finding.
    #[schemars(range(min = 1, max = "u32::MAX"))]
    pub n_of: Option<u32>,
    /// When the wait answers at the latest, unix milliseconds; clamped to the
    /// children's cutoff, which is also its default.
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub until: Option<u64>,
    /// The wait's key in the run: the same key answers as the same wait.
    pub step_key: String,
}

/// `tasks.wait({request, step_key})`: a wait on one world-privacy request
/// the run's actor opened, answered once a holder applied or declined it,
/// with no reader child, quorum or reader cutoff.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskWaitWorldRequest {
    /// The request's id, hex: the `wait` handle's `group_ref` that
    /// `vault.worlds.privacy.set` answered with.
    pub request: String,
    /// The wait's key in the run.
    pub step_key: String,
}

/// `tasks.refuse`'s output: what the agent's dial made of her refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskRefuseOutput {
    pub task: EntityId,
    /// Where her dial sat: `none`, `voice`, `veto` or `full`.
    pub level: crate::store::agent_refusal::RefusalLevel,
    /// The level's outcome: `proceed`, `object` or `decline`.
    pub outcome: crate::agent_def::refusal::RefusalOutcome,
    /// A byte-identical retry answered by the first decision.
    pub replay: bool,
}

/// `self.report_blocked`'s output: the witnessed blocked receipt. The
/// report grants no authority, widens no scope, and completes no task;
/// it is supplementary, semi-trusted evidence for the Coach's Issues
/// job, read back with `vault.coach.inspect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReportBlockedOutput {
    /// The blocked receipt's MESSAGE id, hex.
    pub receipt: String,
}

// The model crate owns Scope but has no schemars dependency. Runtime decoding
// and SDK types use that Scope directly; these mirrors supply its MCP schema.
#[derive(schemars::JsonSchema)]
#[schemars(rename = "BranchScope")]
#[expect(dead_code, reason = "schema mirror of the model crate's Scope")]
pub struct BranchScopeSchema {
    world: Option<String>,
    facet: Option<String>,
    relationship: Option<String>,
    project: Option<String>,
    readable: std::collections::BTreeSet<BranchScopeResourceSchema>,
    writable: std::collections::BTreeSet<BranchScopeResourceSchema>,
}

#[derive(schemars::JsonSchema)]
#[schemars(rename = "BranchScopeResource")]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[expect(dead_code, reason = "schema mirror of the model crate's ScopeResource")]
pub enum BranchScopeResourceSchema {
    Bucket { key: String },
    DocumentVersion { document: String, version: String },
    Projection { key: String },
}
