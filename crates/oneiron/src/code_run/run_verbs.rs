//! The inputs and outputs of the verb-table rows a code run answers itself
//! (`context: "run"` in `scripts/sdk/agent-verbs.json`).
//!
//! Each input is the object code mode's `vault.<row>(input)` takes. The guest
//! bridge decodes it into the run's own typed `self.*` call, so a row keeps the
//! effect, gate and replay row it had as a hand-written import. Each input is
//! closed: a field it does not list is refused, as on every other row.
//!
//! Each output is what the row's reply carries under `output`, as its row
//! names it, so the catalog fragment types the reply.
//!
//! The integer bounds are the ones the typed imports enforced: a time is a
//! JavaScript safe integer, since a guest number above it was already rounded,
//! and a search limit fits a `u32`.

/// The largest integer a JavaScript number carries exactly.
pub const JS_SAFE_INTEGER: u64 = (1 << 53) - 1;

use serde::{Deserialize, Serialize};

use crate::code_run::SessionHookDisposition;
use crate::entity_id::EntityId;

/// `vault.search`: a bounded text search over the run's storage route.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemorySearchInput {
    pub query: String,
    #[schemars(range(max = "u32::MAX"))]
    pub limit: Option<u32>,
}

/// `vault.claims.put`: one claim candidate through the run's gate.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryTimeRange {
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub start: u64,
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub end: u64,
}

/// `vault.claims.supersede`: closes `oldId` in favour of `newId`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemorySupersedeInput {
    pub new_id: String,
    pub old_id: String,
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub now: u64,
}

impl MemorySupersedeInput {
    /// The same typed call on code mode and the credential-bound run door.
    pub(crate) fn into_call(self) -> crate::Result<super::SelfMemorySupersedeClaimCall> {
        if self.now > JS_SAFE_INTEGER {
            return Err(crate::Error::InvalidClaimBody("invalid unix time"));
        }
        Ok(super::SelfMemorySupersedeClaimCall::new(
            EntityId::from_hex(&self.new_id)?,
            EntityId::from_hex(&self.old_id)?,
            self.now,
        ))
    }
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

/// `tasks.refuse`: the agent's own refusal of the TASK her run realizes,
/// applied through her refusal dial (OF-533).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TaskRefuseInput {
    /// The bound TASK's id, hex; the run's own TASK when absent. Any other
    /// TASK is refused.
    pub task_ref: Option<String>,
    /// What the refusal concerns.
    pub domain: TaskRefuseDomain,
    /// Her durable reason: `cl_<hex>` (a claim) or `tn_<hex>` (a turn).
    pub reason_ref: String,
    /// When she refused, unix seconds; the run's clock when absent.
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub at: Option<u64>,
}

impl TaskRefuseInput {
    /// The same refusal call on code mode and the credential-bound run door.
    pub(crate) fn into_call(self, now: u64) -> crate::Result<super::SelfTaskRefuseCall> {
        let at = self.at.unwrap_or(now);
        if at > JS_SAFE_INTEGER {
            return Err(crate::Error::InvalidClaimBody("invalid unix time"));
        }
        Ok(super::SelfTaskRefuseCall {
            task_ref: self
                .task_ref
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?,
            domain: match self.domain {
                TaskRefuseDomain::Bond => crate::agent_def::RefusalDomain::Bond,
                TaskRefuseDomain::Logistics => crate::agent_def::RefusalDomain::Logistics,
            },
            reason_ref: self.reason_ref,
            at,
        })
    }
}

/// The wire name of a refusal domain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskRefuseDomain {
    Bond,
    Logistics,
}

/// `self.report_blocked`: the agent's own word that it cannot go on
/// (ARCH-0066 #grammar). Only the closed category can drive routing; the
/// detail is witnessed as the escaped, untrusted leaf of the blocked
/// receipt, never a planner instruction.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportBlockedInput {
    /// The closed blocked category: `tool`, `permission`, `context` or
    /// `environment`.
    pub category: super::blocked::BlockedCategory,
    /// What blocked the agent, in its own words.
    pub detail: String,
}

impl ReportBlockedInput {
    /// The same blocked-report call on code mode and the credential-bound
    /// run door. The host stamps its order and time; the guest supplies
    /// neither.
    pub(crate) fn into_call(self) -> super::blocked::SelfReportBlockedCall {
        super::blocked::SelfReportBlockedCall::new(self.category, self.detail)
    }
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

/// `self.agents.spawn`: one child agent under the run's attempt (ARCH-0079
/// #spawn). The parent states what it needs apart from the work. With the
/// host's planner and the agent's lease the planner picks the seat; else the
/// named agent runs. Parent, run and actor are the host's.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSpawnInput {
    /// What the parent needs, in one or two lines. The planner routes on it.
    pub need: String,
    /// The work itself. The child reads it as its briefing.
    pub prompt: String,
    /// The spawn's key in the run: the same key spawns the same child.
    pub intent_key: String,
    /// The AGENT_DEF to run, hex, when no planner picks the seat.
    pub agent: Option<String>,
    pub care: Option<SpawnCare>,
    /// Constraints and preferences: a model family, a time limit.
    pub notes: Option<String>,
    pub model: Option<SpawnKnob<String>>,
    pub width: Option<SpawnKnob<u32>>,
    pub pattern: Option<SpawnKnob<SpawnPattern>>,
    /// Hard spend cap for the whole spawn, in lease units. It only narrows.
    pub budget: Option<SpawnKnob<u64>>,
    /// What the child may see: a context descriptor (`layers`, `memory`,
    /// `chat`). Its briefing is the prompt.
    pub context: Option<crate::context_projection::ContextSpec>,
    /// Settled sibling results the child reads, TASK ids, hex.
    pub context_from: Option<Vec<String>>,
    /// Delegation depth left below the child; clamped to the parent's.
    pub depth: Option<u8>,
    /// The direct child project the child works in, hex; the parent's when
    /// absent.
    pub project: Option<String>,
    /// What the child is to achieve, one line each, kept verbatim and in
    /// order (OF-544); its confession answers each. Absent, the runner
    /// infers its own.
    pub objectives: Option<Vec<String>>,
    /// Whom the child may address (FIX 1380): `parent`, `subtree`,
    /// `project` or `vault`. Absent, the spawn role's default; either is
    /// clamped to the parent's reach.
    #[serde(default)]
    pub comm: Option<crate::agent_dispatch::CommReach>,
}

/// One spawn field as the parent sets it (ARCH-0079 #seed-pin): a seed is
/// where the planner starts, weighted in runs; a pin is never overridden.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SpawnKnob<T> {
    Seed { value: T, weight_runs: f64 },
    Pin { value: T },
}

impl<T> SpawnKnob<T> {
    fn map<U>(
        self,
        f: impl FnOnce(T) -> crate::Result<U>,
    ) -> crate::Result<crate::agent_dispatch::SpawnOverride<U>> {
        Ok(match self {
            Self::Seed { value, weight_runs } => crate::agent_dispatch::SpawnOverride::Seed {
                value: f(value)?,
                weight_runs,
            },
            Self::Pin { value } => crate::agent_dispatch::SpawnOverride::Pin { value: f(value)? },
        })
    }
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

/// A coordination pattern by its word.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpawnPattern {
    Solo,
    CeoDecides,
    Committee,
    Vote,
    Market,
    Rotation,
}

fn spawn_invalid(detail: &'static str) -> crate::Error {
    crate::Error::Artifact(crate::error::ArtifactError::InvalidAgentDispatchInput(
        detail,
    ))
}

impl AgentSpawnInput {
    /// The typed call: the ask, the named target and the context the guest
    /// may request. The prompt rides the context descriptor's briefing.
    ///
    /// # Errors
    ///
    /// A blank need or prompt, a malformed id, model or context descriptor.
    pub fn into_call(self) -> crate::Result<super::SelfAgentSpawnCall> {
        use crate::agent_dispatch::{AgentSpawnContext, CareLevel, CoordinationPattern};
        if self.need.trim().is_empty() {
            return Err(spawn_invalid("a spawn states its need"));
        }
        if self.prompt.trim().is_empty() {
            return Err(spawn_invalid("a spawn carries its prompt"));
        }
        let mut spec = self.context.unwrap_or_default();
        spec.briefing = Some(self.prompt);
        let context = AgentSpawnContext {
            context_spec: Some(spec),
            context_from: self
                .context_from
                .unwrap_or_default()
                .iter()
                .map(|id| Ok(crate::EntityId::from_hex(id)?))
                .collect::<crate::Result<_>>()?,
            depth_remaining: self.depth,
            project_ref: self
                .project
                .as_deref()
                .map(crate::EntityId::from_hex)
                .transpose()?,
            objectives: self.objectives,
            comm: self.comm,
            ..AgentSpawnContext::default()
        };
        let ask = super::SelfSpawnAsk {
            need: self.need,
            care: self.care.map(|care| match care {
                SpawnCare::Light => CareLevel::Light,
                SpawnCare::Medium => CareLevel::Medium,
                SpawnCare::High => CareLevel::High,
                SpawnCare::XHigh => CareLevel::XHigh,
                SpawnCare::Max => CareLevel::Max,
            }),
            notes: self.notes,
            model: self
                .model
                .map(|knob| {
                    knob.map(|model| {
                        crate::llm::ModelId::new(model)
                            .map_err(|_| spawn_invalid("invalid spawn model id"))
                    })
                })
                .transpose()?,
            width: self.width.map(|knob| knob.map(Ok)).transpose()?,
            pattern: self
                .pattern
                .map(|knob| {
                    knob.map(|pattern| {
                        Ok(match pattern {
                            SpawnPattern::Solo => CoordinationPattern::Solo,
                            SpawnPattern::CeoDecides => CoordinationPattern::CeoDecides,
                            SpawnPattern::Committee => CoordinationPattern::Committee,
                            SpawnPattern::Vote => CoordinationPattern::Vote,
                            SpawnPattern::Market => CoordinationPattern::Market,
                            SpawnPattern::Rotation => CoordinationPattern::Rotation,
                        })
                    })
                })
                .transpose()?,
            budget_cap_units: self.budget.map(|knob| knob.map(Ok)).transpose()?,
        };
        Ok(super::SelfAgentSpawnCall {
            target: self
                .agent
                .as_deref()
                .map(crate::EntityId::from_hex)
                .transpose()?
                .map(crate::agent_dispatch::AgentDispatchTarget::Custom),
            context,
            intent_key: self.intent_key,
            ask: Some(ask),
        })
    }
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
    pub slice: Option<crate::llm::Scope>,
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

/// `tasks.wait`'s input: one wait over reader children the run spawned, or
/// one on a world-privacy request the run's actor opened (FIX 4706).
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum TaskWaitInput {
    Readers(TaskWaitSetRequest),
    WorldPrivacy(TaskWaitWorldRequest),
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

/// What `tasks.wait` answers: the reduction over reader children, or a
/// world-privacy request's terminal state (`WorldPrivacyReady`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum TaskWaitOutput {
    Readers(crate::code_run::TaskWaitSetResult),
    WorldPrivacy(crate::task_verb::TaskAskWait),
}

/// `vault.search`'s output: the hits, best first, and in an off-record room
/// what each verb hook bound to the search did (WILL L11-01 S01-2c).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MemorySearchOutput {
    pub results: Vec<MemorySearchHit>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<SessionHookDisposition>,
}

/// One `vault.search` hit.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct MemorySearchHit {
    pub id: EntityId,
    pub score: f32,
}

/// `vault.claims.put` and `vault.claims.supersede`'s output: the claim
/// written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryWriteOutput {
    pub id: EntityId,
}

/// `vault.edges.put`'s output: the edge written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryEdgeOutput {
    pub src: EntityId,
    /// The edge kind's name.
    pub kind: String,
    pub tgt: EntityId,
}

/// `tasks.refuse`'s output: what the agent's dial made of her refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskRefuseOutput {
    pub task: EntityId,
    /// Where her dial sat: `none`, `voice`, `veto` or `full`.
    pub level: crate::agent_def::RefusalLevel,
    /// The level's outcome: `proceed`, `object` or `decline`.
    pub outcome: crate::agent_def::RefusalOutcome,
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

/// `self.agents.spawn`'s output: the queued attempt, or the widening its
/// spawn proposed instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AgentSpawnOutput {
    Queued {
        kind: AgentSpawnKind,
        /// The attempt's id, hex.
        attempt: String,
        /// What the launch starts and may spend, stated before it runs: its
        /// agent count, expected spend and cap (OF-532).
        launch: Option<crate::agent_dispatch::LaunchStatement>,
    },
    ProposedWiden {
        kind: AgentSpawnKind,
        proposal: String,
    },
}

/// The `kind` every `self.agents.spawn` output carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSpawnKind {
    AgentSpawn,
}

/// `self.leader.pattern`'s output: the pattern loaded, as the leader reads
/// it (OF-389).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaderPatternOutput {
    /// The entity that loaded: an exploration trial may route to its
    /// proposal.
    pub skill: EntityId,
    pub skill_id: String,
    pub version: String,
    pub desc: String,
    pub files: Option<Vec<LeaderPatternFile>>,
}

/// `self.leader.split`'s output: the subproject her TASK wraps (OF-389).
/// A retry answers the same child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderSplitOutput {
    /// The child PROJECT.
    pub project: EntityId,
    /// The TASK that wraps it.
    pub task: EntityId,
    /// The project it was spawned under.
    pub parent: EntityId,
    pub leader: EntityId,
    /// How many more levels the child may spawn.
    pub depth_remaining: u8,
}

/// One file of a loaded pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaderPatternFile {
    pub path: String,
    pub text: String,
}

// The model crate owns Scope but has no schemars dependency. Runtime decoding
// and SDK types use that Scope directly; these mirrors supply its MCP schema.
#[derive(schemars::JsonSchema)]
#[schemars(rename = "BranchScope")]
#[expect(dead_code, reason = "schema mirror of the model crate's Scope")]
struct BranchScopeSchema {
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
enum BranchScopeResourceSchema {
    Bucket { key: String },
    DocumentVersion { document: String, version: String },
    Projection { key: String },
}
