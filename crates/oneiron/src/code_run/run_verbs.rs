//! The inputs and outputs of the verb-table rows a code run answers itself
//! (`context: "run"` in `scripts/sdk/verbs/`).
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

#[doc(hidden)]
use oneiron_verb_wire::code_run::run_verbs::{
    BranchScopeResourceSchema, BranchScopeSchema, spawn_invalid,
};
#[doc(hidden)]
pub use oneiron_verb_wire::code_run::run_verbs::{
    JS_SAFE_INTEGER, LeaderAdviceInput, LeaderPatternInput, LeaderSplitInput, MemoryClaimInput,
    MemoryEdgeInput, MemorySearchInput, MemoryTimeRange, ReportBlockedOutput, SkillCallInput,
    SpawnCare, SummarizeInput, SummarizeInputEffort, TaskRefuseDomain, TaskRefuseOutput,
    TaskWaitSetRequest, TaskWaitWorldRequest,
};

use serde::{Deserialize, Serialize};

use crate::code_run::SessionHookDisposition;
use crate::entity_id::EntityId;

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
    pub depth: Option<u64>,
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
    /// Leave the balance out of the cost envelope a planned team's pattern
    /// run reads (FIX 9536). Off by default: the run reads the whole
    /// envelope, which the host enforces either way.
    #[serde(default)]
    pub balance_free_prompt: bool,
    /// The powers the child holds (SPAWN-KNOB): an absent power is the
    /// parent's, `false` switches it off for the child. Asking `true` for a
    /// power the parent does not hold is refused.
    #[serde(default)]
    pub powers: Option<crate::agent_def::ChildPowerRequest>,
}

/// One spawn field as the parent sets it (ARCH-0079 #seed-pin): a seed is
/// where the planner starts, weighted in runs; a pin is never overridden.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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

/// A coordination pattern by its word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpawnPattern {
    Solo,
    CeoDecides,
    Committee,
    Vote,
    Market,
    Rotation,
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
            powers: self.powers,
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
            balance_free_prompt: self.balance_free_prompt,
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
    pub powers: Option<crate::agent_def::ChildPowerRequest>,
}

/// `tasks.wait`'s input: one wait over reader children the run spawned, one
/// on a world-privacy request the run's actor opened (FIX 4706), or one over
/// AGENT children the run spawned (slice 6.5b).
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum TaskWaitInput {
    Readers(TaskWaitSetRequest),
    WorldPrivacy(TaskWaitWorldRequest),
    Agents(TaskWaitAgentsRequest),
}

/// `tasks.wait({agents, all?, n_of?, step_key})`: one wait over AGENT
/// children the run spawned with `self.agents.spawn` (slice 6.5b), answered
/// once all of them have ended, or `n_of` of them have completed. It names
/// no deadline: a child ends by its own run, its limits, a cancel or its
/// spawner's kill, and each of those answers the wait.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskWaitAgentsRequest {
    /// The children's attempt ids, hex, as `self.agents.spawn` answered them.
    pub agents: Vec<String>,
    /// Wait for every child to end; the default.
    pub all: Option<bool>,
    /// Wait for this many children to complete.
    #[schemars(range(min = 1, max = "u32::MAX"))]
    pub n_of: Option<u32>,
    /// The wait's key in the run: the same key answers as the same wait.
    pub step_key: String,
}

impl TaskWaitAgentsRequest {
    /// The wait call the run's dispatcher takes.
    pub(crate) fn into_call(self) -> crate::code_run::TaskWaitSetCall {
        crate::code_run::TaskWaitSetCall {
            tasks: Vec::new(),
            all: self.all,
            n_of: self.n_of,
            until: None,
            step_key: self.step_key,
            request: None,
            agents: Some(self.agents),
        }
    }
}

/// What `tasks.wait` answers: the reduction over reader children, a
/// world-privacy request's terminal state (`WorldPrivacyReady`), or the
/// reduction over AGENT children. The host door's caller reads it back, so
/// it decodes too.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TaskWaitOutput {
    Readers(crate::code_run::TaskWaitSetResult),
    WorldPrivacy(crate::task_verb::TaskAskWait),
    Agents(crate::agent_dispatch::AgentWaitSetResult),
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

/// `self.agents.spawn`'s output: the queued attempt, the widening its
/// spawn proposed instead, or an erase of its target or its asker that
/// launched nothing.
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
        /// The asked fields this spawn did not apply, and why (OF-541): a
        /// spawn the host did not plan leaves its care, notes, model, width
        /// and pattern, and its need without the agent's lease. Absent when
        /// none.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unapplied: Vec<crate::agent_dispatch::SpawnUnapplied>,
    },
    ProposedWiden {
        kind: AgentSpawnKind,
        proposal: String,
        /// As on `queued`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unapplied: Vec<crate::agent_dispatch::SpawnUnapplied>,
    },
    /// An erase took the AGENT_DEF the planned spawn's plan seats: nothing
    /// launched (Engine 10-22).
    TargetErased { kind: AgentSpawnKind },
    /// An erase of its asker took the planned spawn's intent: nothing
    /// launched (FIX 9183).
    AskerErased { kind: AgentSpawnKind },
}

/// The `kind` every `self.agents.spawn` output carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSpawnKind {
    AgentSpawn,
}

/// The one projection of a spawn's answer onto `self.agents.spawn`'s
/// output, for the guest's reply and the host door alike (FIX 9183).
impl From<crate::code_run::SelfAgentSpawnResult> for AgentSpawnOutput {
    fn from(result: crate::code_run::SelfAgentSpawnResult) -> Self {
        use crate::code_run::SelfAgentSpawnResult;
        let kind = AgentSpawnKind::AgentSpawn;
        match result {
            SelfAgentSpawnResult::Queued {
                attempt_ref,
                launch,
                unapplied,
            } => Self::Queued {
                kind,
                attempt: crate::entity_id::bytes_to_hex_lower(attempt_ref.as_bytes()),
                launch,
                unapplied,
            },
            SelfAgentSpawnResult::ProposedWiden {
                proposal_ref,
                unapplied,
            } => Self::ProposedWiden {
                kind,
                proposal: proposal_ref,
                unapplied,
            },
            SelfAgentSpawnResult::TargetErased => Self::TargetErased { kind },
            SelfAgentSpawnResult::AskerErased => Self::AskerErased { kind },
        }
    }
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
    pub depth_remaining: u64,
}

/// One file of a loaded pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaderPatternFile {
    pub path: String,
    pub text: String,
}
