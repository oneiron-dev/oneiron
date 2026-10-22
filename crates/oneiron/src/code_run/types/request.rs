//! Values carried by guest calls, without host authority.
//! Entry type: `SelfAgentSpawnCall`.
//! Definitions live here; `code_run::types` forwards the old names.

use super::*;

/// An owner-authorized row update requested by an agent action. The owner
/// proof is HOST-BOUND on the dispatcher, never supplied in this guest call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfWakePolicyWriteCall {
    pub policy: crate::dreamer_wake::DreamerWakePolicy,
}

impl SelfWakePolicyWriteCall {
    #[must_use]
    pub const fn new(policy: crate::dreamer_wake::DreamerWakePolicy) -> Self {
        Self { policy }
    }
}

/// Arguments for the `vault.search` fixture call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfMemorySearchCall {
    pub query: String,
    pub limit: usize,
}

impl SelfMemorySearchCall {
    #[must_use]
    pub fn new(query: impl Into<String>, limit: usize) -> Self {
        Self {
            query: query.into(),
            limit,
        }
    }
}

/// Internal fixture write routed through [`Vault::batch`].
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemoryWriteFixtureCall {
    pub id: EntityId,
    pub candidate: Box<ClaimCandidate>,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

impl SelfMemoryWriteFixtureCall {
    #[must_use]
    pub fn new(
        id: EntityId,
        candidate: ClaimCandidate,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        Self {
            id,
            candidate: Box::new(candidate),
            occurred,
            learned_at,
        }
    }
}

/// Arguments for the public `vault.claims.put` trap.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemoryPutClaimCall {
    pub id: EntityId,
    pub candidate: Box<ClaimCandidate>,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

impl SelfMemoryPutClaimCall {
    #[must_use]
    pub fn new(
        id: EntityId,
        candidate: ClaimCandidate,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        Self {
            id,
            candidate: Box::new(candidate),
            occurred,
            learned_at,
        }
    }
}

/// Arguments for the public `vault.claims.supersede` trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfMemorySupersedeClaimCall {
    pub new_id: EntityId,
    pub old_id: EntityId,
    pub now: u64,
}

impl SelfMemorySupersedeClaimCall {
    #[must_use]
    pub const fn new(new_id: EntityId, old_id: EntityId, now: u64) -> Self {
        Self {
            new_id,
            old_id,
            now,
        }
    }
}

/// Arguments for the public `vault.edges.put` trap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelfMemoryPutEdgeCall {
    pub src: EntityId,
    pub kind: EdgeKind,
    pub tgt: EntityId,
    pub weight: f32,
}

impl SelfMemoryPutEdgeCall {
    #[must_use]
    pub const fn new(src: EntityId, kind: EdgeKind, tgt: EntityId, weight: f32) -> Self {
        Self {
            src,
            kind,
            tgt,
            weight,
        }
    }
}

/// Arguments for the `ask` fixture call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfAskCall {
    pub prompt: String,
}

impl SelfAskCall {
    #[must_use]
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
        }
    }
}

/// Arguments for the `self.context` descriptor bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfContextCall {
    pub spec: ContextSpec,
}

impl SelfContextCall {
    #[must_use]
    pub const fn new(spec: ContextSpec) -> Self {
        Self { spec }
    }
}

/// Arguments for one `self.speak` / `self.think` / `self.express` call.
///
/// `text` is the guest's; `order` and `occurred_at` are HOST-STAMPED by the
/// runtime bridge through [`SelfCall::with_bridge_stamp`] before dispatch, so
/// the bubble's position and timestamp are the host's total bridge ordering
/// and frozen determinism clock rather than anything guest code chose. They
/// live in the call because the dispatcher — not the bridge — is what owns the
/// actor and the storage route the bubble is written through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSpeechCall {
    pub text: String,
    /// Position in the run's total bridge ordering; becomes the witness
    /// message's `order`.
    pub order: u32,
    /// Frozen unix SECONDS for the bubble, derived from the run's determinism
    /// clock at this call's bridge position.
    pub occurred_at: u64,
}

impl SelfSpeechCall {
    /// A speech call carrying only the guest's text. Order and timestamp are
    /// zero until the bridge stamps them.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            order: 0,
            occurred_at: 0,
        }
    }

    #[must_use]
    pub fn with_bridge_stamp(mut self, order: u32, occurred_at: u64) -> Self {
        self.order = order;
        self.occurred_at = occurred_at;
        self
    }
}

/// Arguments for destructive/outbound fixture effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfFixtureEffectCall {
    pub label: String,
}

impl SelfFixtureEffectCall {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

/// One SDK verb-table call from code mode, at the verb's SDK path.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfAgentVerbCall {
    pub verb: crate::task_verb::sdk::AgentVerb,
    /// The verb's whole typed input, as its REST body and SDK bindings take it.
    pub input: serde_json::Value,
}

/// `self.skills.call(...)`: the skill and the arguments its call contract
/// takes. No lease, executor or runtime comes from the guest.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfSkillCall {
    pub skill: EntityId,
    pub args: serde_json::Value,
}

/// `tasks.refuse(...)`. The reason stays the caller's string until the
/// dispatcher resolves it against the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTaskRefuseCall {
    /// The TASK the guest named, if any; it must be the bound one.
    pub task_ref: Option<EntityId>,
    pub domain: crate::agent_def::RefusalDomain,
    pub reason_ref: String,
    pub at: u64,
}

/// No actor, source, lease or approval fields are accepted from guest code.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfAgentDefinitionPutCall {
    pub id: EntityId,
    pub definition: Box<crate::agent_def::AgentDefinition>,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

/// No parent/run/actor fields are accepted from guest code.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfAgentSpawnCall {
    /// The agent or workflow to run. Unset, the spawn needs the host's
    /// planner to pick its seat.
    pub target: Option<crate::agent_dispatch::AgentDispatchTarget>,
    pub context: crate::agent_dispatch::AgentSpawnContext,
    pub intent_key: String,
    /// OF-541: what the spawner asks the planner for. With the host's
    /// planner and the agent's lease, the host places the spawn's type and
    /// plans its seat, which replaces `target`. Otherwise `target` runs.
    pub ask: Option<SelfSpawnAsk>,
}

/// A spawn's ask in the spawner's words (ARCH-0079 #spawn): the need and
/// the knobs she seeds or pins. The host places the type, so this is a
/// [`crate::agent_dispatch::SpawnNeed`] without its stamp.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfSpawnAsk {
    pub need: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub care: Option<crate::agent_dispatch::CareLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<crate::agent_dispatch::SpawnOverride<crate::llm::ModelId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<crate::agent_dispatch::SpawnOverride<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern:
        Option<crate::agent_dispatch::SpawnOverride<crate::agent_dispatch::CoordinationPattern>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_cap_units: Option<crate::agent_dispatch::SpawnOverride<u64>>,
    /// Leave the balance out of the cost envelope a planned team's pattern
    /// run reads (FIX 9536); off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub balance_free_prompt: bool,
}

impl SelfSpawnAsk {
    /// The planner's need: this ask at the type the host placed.
    #[must_use]
    pub fn into_need(
        self,
        type_ref: crate::task_type::TaskTypeRef,
    ) -> crate::agent_dispatch::SpawnNeed {
        crate::agent_dispatch::SpawnNeed {
            need: self.need,
            care: self.care,
            notes: self.notes,
            type_ref,
            model: self.model,
            width: self.width,
            pattern: self.pattern,
            budget_cap_units: self.budget_cap_units,
            balance_free_prompt: self.balance_free_prompt,
        }
    }
}

/// The bound leader's calls (OF-389). Guest text selects; it never names a
/// lease, a task or a principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfLeaderCall {
    /// Her top `top` team shapes, the host's count when unset. Advice
    /// only: no work starts.
    Advice { top: Option<u32> },
    /// Load the pattern workflow she picked from the advice. Selecting a
    /// pattern is not a spawn.
    Pattern { skill: EntityId },
    /// Split her TASK into a subproject under the TASK's project, led by
    /// `leader` (herself when unset) over `slice` (the parent's when
    /// unset). The host binds the TASK and the project from her lease.
    Split {
        leader: Option<EntityId>,
        slice: Option<crate::llm::Scope>,
    },
}
