//! Answers and durable waits recorded for first-party calls.
//! Entry type: `SelfDispatchOutcome`.
//! Definitions live here; `code_run::types` forwards the old names.

use super::*;

/// Result of dispatching a `self.*` call.
#[derive(Debug, Clone, PartialEq)]
pub enum SelfDispatchOutcome {
    AgentSpawn(SelfAgentSpawnResult),
    AgentDefinitionPut(SelfAgentDefinitionPutResult),
    TaskAsk(crate::task_verb::TaskAskReceipt),
    TaskAskStatus(crate::task_verb::TaskAskStatus),
    MemorySearch(SelfMemorySearchResult),
    MemoryWrite(SelfMemoryWriteResult),
    MemoryEdgeWrite(SelfMemoryEdgeWriteResult),
    DurableWait(SelfDurableWait),
    Denied(SelfDeniedResult),
    Failed(SelfFailedResult),
    /// The descriptor `self.context(spec)` handed back, normalized.
    Context(SelfContextResult),
    /// One durable MESSAGE bubble emitted by the speech family (ONE-1686).
    Speech(SelfSpeechResult),
    ReportBlocked {
        receipt: EntityId,
    },
    /// JSON of the effective rows after a read or atomic replacement.
    InferenceDefaults(String),
    /// The authorized v1 policy row that was persisted in the vault.
    WakePolicyWritten(crate::dreamer_wake::DreamerWakePolicy),
    /// The verb's answer: its JSON output and the rows that produced it.
    AgentVerb(AgentVerbAnswer),
    /// A fold verb's answer, as JSON.
    Fold(String),
    /// What the agent's dial made of her refusal.
    TaskRefusal(SelfTaskRefusalResult),
    /// What one callable skill returned.
    SkillCall(SelfSkillCallResult),
    /// A queued reader child.
    ReaderSpawn(super::reader::ReaderSpawnReceipt),
    /// A reader child's finding, kept.
    ReaderReport(super::reader::ReaderReportReceipt),
    /// One reduction of a wait over the run's reader children.
    TaskWaitSet(super::reader::TaskWaitSetResult),
    /// A summary's card, its job while it is made, or a withheld member's
    /// reply.
    Summarize(super::reader::SummarizeReply),
    /// The leader's advice or loaded pattern, as JSON.
    Leader(String),
    /// A team run's start or receipt (OF-540).
    Team(crate::team::TeamRunAnswer),
    /// A team output submitted for the owner's review (OF-540).
    TeamSubmitted(super::TeamSubmitAnswer),
}

/// What one callable skill returned: JSON its contract's `returns` shape
/// admitted.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfSkillCallResult {
    pub skill: EntityId,
    pub output: serde_json::Value,
}

/// What one self-refusal became.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTaskRefusalResult {
    pub task_ref: EntityId,
    /// Where her dial sat; the outcome is the level's.
    pub level: crate::agent_def::RefusalLevel,
    /// A byte-identical retry answered by the first decision.
    pub replay: bool,
}

impl SelfTaskRefusalResult {
    /// Whether the refusal declined the TASK: the run does nothing more for it.
    #[must_use]
    pub const fn declined(&self) -> bool {
        matches!(
            self.level.outcome(),
            crate::agent_def::RefusalOutcome::Decline
        )
    }

    /// The outcome's wire word.
    #[must_use]
    pub const fn outcome_word(&self) -> &'static str {
        match self.level.outcome() {
            crate::agent_def::RefusalOutcome::Proceed => "proceed",
            crate::agent_def::RefusalOutcome::Object => "object",
            crate::agent_def::RefusalOutcome::Decline => "decline",
        }
    }
}

/// Result of one `self.speak`/`self.think`/`self.express` call.
///
/// Carries no message or turn id ON PURPOSE: those are minted per emission and
/// would make the replay row — and the step state hash over it — depend on
/// identity the run cannot reproduce. What replay needs is WHICH bubble the
/// call emitted, which is exactly the effect, its position and its visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfSpeechResult {
    pub effect: SelfEffect,
    /// The bubble's `order`: this call's position in the run's bridge ordering.
    pub order: u32,
    /// `true` for speak/express, `false` for think.
    pub is_visible: bool,
    /// Whether a durable MESSAGE bubble was materialized.
    ///
    /// Always `true` on a value the dispatcher builds, on BOTH storage arms:
    /// a speech effect either materializes its bubble or fails, and a failure
    /// is a `Denied`/`Failed`/`DurableWait` outcome instead. The field stays
    /// because it is the guest-visible and replay-visible statement of that
    /// fact, and the replay decoder REFUSES a speech outcome carrying `false`
    /// — an incoherent row, not a weaker one.
    pub emitted: bool,
}

/// Result of the `self.context` descriptor bridge: the spec as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfContextResult {
    pub spec: ContextSpec,
}

/// Result of a `vault.search` fixture dispatch.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemorySearchResult {
    pub query: String,
    pub results: Vec<ScoredEntity>,
    /// What each verb hook bound to the search did, in a room (WILL L11-01
    /// S01-2c); empty outside one.
    pub hooks: Vec<SessionHookDisposition>,
}

/// Result of an internal fixture memory write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfMemoryWriteResult {
    pub id: EntityId,
}

/// Result of a public `vault.edges.put` trap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelfMemoryEdgeWriteResult {
    pub src: EntityId,
    pub kind: EdgeKind,
    pub tgt: EntityId,
}

/// Result of a `self.*` trap rejected after the gate recorded an audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfDeniedResult {
    pub effect: SelfEffect,
    pub outcome: String,
    pub reason_codes: Vec<String>,
}

/// Result of a `self.*` trap that failed after crossing an audited write boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfFailedResult {
    pub effect: SelfEffect,
    pub error: String,
}

/// Durable wait produced for effects that need human/external resolution.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SelfDurableWait {
    pub wait_id: EntityId,
    pub effect: SelfEffect,
    pub reason: SelfDurableWaitReason,
    pub prompt: Option<String>,
}

/// Why a dispatched effect parked instead of committing immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SelfDurableWaitReason {
    HumanInput,
    DestructiveEffect,
    OutboundEffect,
    /// Waiting on a peer executor's result landing on a delegated TASK
    /// (ONE-1700). The three reasons above are all consent-scale; this one is
    /// not, which is why it maps to its own trap kind.
    PeerResult,
}

/// The durable wait a peer delegation raises: the delegated TASK ref IS the
/// wait id, so the trap, the local binding, and the replicated result all key
/// on one entity.
#[must_use]
pub const fn peer_result_wait(task_ref: EntityId) -> SelfDurableWait {
    SelfDurableWait {
        wait_id: task_ref,
        effect: SelfEffect::TaskDelegate,
        reason: SelfDurableWaitReason::PeerResult,
        prompt: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfAgentDefinitionPutResult {
    pub id: EntityId,
    pub disposition: crate::agent_def::AgentDefinitionPutDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfAgentSpawnResult {
    Queued {
        attempt_ref: crate::attempt_queue::AttemptId,
        /// The statement frozen at launch (OF-532): its agent count,
        /// expected spend and cap. `None` only for a launch that stated none.
        launch: Option<crate::agent_dispatch::LaunchStatement>,
        /// OF-541: the asked fields a direct spawn did not apply, and why.
        /// Empty for a planned spawn.
        unapplied: Vec<crate::agent_dispatch::SpawnUnapplied>,
    },
    ProposedWiden {
        proposal_ref: String,
        /// As on `Queued`.
        unapplied: Vec<crate::agent_dispatch::SpawnUnapplied>,
    },
    /// An erase took the AGENT_DEF the planned spawn's plan seats (Engine
    /// 10-22): the intent records it, and nothing launched.
    TargetErased,
}
