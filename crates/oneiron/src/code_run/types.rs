// Referenced only by an intra-doc link on `SelfCall::MemoryWriteFixture`;
// gated so the name is in scope for rustdoc without being an unused import.
#[cfg(doc)]
use crate::Vault;
use crate::context_projection::ContextSpec;
use crate::off_record::ExecutorUtterance;
use crate::{ClaimCandidate, EdgeKind, EntityId, Result, ScoredEntity, TimeRange};

/// Dispatcher for host-side `self.*` calls emitted by a first-party runtime.
pub trait SelfDispatcher {
    /// Routes one typed call through the host-owned dispatcher.
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome>;
}

/// Typed first-party host call.
#[derive(Debug, Clone, PartialEq)]
pub enum SelfCall {
    /// Typed bounded dispatch. Parent/run identity comes from the host binding.
    AgentsSpawn(Box<SelfAgentSpawnCall>),
    /// Async question to live scope authority holders. Returns without waiting.
    TasksAsk(Box<crate::task_verb::TaskAskSpec>),
    /// Requests a C9 wait for this handle, only at the caller's idle point.
    TasksWait(crate::task_verb::TaskAskHandle),
    /// The agent's own refusal of the run's bound TASK, through her refusal
    /// dial (OF-533). The TASK comes from the host binding.
    TasksRefuse(SelfTaskRefuseCall),
    /// `self.skills.call` (OF-353): one agent-callable skill, run as a step
    /// of its own under the running attempt's lease, with the caller's host
    /// as its bridge. The lease, executor and runtime are the host's.
    SkillsCall(SelfSkillCall),
    /// Fixture for `vault.search(...)`.
    MemorySearch(SelfMemorySearchCall),
    /// Internal fixture proving dispatcher-stamped writes use the batch/gate path.
    ///
    /// This is not the CODE-007a public `vault.claims.put` trap surface.
    MemoryWriteFixture(SelfMemoryWriteFixtureCall),
    /// Public first-party `vault.claims.put(...)` trap.
    MemoryPutClaim(SelfMemoryPutClaimCall),
    /// Public first-party `vault.claims.supersede(...)` trap.
    MemorySupersedeClaim(SelfMemorySupersedeClaimCall),
    /// Public first-party `vault.edges.put(...)` trap.
    MemoryPutEdge(SelfMemoryPutEdgeCall),
    /// Fixture for `ask(...)`.
    Ask(SelfAskCall),
    /// Fixture for destructive effects, which must park as durable waits.
    DestructiveFixture(SelfFixtureEffectCall),
    /// Fixture for outbound effects, which must park as durable waits.
    OutboundFixture(SelfFixtureEffectCall),
    /// Public first-party `self.context(spec)` bridge (ONE-1709).
    ///
    /// The one `self.*` call that is not an effect: it validates/normalizes a
    /// projection DESCRIPTOR and hands it straight back. It reads no memory,
    /// opens no transaction, consumes no budget, and resolves no prompt text —
    /// resolution happens later, at agent dispatch, so the delegate reads fresh
    /// state instead of a create-time snapshot.
    Context(SelfContextCall),
    /// Public first-party `self.speak(text)` (ONE-1686, RT-04).
    Speak(SelfSpeechCall),
    /// Public first-party `self.think(text)` (ONE-1686, RT-04).
    Think(SelfSpeechCall),
    /// Public first-party `self.express(text)` (ONE-1686, RT-04).
    Express(SelfSpeechCall),
    ReportBlocked(super::blocked::SelfReportBlockedCall),
    /// Reusable definition authoring, independent of launching a child.
    AgentsPut(Box<SelfAgentDefinitionPutCall>),
    /// Read the active inference rows through the host-bound resident action.
    InferenceDefaultsRead,
    /// Replace validated inference rows under the host's delegated policy gate.
    InferenceDefaultsReplace(String),
    /// Host-authorized action; a guest request alone carries no owner proof.
    WakePolicyWrite(SelfWakePolicyWriteCall),
    /// A verb at its SDK path (`vault.recall(input)`): one row of the SDK verb table.
    AgentVerb(SelfAgentVerbCall),
    /// `self.fold`, `self.compact`, `self.unfold`, `self.folds` and
    /// `describe({fold})`: the run's own log (ARCH-0067 §2.2).
    Fold(crate::compaction::SelfFoldCall),
    /// `self.spawn`: one reader child over a result of the run, queued on
    /// the run's route (ARCH-0079 #reader-forks). The parent run is the
    /// bridge call's.
    ReaderSpawn(Box<super::reader::SelfReaderSpawnCall>),
    /// `tasks.update({task_ref, resultRef})` from a reader child: its
    /// finding, one of its own stored results.
    ReaderReport(super::reader::SelfReaderReportCall),
    /// `self.team.start` and `self.team.record` (OF-540): a pattern-skill
    /// run's own team. The leader is the bound attempt.
    Team(crate::team::SelfTeamCall),
    /// `tasks.wait({tasks, ...})`: one wait over the run's reader children.
    TasksWaitSet(super::reader::TaskWaitSetCall),
    /// `self.leader.advice` and `self.leader.pattern` (OF-389): the bound
    /// leader's top shapes, and the pattern she picked from them, on the
    /// host's planner binding. The lease and the skills are the host's.
    Leader(SelfLeaderCall),
}

impl SelfCall {
    /// Returns the host effect class for this call.
    #[must_use]
    pub const fn effect(&self) -> SelfEffect {
        match self {
            Self::AgentsSpawn(_) => SelfEffect::AgentsSpawn,
            Self::AgentsPut(_) => SelfEffect::AgentsPut,
            Self::TasksAsk(_) => SelfEffect::TasksAsk,
            Self::TasksWait(_) => SelfEffect::TasksWait,
            Self::TasksRefuse(_) => SelfEffect::TasksRefuse,
            Self::SkillsCall(_) => SelfEffect::SkillsCall,
            Self::MemorySearch(_) => SelfEffect::MemorySearch,
            Self::MemoryWriteFixture(_) => SelfEffect::MemoryWriteFixture,
            Self::MemoryPutClaim(_) => SelfEffect::MemoryPutClaim,
            Self::MemorySupersedeClaim(_) => SelfEffect::MemorySupersedeClaim,
            Self::MemoryPutEdge(_) => SelfEffect::MemoryPutEdge,
            Self::Ask(_) => SelfEffect::Ask,
            Self::DestructiveFixture(_) => SelfEffect::DestructiveFixture,
            Self::OutboundFixture(_) => SelfEffect::OutboundFixture,
            Self::Context(_) => SelfEffect::Context,
            Self::Speak(_) => SelfEffect::Speak,
            Self::Think(_) => SelfEffect::Think,
            Self::Express(_) => SelfEffect::Express,
            Self::ReportBlocked(_) => SelfEffect::ReportBlocked,
            Self::InferenceDefaultsRead => SelfEffect::InferenceDefaultsRead,
            Self::InferenceDefaultsReplace(_) => SelfEffect::InferenceDefaultsReplace,
            Self::WakePolicyWrite(_) => SelfEffect::WakePolicyWrite,
            Self::AgentVerb(_) => SelfEffect::AgentVerb,
            Self::Fold(_) => SelfEffect::Fold,
            Self::ReaderSpawn(_) => SelfEffect::ReaderSpawn,
            Self::ReaderReport(_) => SelfEffect::ReaderReport,
            Self::TasksWaitSet(_) => SelfEffect::TasksWaitSet,
            Self::Leader(_) => SelfEffect::Leader,
            Self::Team(_) => SelfEffect::Team,
        }
    }

    /// Stamps the HOST-owned bridge ordering onto a speech call.
    ///
    /// `seq` is the call's position in the run's total bridge ordering — the
    /// same number the replay row carries — and `started_at_ms` is the frozen
    /// determinism clock for that position. Guest code supplies neither: the
    /// bridge overwrites whatever arrived, exactly as the dispatcher binds
    /// actor and source outside the guest payload, so a guest cannot forge the
    /// order or the timestamp of its own bubble.
    ///
    /// Non-speech calls are returned unchanged, so the bridge can stamp every
    /// call unconditionally and existing request encodings stay byte-identical.
    #[must_use]
    pub fn with_bridge_stamp(self, seq: u64, started_at_ms: u64) -> Self {
        let order = u32::try_from(seq).unwrap_or(u32::MAX);
        let occurred_at = started_at_ms / 1000;
        match self {
            Self::Speak(call) => Self::Speak(call.with_bridge_stamp(order, occurred_at)),
            Self::Think(call) => Self::Think(call.with_bridge_stamp(order, occurred_at)),
            Self::Express(call) => Self::Express(call.with_bridge_stamp(order, occurred_at)),
            Self::ReportBlocked(call) => Self::ReportBlocked(call.stamped(order, occurred_at)),
            other => other,
        }
    }
}

/// Host effect class routed by the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SelfEffect {
    AgentsSpawn,
    TasksAsk,
    TasksWait,
    /// The agent's own refusal of its bound TASK (OF-533).
    TasksRefuse,
    /// An agent-callable skill run on the caller's lease (OF-353).
    SkillsCall,
    MemorySearch,
    MemoryWriteFixture,
    MemoryPutClaim,
    MemorySupersedeClaim,
    MemoryPutEdge,
    Ask,
    DestructiveFixture,
    OutboundFixture,
    /// A workflow step handing work to a peer executor over the synced TASK
    /// (ONE-1700). It parks on C9 exactly as the consent-scale effects do.
    TaskDelegate,
    /// `self.context(spec)` (ONE-1709) — a descriptor round-trip, not an
    /// effect. It is a `SelfEffect` only so the replay log stays a total
    /// ordering over every bridge call.
    Context,
    /// `self.speak(text)` (ONE-1686) — an addressed utterance.
    Speak,
    /// `self.think(text)` (ONE-1686) — reasoning the run keeps for itself.
    Think,
    /// `self.express(text)` (ONE-1686) — non-verbal expression.
    Express,
    ReportBlocked,
    AgentsPut,
    InferenceDefaultsRead,
    InferenceDefaultsReplace,
    WakePolicyWrite,
    /// One SDK verb-table call, run by the host's bound verb door.
    AgentVerb,
    /// A fold verb on the run's own log, answered by its fold ledger.
    Fold,
    /// A reader child queued over one of the run's results.
    ReaderSpawn,
    /// A reader child's finding.
    ReaderReport,
    /// A wait over the run's reader children.
    TasksWaitSet,
    /// The bound leader's advice or pattern load (OF-389).
    Leader,
    /// A team run the bound agent leads: its start or its receipt.
    Team,
}

impl SelfEffect {
    /// Stable effect label used in host-generated provenance.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentsSpawn => "agents.spawn",
            Self::AgentsPut => "vault.agents.put",
            Self::TasksAsk => "tasks.ask",
            Self::TasksWait => "tasks.wait",
            Self::TasksRefuse => "tasks.refuse",
            Self::SkillsCall => "self.skills.call",
            Self::MemorySearch => "self.memory.search",
            Self::MemoryWriteFixture => "self.memory.write_fixture",
            Self::MemoryPutClaim => "self.memory.put_claim",
            Self::MemorySupersedeClaim => "self.memory.supersede_claim",
            Self::MemoryPutEdge => "self.memory.put_edge",
            Self::Ask => "ask",
            Self::DestructiveFixture => "self.fixture.destructive",
            Self::OutboundFixture => "self.fixture.outbound",
            Self::TaskDelegate => "self.tasks.delegate",
            Self::Context => "self.context",
            Self::Speak => "self.speak",
            Self::Think => "self.think",
            Self::Express => "self.express",
            Self::ReportBlocked => "self.report_blocked",
            Self::InferenceDefaultsRead => "self.inference_defaults.read",
            Self::InferenceDefaultsReplace => "self.inference_defaults.replace",
            Self::WakePolicyWrite => "dreamer.wake_policy.set",
            Self::AgentVerb => "self.verbs.call",
            Self::Fold => "self.fold",
            Self::ReaderSpawn => "self.spawn",
            Self::ReaderReport => "tasks.update",
            Self::TasksWaitSet => "tasks.wait_set",
            Self::Leader => "self.leader",
            Self::Team => "self.team",
        }
    }

    /// Which executor utterance this effect emits, if it is a speech effect.
    ///
    /// The speech family and [`ExecutorUtterance`] are the SAME three verbs
    /// seen from the bridge and from the witness door. Mapping them here — in
    /// one exhaustive match — is what keeps a fourth speech effect from
    /// silently defaulting to a visibility or a message type nobody chose.
    #[must_use]
    pub const fn speech_utterance(self) -> Option<ExecutorUtterance> {
        match self {
            Self::Speak => Some(ExecutorUtterance::Speak),
            Self::Think => Some(ExecutorUtterance::Think),
            Self::Express => Some(ExecutorUtterance::Express),
            Self::AgentsSpawn
            | Self::AgentsPut
            | Self::TasksAsk
            | Self::TasksWait
            | Self::TasksRefuse
            | Self::SkillsCall
            | Self::MemorySearch
            | Self::MemoryWriteFixture
            | Self::MemoryPutClaim
            | Self::MemorySupersedeClaim
            | Self::MemoryPutEdge
            | Self::Ask
            | Self::DestructiveFixture
            | Self::OutboundFixture
            | Self::TaskDelegate
            | Self::Context
            | Self::ReportBlocked
            | Self::InferenceDefaultsRead
            | Self::InferenceDefaultsReplace => None,
            Self::WakePolicyWrite | Self::AgentVerb | Self::Fold => None,
            Self::ReaderSpawn | Self::ReaderReport | Self::TasksWaitSet | Self::Leader => None,
            Self::Team => None,
        }
    }

    /// Whether this effect belongs to the `self.speak` family.
    #[must_use]
    pub const fn is_speech(self) -> bool {
        self.speech_utterance().is_some()
    }
}

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

/// A verb call's answer, as the host door gives it and the run records it:
/// the verb's JSON output, exactly as its other doors return it, and the rows
/// the door listed as served in producing it (DEC-0005), ids only. The record
/// keeps the rows beside the output, so a re-entered run's replayed answers
/// are released by the rows that produced them. A door always lists them;
/// `None` is only an answer recorded with no set, which no caller off this
/// device is released.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentVerbAnswer {
    pub output: serde_json::Value,
    pub rows: Option<Vec<EntityId>>,
}

/// A verb call the bound door refused or could not run, as the guest sees it:
/// a stable code, never prose. Agent-facing words are configuration, so the
/// host or prompt layer supplies any wording for a code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentVerbRefusal {
    pub code: String,
}

/// The refusal a verb call gets from a run whose host binds no verb door.
pub const AGENT_VERB_DOOR_UNBOUND: &str = "agent_verb_door_unbound";

/// The refusal a verb call gets from a run bound to an off-record session:
/// the host's door runs on the canonical vault, where the session's route
/// and saver are not checked.
pub const AGENT_VERB_SESSION_BOUND: &str = "agent_verb_session_bound";

/// The host's door onto the SDK verb table.
///
/// The engine runs no verb here. The host that binds this door runs each call
/// with its own actor ceiling and gate, exactly as its other doors do, so code
/// mode holds no authority a direct call lacks. Unbound, a verb call is refused.
///
/// The door binds `origin` onto the memory surface the verb runs on, so the
/// verb's claims carry the run's `Generated` source, lineage and provenance,
/// never a source the guest's input names. Its answer lists the rows the
/// verb served, as its other doors list them for release.
///
/// The door binds `invocation`, the call's step's id, as the logical verb
/// the row's verb hooks fire once for (ARCH-0080 §3). The outer `Err` is
/// only a hook's stop (`Error::VerbHook`); every refusal is the inner one.
pub trait AgentVerbDoor: Send + Sync {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &crate::memory::HostWriteOrigin,
        invocation: crate::runtime_hooks::InvocationId,
    ) -> crate::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>>;

    /// Admits one call the run serves itself, before it runs. The host's
    /// ceiling and credential bind these as they bind [`Self::call`], so a run
    /// keeps no authority its door has lost or never had. A search admitted
    /// with a key reads only what that key's lane admits, and a facet stamp
    /// admitted with one places only a row that lane reads. A refusal spelled as
    /// a gate's outcome word (`pending`, `deny`) is taken as that gate's: the
    /// run's bridge halts after it, as after any gate's refusal.
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> std::result::Result<Option<crate::claim::ScopedReadActorKey>, AgentVerbRefusal>;

    /// Whether a result the run retained stays on this device for the door's
    /// caller now (DEC-0005), re-checked at each read of it: `rows` are the
    /// rows the run was served producing it, `None` when one of its answers
    /// was recorded with no row set. A door whose caller sits on this device
    /// withholds nothing.
    fn withholds_retained(
        &self,
        _rows: Option<&[EntityId]>,
    ) -> std::result::Result<bool, AgentVerbRefusal> {
        Ok(false)
    }
}

/// One call a run serves itself, as its host door is asked about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCall {
    /// A call over the bridge: a run row such as `vault.search` or
    /// `vault.claims.put`, or a `self.*` import. The run's trailing
    /// implicit speech is a `self.speak` too.
    Bridge(SelfEffect),
    /// A read of the run's own recorded output: by its context reference, or
    /// a resumed write's kept answer, read back from its receipt.
    RecordedOutput,
}

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
    /// The leader's advice or loaded pattern, as JSON.
    Leader(String),
    /// A team run's start or receipt (OF-540).
    Team(crate::team::TeamRunAnswer),
}

/// `self.skills.call(...)`: the skill and the arguments its call contract
/// takes. No lease, executor or runtime comes from the guest.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfSkillCall {
    pub skill: EntityId,
    pub args: serde_json::Value,
}

/// What one callable skill returned: JSON its contract's `returns` shape
/// admitted.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfSkillCallResult {
    pub skill: EntityId,
    pub output: serde_json::Value,
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

/// No actor, source, lease or approval fields are accepted from guest code.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfAgentDefinitionPutCall {
    pub id: EntityId,
    pub definition: Box<crate::agent_def::AgentDefinition>,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfAgentDefinitionPutResult {
    pub id: EntityId,
    pub disposition: crate::agent_def::AgentDefinitionPutDisposition,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfAgentSpawnResult {
    Queued {
        attempt_ref: crate::attempt_queue::AttemptId,
    },
    ProposedWiden {
        proposal_ref: String,
    },
}
