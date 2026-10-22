//! Host and replay effect labels for first-party calls.
//! Entry type: `SelfEffect`.
//! Definitions live here; `code_run::types` forwards the old names.

use super::*;

/// Host effect class routed by the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SelfEffect {
    AgentsSpawn,
    TasksAsk,
    TasksWait,
    /// The agent's own refusal of its bound TASK (OF-533).
    TasksRefuse,
    /// An addressed peer's run landing its consult answer or abstention
    /// (DOOR-063).
    ConsultResult,
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
    /// An answer to a connector's mid-call questions, sent by the host's
    /// bound verb door (ONE-2510).
    ConnectorAnswer,
    /// A world-settings request of the run's agent, answered by the vault's
    /// world-privacy door (FIX 4480).
    WorldPrivacySet,
    /// A fold verb on the run's own log, answered by its fold ledger.
    Fold,
    /// A reader child queued over one of the run's results.
    ReaderSpawn,
    /// A reader child's finding.
    ReaderReport,
    /// A wait over the run's reader children.
    TasksWaitSet,
    /// A summary of the run's results, made by a host job.
    Summarize,
    /// The bound leader's advice or pattern load (OF-389).
    Leader,
    /// The bound leader's split of her TASK into a subproject (OF-389): a
    /// write, apart from her reads.
    LeaderSplit,
    /// A team run the bound agent leads: its start or its receipt.
    Team,
    /// A saved workflow's run the leased agent binds to a TASK it owns,
    /// under its own lease (FIX 5316).
    WorkflowDispatch,
    /// The run repo rows (FIX 6867), one effect a row: the leased run's
    /// snapshot manifest, file and definitions reads, its own work's reads
    /// and queue, its import and its work's open.
    RepoSnapshotsGet,
    RepoSnapshotsRead,
    RepoSymbolsDefinitions,
    RepoViewsGet,
    RepoViewsRead,
    RepoMergeQueueObserve,
    RepoSnapshotsIngest,
    RepoWorkOpen,
    /// The run repo write rows of PR2b (FIX 6867): its symbol declaration,
    /// renewal and release, its proposal and its queue entry.
    RepoSymbolsDeclare,
    RepoSymbolsRenew,
    RepoSymbolsRelease,
    RepoProposalSubmit,
    RepoMergeQueueEnqueue,
    /// The run's checkout binding and export (FIX 6867, G1 PR3b).
    RepoCheckoutBind,
    RepoExport,
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
            Self::ConsultResult => "tasks.consult.result",
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
            Self::ConnectorAnswer => "connector.answer",
            Self::WorldPrivacySet => "vault.worlds.privacy.set",
            Self::Fold => "self.fold",
            Self::ReaderSpawn => "self.spawn",
            Self::ReaderReport => "tasks.update",
            Self::TasksWaitSet => "tasks.wait_set",
            Self::Summarize => "summarize",
            Self::Leader => "self.leader",
            Self::LeaderSplit => "self.leader.split",
            Self::Team => "self.team",
            Self::WorkflowDispatch => "self.workflows.dispatch_bound",
            Self::RepoSnapshotsGet => "self.code.snapshots.get",
            Self::RepoSnapshotsRead => "self.code.snapshots.read",
            Self::RepoSymbolsDefinitions => "self.code.symbols.definitions",
            Self::RepoViewsGet => "self.code.views.get",
            Self::RepoViewsRead => "self.code.views.read",
            Self::RepoMergeQueueObserve => "self.code.merge_queue.observe",
            Self::RepoSnapshotsIngest => "self.code.snapshots.ingest",
            Self::RepoWorkOpen => "self.code.work.open",
            Self::RepoSymbolsDeclare => "self.code.symbols.declare",
            Self::RepoSymbolsRenew => "self.code.symbols.renew",
            Self::RepoSymbolsRelease => "self.code.symbols.release",
            Self::RepoProposalSubmit => "self.code.proposal_submit",
            Self::RepoMergeQueueEnqueue => "self.code.merge_queue.enqueue",
            Self::RepoCheckoutBind => "self.code.checkout.bind",
            Self::RepoExport => "self.code.export",
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
            | Self::ConsultResult
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
            Self::WakePolicyWrite
            | Self::AgentVerb
            | Self::ConnectorAnswer
            | Self::WorldPrivacySet
            | Self::Fold => None,
            Self::ReaderSpawn | Self::ReaderReport | Self::TasksWaitSet | Self::Summarize => None,
            Self::Leader | Self::LeaderSplit => None,
            Self::Team | Self::WorkflowDispatch => None,
            Self::RepoSnapshotsGet
            | Self::RepoSnapshotsRead
            | Self::RepoSymbolsDefinitions
            | Self::RepoViewsGet
            | Self::RepoViewsRead
            | Self::RepoMergeQueueObserve
            | Self::RepoSnapshotsIngest
            | Self::RepoWorkOpen
            | Self::RepoSymbolsDeclare
            | Self::RepoSymbolsRenew
            | Self::RepoSymbolsRelease
            | Self::RepoProposalSubmit
            | Self::RepoMergeQueueEnqueue
            | Self::RepoCheckoutBind
            | Self::RepoExport => None,
        }
    }

    /// Whether this effect belongs to the `self.speak` family.
    #[must_use]
    pub const fn is_speech(self) -> bool {
        self.speech_utterance().is_some()
    }
}
