//! Guest-authored calls accepted by a first-party code runtime.
//! Entry type: `SelfCall`.
//! Definitions live here; `code_run::types` forwards the old names.

use super::*;

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
    /// `tasks.consult.result` (DOOR-063): the addressed peer's run lands its
    /// answer or abstention on one consult TASK. The actor comes from the
    /// host binding's live lease.
    ConsultResult(crate::task_verb::run_doors::ConsultLandRequest),
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
    /// state instead of a create-time snapshot. A verb hook bound to it runs
    /// around it on canonical storage, as around any call.
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
    /// `connector.answer` (ONE-2510): the run's answer to the questions a
    /// connector asked mid-call, sent through the bound door under the
    /// original call's grant and principal.
    ConnectorAnswer(crate::task_verb::sdk::ConnectorAnswerRequest),
    /// `vault.worlds.privacy.set` (FIX 4480): the run's agent asks to change
    /// a world's settings, within the owner's rules.
    WorldPrivacySet(crate::policy_model::WorldPrivacySetInput),
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
    /// `self.team.submit` (OF-540): the bound leader submits one pinned
    /// output of its team for the owner's acceptance review.
    TeamSubmit(super::TeamSubmitInput),
    /// `self.workflows.dispatch_bound` (FIX 5316): the run's agent binds one
    /// run of a saved workflow to a TASK it owns. The actor, the parent, the
    /// run and the spend come from the host binding's live lease.
    WorkflowDispatch(Box<crate::task_verb::sdk::WorkflowBoundDispatchRequest>),
    /// `tasks.wait({tasks, ...})`: one wait over the run's reader children.
    TasksWaitSet(super::reader::TaskWaitSetCall),
    /// `summarize(r, {effort?, group?, defer?})`: one summary of the run's
    /// results, made by a host job on the run's route and memoised by its
    /// members' occurrences and recipe.
    Summarize(Box<super::reader::SelfSummarizeCall>),
    /// `self.leader.advice`, `self.leader.pattern` and `self.leader.split`
    /// (OF-389): the bound leader's top shapes and the pattern she picked
    /// from them, on the host's planner binding, and the split of her TASK
    /// into a subproject, signed by the host's issuer. The lease, the skills,
    /// the TASK and the key are the host's.
    Leader(SelfLeaderCall),
    /// `self.code.*` (FIX 6867): a leased agent run's own repo reads, import
    /// and work, under its owner's Grant. The actor, lease, TASK and run come
    /// from the host binding.
    Repo(super::repo_calls::RepoRunCall),
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
            Self::ConsultResult(_) => SelfEffect::ConsultResult,
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
            Self::ConnectorAnswer(_) => SelfEffect::ConnectorAnswer,
            Self::WorldPrivacySet(_) => SelfEffect::WorldPrivacySet,
            Self::Fold(_) => SelfEffect::Fold,
            Self::ReaderSpawn(_) => SelfEffect::ReaderSpawn,
            Self::ReaderReport(_) => SelfEffect::ReaderReport,
            Self::TasksWaitSet(_) => SelfEffect::TasksWaitSet,
            Self::Summarize(_) => SelfEffect::Summarize,
            Self::Leader(SelfLeaderCall::Split { .. }) => SelfEffect::LeaderSplit,
            Self::Leader(_) => SelfEffect::Leader,
            Self::Team(_) | Self::TeamSubmit(_) => SelfEffect::Team,
            Self::WorkflowDispatch(_) => SelfEffect::WorkflowDispatch,
            Self::Repo(call) => call.effect(),
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
