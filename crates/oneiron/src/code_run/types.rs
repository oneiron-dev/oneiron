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
    /// Fixture for `self.memory.search(...)`.
    MemorySearch(SelfMemorySearchCall),
    /// Internal fixture proving dispatcher-stamped writes use the batch/gate path.
    ///
    /// This is not the CODE-007a public `self.memory.put_claim` trap surface.
    MemoryWriteFixture(SelfMemoryWriteFixtureCall),
    /// Public first-party `self.memory.put_claim(...)` trap.
    MemoryPutClaim(SelfMemoryPutClaimCall),
    /// Public first-party `self.memory.supersede_claim(...)` trap.
    MemorySupersedeClaim(SelfMemorySupersedeClaimCall),
    /// Public first-party `self.memory.put_edge(...)` trap.
    MemoryPutEdge(SelfMemoryPutEdgeCall),
    /// Fixture for `self.ask_human(...)`.
    AskHuman(SelfAskHumanCall),
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
}

impl SelfCall {
    /// Returns the host effect class for this call.
    #[must_use]
    pub const fn effect(&self) -> SelfEffect {
        match self {
            Self::MemorySearch(_) => SelfEffect::MemorySearch,
            Self::MemoryWriteFixture(_) => SelfEffect::MemoryWriteFixture,
            Self::MemoryPutClaim(_) => SelfEffect::MemoryPutClaim,
            Self::MemorySupersedeClaim(_) => SelfEffect::MemorySupersedeClaim,
            Self::MemoryPutEdge(_) => SelfEffect::MemoryPutEdge,
            Self::AskHuman(_) => SelfEffect::AskHuman,
            Self::DestructiveFixture(_) => SelfEffect::DestructiveFixture,
            Self::OutboundFixture(_) => SelfEffect::OutboundFixture,
            Self::Context(_) => SelfEffect::Context,
            Self::Speak(_) => SelfEffect::Speak,
            Self::Think(_) => SelfEffect::Think,
            Self::Express(_) => SelfEffect::Express,
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
            other => other,
        }
    }
}

/// Host effect class routed by the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfEffect {
    MemorySearch,
    MemoryWriteFixture,
    MemoryPutClaim,
    MemorySupersedeClaim,
    MemoryPutEdge,
    AskHuman,
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
}

impl SelfEffect {
    /// Stable effect label used in host-generated provenance.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemorySearch => "self.memory.search",
            Self::MemoryWriteFixture => "self.memory.write_fixture",
            Self::MemoryPutClaim => "self.memory.put_claim",
            Self::MemorySupersedeClaim => "self.memory.supersede_claim",
            Self::MemoryPutEdge => "self.memory.put_edge",
            Self::AskHuman => "self.ask_human",
            Self::DestructiveFixture => "self.fixture.destructive",
            Self::OutboundFixture => "self.fixture.outbound",
            Self::TaskDelegate => "self.tasks.delegate",
            Self::Context => "self.context",
            Self::Speak => "self.speak",
            Self::Think => "self.think",
            Self::Express => "self.express",
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
            Self::MemorySearch
            | Self::MemoryWriteFixture
            | Self::MemoryPutClaim
            | Self::MemorySupersedeClaim
            | Self::MemoryPutEdge
            | Self::AskHuman
            | Self::DestructiveFixture
            | Self::OutboundFixture
            | Self::TaskDelegate
            | Self::Context => None,
        }
    }

    /// Whether this effect belongs to the `self.speak` family.
    #[must_use]
    pub const fn is_speech(self) -> bool {
        self.speech_utterance().is_some()
    }
}

/// Arguments for the `self.memory.search` fixture call.
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

/// Arguments for the public `self.memory.put_claim` trap.
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

/// Arguments for the public `self.memory.supersede_claim` trap.
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

/// Arguments for the public `self.memory.put_edge` trap.
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

/// Arguments for the `self.ask_human` fixture call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfAskHumanCall {
    pub prompt: String,
}

impl SelfAskHumanCall {
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

/// Result of dispatching a `self.*` call.
#[derive(Debug, Clone, PartialEq)]
pub enum SelfDispatchOutcome {
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

/// Result of a `self.memory.search` fixture dispatch.
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

/// Result of a public `self.memory.put_edge` trap.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfDurableWait {
    pub wait_id: EntityId,
    pub effect: SelfEffect,
    pub reason: SelfDurableWaitReason,
    pub prompt: Option<String>,
}

/// Why a dispatched effect parked instead of committing immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
