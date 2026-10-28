//! Typed serving payloads and observable extraction receipts.
use crate::{ModelId, affect::Vad, embed::EmbedderLocality};
use serde::{Deserialize, Serialize};
use std::time::Duration;
#[derive(Debug, Clone, Serialize)]
pub struct EncoderMessage {
    pub id: String,
    pub text: String,
}
/// Which side of the conversation a turn is on, read from its messages'
/// stored author: a role, never a guess from turn order or ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpeakerRole {
    /// The user side: the owner or another human.
    #[serde(rename = "A")]
    User,
    /// The companion side: the vault's own agents.
    #[serde(rename = "B")]
    Companion,
}
/// One earlier turn the tagger reads for context and tags nothing in.
#[derive(Debug, Clone, Serialize)]
pub struct EncoderTurn {
    pub turn: String,
    pub messages: Vec<EncoderMessage>,
    /// The turn's side, when its stored authors name one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speaker: Option<SpeakerRole>,
}
/// Which register of its conversation a call reads (FIX 9520, 10167).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncoderRegister {
    /// The live register: the turn and a bounded window of earlier text,
    /// never a later turn. A live call reads it.
    #[default]
    Live,
    /// The whole conversation as it is authorized and stored now: every
    /// earlier turn whole, the turn, then every later turn, in conversation
    /// order, with where it stops short of that. An import, backfill or
    /// other bulk marker reads it. Spans still index the turn's own messages
    /// alone.
    Conversation(RegisterReach),
}
impl EncoderRegister {
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }
}
/// Where a conversation register stops short of its conversation (FIX
/// 10705): neither, for one read whole. A side stops at its bound of turns,
/// keeping the nearest; walking down a DAG it also stops at a branch, whose
/// lines it does not choose between.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterReach {
    /// Turns older than the first of `context` were not read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub earlier_cut: bool,
    /// Turns later than the last of `following` were not read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub later_cut: bool,
}
impl RegisterReach {
    /// Whether the register reads its whole conversation.
    pub const fn is_whole(&self) -> bool {
        !self.earlier_cut && !self.later_cut
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct EncoderInput {
    pub turn: String,
    pub messages: Vec<EncoderMessage>,
    /// Earlier turns of the same conversation, oldest first: the live
    /// register's window, or every earlier turn of the conversation
    /// register. Empty for a turn read alone. Spans index `messages` only.
    pub context: Vec<EncoderTurn>,
    /// Later turns of the same conversation, oldest first: only the
    /// conversation register carries them ([`EncoderRegister`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub following: Vec<EncoderTurn>,
    /// The register this input reads.
    #[serde(skip_serializing_if = "EncoderRegister::is_live")]
    pub register: EncoderRegister,
    /// The input's language as a lowercase ISO 639 code, only when a stored
    /// or configured fact names it; without it the tagger detects it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// The current turn's side, when its stored authors name one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speaker: Option<SpeakerRole>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NerSpan {
    pub message: usize,
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub confidence: f32,
}
/// Two spans of this turn in one entity: `antecedent` is the nearest
/// earlier mention of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorefLink {
    pub span: usize,
    pub antecedent: usize,
    /// The tagger's confidence in the decision, when it gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
}
/// A span whose antecedent is in a context turn: addressed by the turn and
/// message ids the input sent and half-open UTF-8 byte offsets into that
/// message's text as sent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextLink {
    pub span: usize,
    pub turn: String,
    pub message: String,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
}
/// Who a speaker link says a span is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpeakerTarget {
    /// Whoever speaks the span's turn.
    Speaker,
    /// Whoever the span's turn is spoken to.
    Addressee,
}
/// A span that is the speaker or the addressee of its turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpeakerLink {
    pub span: usize,
    pub target: SpeakerTarget,
    pub confidence: f32,
}
/// The mood a model measured over one window of a turn it read in several
/// (FIX 9518): from `message`/`start` to `end_message`/`end`, UTF-8 byte
/// offsets into those messages of the input. The model gives no mood of the
/// whole turn then, and none is made up from the parts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoodPart {
    pub message: usize,
    pub start: usize,
    pub end_message: usize,
    pub end: usize,
    /// Read strictly, as an answer's whole mood is.
    #[serde(deserialize_with = "strict_part_vad")]
    pub vad: Vad,
}
/// What a tagger returns for one input. A model returns what it has heads
/// for: a spans-only model sends no links and no mood. A span carries at
/// most one of a link, a context link and a speaker link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EncoderOutput {
    pub spans: Vec<NerSpan>,
    #[serde(default)]
    pub links: Vec<CorefLink>,
    /// Read strictly: the three coordinates and no other field.
    #[serde(
        default,
        deserialize_with = "strict_vad",
        skip_serializing_if = "Option::is_none"
    )]
    pub vad: Option<Vad>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_links: Vec<ContextLink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub speaker_links: Vec<SpeakerLink>,
    /// The moods of a turn read in several windows, one per window that
    /// measured one, when `vad` is none for that reason (FIX 9518).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mood_parts: Vec<MoodPart>,
    /// The served stack that made the answer, as its model card names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_sha16: Option<String>,
}
/// The mood as a tagger sends it. The shared [`Vad`] reads past fields it
/// does not know; an answer is refused for any field outside the contract.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireVad {
    valence: f32,
    arousal: f32,
    dominance: f32,
}
fn strict_vad<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Vad>, D::Error> {
    Ok(
        Option::<WireVad>::deserialize(deserializer)?.map(|vad| Vad {
            valence: vad.valence,
            arousal: vad.arousal,
            dominance: vad.dominance,
        }),
    )
}
fn strict_part_vad<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vad, D::Error> {
    let vad = WireVad::deserialize(deserializer)?;
    Ok(Vad {
        valence: vad.valence,
        arousal: vad.arousal,
        dominance: vad.dominance,
    })
}
/// The scheduling class of one extraction call. It orders calls in a host's
/// dispatcher and is never part of the input, its digest or a marker's dedupe
/// key: the tagger never sees it. A tagging marker carries one, and the
/// reconciler passes each marker's effective class (FIX 6755).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionWork {
    /// A call someone waits on: the explicit tag door, and a marker a chat or
    /// voice witness commit owes. It goes before every waiting bulk call, and
    /// a running call is never pre-empted for it.
    Live,
    /// Everything else: a marker an import, a host executor, a promotion, a
    /// publication or a recovery owes, and feedback redaction.
    Bulk,
}
/// Who one extraction call is made for: the key a host's dispatcher shares
/// its room by (FIX 9519), so one caller's backlog never holds another's
/// calls back. Opaque and stable: an actor, or a vault's own background
/// tagging, never a process-wide stand-in. Like the class, it is never part
/// of the input, its digest or a marker's dedupe key: the tagger never sees
/// it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtractionCaller(String);
impl ExtractionCaller {
    /// A caller named by `key`.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }
    /// An actor's own calls.
    pub fn actor(actor: &crate::EntityId) -> Self {
        Self(format!("actor:{}", actor.to_hex()))
    }
    /// A vault's own background tagging: its markers, under the vault's
    /// root project, the one id every replica of it gives the same answer.
    pub fn vault(vault: &crate::Vault) -> Self {
        match vault.root_project() {
            Ok(root) => Self(format!("vault:{}", root.to_hex())),
            Err(_) => Self("vault".to_owned()),
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
/// The runtime that ran one call. A call names the runtime that actually ran
/// it, never one it fell back from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionRuntime {
    /// The host's in-process candle runtime.
    Candle,
    /// A configured tagger server: one opaque worker, whose own runtime the
    /// host does not claim.
    Endpoint,
    /// A bundle's MLX platform row, run by the host's managed worker.
    Mlx,
    /// A bundle's Core ML platform row, run in the host's process.
    #[serde(rename = "coreml")]
    CoreMl,
}
impl ExecutionRuntime {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candle => "candle",
            Self::Endpoint => "endpoint",
            Self::Mlx => "mlx",
            Self::CoreMl => "coreml",
        }
    }
}
/// The compute a call's runtime was configured for: what the host asked
/// for, not a reading of which chip ran it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCompute {
    Cpu,
    Metal,
    Cuda,
    /// Core ML's CPU and Neural Engine units, as its model was loaded for.
    CpuAndNe,
    /// An endpoint's own, which the host does not claim.
    Opaque,
}
impl ExecutionCompute {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Metal => "metal",
            Self::Cuda => "cuda",
            Self::CpuAndNe => "cpu_and_ne",
            Self::Opaque => "opaque",
        }
    }
}
/// Why a host's dispatcher sent a call to the worker that ran it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPick {
    /// Several workers were free; the calibrated rank chose this one.
    Calibrated,
    /// This worker was free: the only free one, or the first to free up.
    Free,
    /// Every worker was busy; this one had the shorter waiting live queue.
    ShorterQueue,
    /// A worker ranked above this one was not ready.
    Fallback,
    /// The slot serves one configured worker: a named device or an endpoint.
    Pinned,
}
/// What ran one extraction call: the worker's runtime and compute, why it
/// was picked, and how long the call waited and ran. Host facts only: no
/// field holds anything a worker reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EncoderExecution {
    pub runtime: ExecutionRuntime,
    pub compute: ExecutionCompute,
    /// `runtime/compute` as engine rows and logs name it (`candle/metal`),
    /// or the runtime alone when its compute is opaque (`endpoint`).
    pub engine: String,
    pub pick: ExecutionPick,
    /// Milliseconds the call waited before its worker took it.
    pub queue_ms: u64,
    /// Milliseconds its worker ran it.
    pub infer_ms: u64,
}
impl EncoderExecution {
    /// One call's facts; the engine id is derived from the runtime and
    /// compute, never taken from the worker.
    pub fn new(
        runtime: ExecutionRuntime,
        compute: ExecutionCompute,
        pick: ExecutionPick,
        queued: Duration,
        ran: Duration,
    ) -> Self {
        let millis = |span: Duration| u64::try_from(span.as_millis()).unwrap_or(u64::MAX);
        Self {
            runtime,
            compute,
            engine: Self::engine_id(runtime, compute),
            pick,
            queue_ms: millis(queued),
            infer_ms: millis(ran),
        }
    }
    /// The engine id of `runtime` on `compute`: `runtime/compute`, or the
    /// runtime alone when its compute is opaque.
    pub fn engine_id(runtime: ExecutionRuntime, compute: ExecutionCompute) -> String {
        match compute {
            ExecutionCompute::Opaque => runtime.as_str().to_owned(),
            _ => format!("{}/{}", runtime.as_str(), compute.as_str()),
        }
    }
}
/// One call's answer beside the facts of the worker that ran it. The answer
/// stays semantic, so parity and digests never compare where it ran.
#[derive(Debug)]
pub struct EncoderAttempt<E = crate::Error> {
    /// `None` only when no worker was dispatched: a dispatched failure keeps
    /// the facts of the worker that failed.
    pub execution: Option<EncoderExecution>,
    pub result: Result<EncoderOutput, E>,
}
/// Hosts own checkpoint execution. No engine implementation guesses model outputs.
pub trait ExtractionEncoder: Send + Sync {
    fn model_id(&self) -> &ModelId;
    fn locality(&self) -> EmbedderLocality;
    /// Runs one call in `work`'s class: its answer with the facts of the
    /// worker that ran it. The class orders the call and never changes what
    /// the tagger reads.
    fn infer(&self, input: &EncoderInput, work: ExtractionWork) -> EncoderAttempt;
    /// [`Self::infer`] for `caller`, whose calls a host's dispatcher shares
    /// its room by (FIX 9519). A host that keeps no per-caller order runs it
    /// as `infer`.
    fn infer_for(
        &self,
        input: &EncoderInput,
        work: ExtractionWork,
        caller: &ExtractionCaller,
    ) -> EncoderAttempt {
        let _ = caller;
        self.infer(input, work)
    }
}
/// Not deserializable: persistence requires a locally validated shadow receipt.
#[derive(Debug, Clone, Serialize)]
pub struct ShadowTrace {
    pub(super) model: String,
    pub(super) input_hash: String,
    pub(super) output: Option<EncoderOutput>,
    pub(super) failure: Option<String>,
    /// What ran the call, when a worker was dispatched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) execution: Option<EncoderExecution>,
    #[serde(skip)]
    pub(super) input: EncoderInput,
}
impl ShadowTrace {
    pub fn output(&self) -> Option<&EncoderOutput> {
        self.output.as_ref()
    }
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
    pub fn execution(&self) -> Option<&EncoderExecution> {
        self.execution.as_ref()
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    pub fn input_hash(&self) -> &str {
        &self.input_hash
    }
}
#[derive(Debug, Serialize)]
pub struct WitnessWithShadow {
    pub witness: super::super::WitnessReceipt,
    pub trace: ShadowTrace,
}
/// A golden comparison supplied by the host's held-out conformance fixture.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncoderGolden {
    pub model: String,
    pub input_hash: String,
    pub output: EncoderOutput,
}
/// A successful model-pinned parity check. Constructible only by comparison.
/// It names the model and the served stack its outputs named: a head swap
/// at one checkpoint keeps the model id, so the stack tells the two apart.
#[derive(Debug, Clone)]
pub struct EncoderParity {
    pub(super) model: String,
    pub(super) stack: Option<String>,
}
impl EncoderParity {
    pub fn verify(traces: &[ShadowTrace], goldens: &[EncoderGolden]) -> crate::Result<Self> {
        if traces.is_empty() || traces.len() != goldens.len() {
            return Err(crate::Error::InvalidConfig(
                "complete shadow/golden parity set required".into(),
            ));
        }
        let model = traces[0].model.clone();
        let stack = goldens[0].output.stack_sha16.clone();
        let mut seen = std::collections::BTreeSet::new();
        for (trace, golden) in traces.iter().zip(goldens) {
            if !seen.insert(&trace.input_hash)
                || trace.model != model
                || golden.model != model
                || golden.output.stack_sha16 != stack
                || trace.input_hash != golden.input_hash
                || trace.output.as_ref() != Some(&golden.output)
                || trace.failure.is_some()
            {
                return Err(crate::Error::InvalidConfig(
                    "encoder shadow parity failed".into(),
                ));
            }
        }
        Ok(Self { model, stack })
    }
}
