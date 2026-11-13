//! Moved from `crates/oneiron/src/memory/extraction/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::affect::Vad;
pub use oneiron_store::extraction_work::ExtractionWork;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;

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

pub fn strict_part_vad<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vad, D::Error> {
    let vad = WireVad::deserialize(deserializer)?;
    Ok(Vad {
        valence: vad.valence,
        arousal: vad.arousal,
        dominance: vad.dominance,
    })
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
