//! The MLX worker's wire, protocol `oneironer-worker-v2` (FIX 6755 slice 3,
//! contract rev 3 A2-A3, Engine call 7): the closed handshake, request and
//! reply objects, and the checks a handshake and a reply must pass.
//!
//! The handshake names the worker, the model, the decode, the runtime, the
//! window and the capabilities. Each must be the pinned one, or the worker
//! stays down with the field named ([`validate_handshake`]). No numeric
//! contract version rides on the wire: the exact protocol string is the v2
//! mapping, and the engine-side model card carries
//! `endpoint::CONTRACT_VERSION` ([`Handshake::card`]). A reply is an untagged
//! envelope of closed objects, `{id, outputs}` or `{id, error}`, never both.
//! An error's message is parsed and dropped, so no text the worker wrote is
//! kept; its code is one of a closed set.

use std::collections::BTreeSet;

use oneiron::memory::extraction::EncoderOutput;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use super::super::dispatcher::Fault;
use super::super::endpoint::{CONTRACT_VERSION, ModelCard, Returns};
use super::super::local::{CHAR_REFINE_K, CHAR_REFINE_TAU, ONEIRONER_DECODE_REVISION};

/// The one wire this engine speaks to a worker.
pub(crate) const PROTOCOL: &str = "oneironer-worker-v2";
/// The worker a handshake must name.
const WORKER_NAME: &str = "oneironer-mlx-worker";
/// The DATE snap the served decode runs, as the worker declares it.
const DATE_SNAP: &str = "before and after refinement (served layers); none without a language";
/// Where the worker's spans are addressed: the window, as message 0.
const SPANS: &str = "window UTF-8 byte offsets, message 0";
/// Who builds each window: the engine, by Candle's own builder.
const BUILT_BY: &str = "engine";
/// The runtime's name, device, id and dtype a handshake must report.
const RUNTIME: [&str; 4] = ["mlx", "metal", "mlx/metal", "float16"];

/// The worker's first frame once it has loaded, verified and warmed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Handshake {
    protocol: String,
    worker: WorkerIdentity,
    model: ModelIdentity,
    decode: Decode,
    runtime: Runtime,
    window: WindowLimits,
    capabilities: Capabilities,
    load_ms: LoadMs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerIdentity {
    name: String,
    version: String,
    lock_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelIdentity {
    checkpoint_sha16: String,
    stack_sha16: String,
    label_count: u32,
    tokenizer_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decode {
    revision: String,
    char_head: bool,
    refine_k: usize,
    refine_tau: f32,
    date_snap: String,
}

/// The worker's report of its runtime: checked, never a receipt, since a
/// receipt names the host's own runtime and compute. `fused_kernels` and
/// `gpu` vary by chip with the same outputs (A3), so neither is required.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    name: String,
    device: String,
    id: String,
    mlx: String,
    dtype: String,
    fused_kernels: bool,
    #[serde(default)]
    gpu: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowLimits {
    built_by: String,
    max_input_tokens: usize,
    qualified_max_window_tokens: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capabilities {
    max_batch: usize,
    max_batch_tokens: usize,
    spans: String,
}

/// Load timings, logged and never a readiness, parity or speed grant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadMs {
    verify: f64,
    weights: f64,
    warm: f64,
    total: f64,
}

/// What a handshake must name: the admitted row's pins, the verified
/// bundle's identity, and the cap the engine passed.
pub(crate) struct Expected {
    pub(crate) version: String,
    pub(crate) lock_sha256: String,
    pub(crate) checkpoint_sha16: String,
    pub(crate) stack_sha16: String,
    pub(crate) label_count: u32,
    /// The full SHA-256 of the tokenizer bytes the engine verified.
    pub(crate) tokenizer_sha256: String,
    /// Whether the bundle has a character head.
    pub(crate) char_head: bool,
    /// The `--max-input-tokens` the engine passed.
    pub(crate) max_input_tokens: usize,
    /// The row's qualified window.
    pub(crate) max_window_tokens: usize,
}

/// The first frame: the handshake, or the refusal of a failed load.
#[derive(Deserialize)]
#[serde(untagged)]
enum First {
    Ready(Box<Handshake>),
    Refused(Refusal),
}

/// `{id, outputs}` or `{id, error}`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Reply {
    Answered(Answered),
    Refused(Refusal),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Answered {
    id: u64,
    outputs: Vec<EncoderOutput>,
}

/// An error frame. A load refusal has no id; a malformed request's is null.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refusal {
    #[serde(default)]
    id: Option<u64>,
    error: WorkerError,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerError {
    code: ErrorCode,
    /// Parsed and dropped: the engine keeps no text the worker wrote.
    #[serde(rename = "message")]
    _message: IgnoredAny,
    /// The index of the input that failed the request, when one did.
    #[serde(default)]
    input: Option<usize>,
}

/// Every error code the worker sends: the request codes after the
/// handshake, `bundle` and `load` in place of one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ErrorCode {
    BadRequest,
    TooManyInputs,
    FrameTooLarge,
    BadInput,
    WindowTooLong,
    EngineFailed,
    Bundle,
    Load,
}

impl ErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::TooManyInputs => "too_many_inputs",
            Self::FrameTooLarge => "frame_too_large",
            Self::BadInput => "bad_input",
            Self::WindowTooLong => "window_too_long",
            Self::EngineFailed => "engine_failed",
            Self::Bundle => "bundle",
            Self::Load => "load",
        }
    }

    /// Whether a request's reply may carry it.
    const fn of_request(self) -> bool {
        !matches!(self, Self::Bundle | Self::Load)
    }
}

/// One request: `1..=max_batch` windows, under an id the session counts.
#[derive(Serialize)]
pub(super) struct Request<'a> {
    pub(super) id: u64,
    pub(super) inputs: &'a [WorkerInput<'a>],
}

/// One window as the worker reads it: the text `Window::new` built, the
/// current turn's UTF-8 byte range in it, and the call's language as it
/// came, absent when none was named.
#[derive(Serialize)]
pub(super) struct WorkerInput<'a> {
    pub(super) window_text: &'a str,
    pub(super) turn_start: usize,
    pub(super) turn_end: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) language: Option<&'a str>,
}

/// What one request's reply says.
pub(super) enum Answer {
    /// One checked output per input, in order.
    Outputs(Vec<EncoderOutput>),
    /// The request failed whole: the worker's code, and the index of the
    /// input that failed it when one did.
    Failed {
        code: &'static str,
        input: Option<usize>,
    },
}

/// The down reason of a handshake whose `field` is not the pinned one.
pub(crate) fn mismatch(field: &str) -> String {
    format!("identity_mismatch:{field}")
}

/// Reads the first frame. A refused load is a crash for `load`, retried,
/// and an identity mismatch for `bundle`, the worker's own check of the
/// bundle. JSON that is not the closed handshake is a mismatch of the
/// protocol; bytes that are not JSON are a malformed frame.
pub(super) fn read_handshake(frame: &[u8]) -> Result<Handshake, Fault> {
    match serde_json::from_slice::<First>(frame) {
        Ok(First::Ready(handshake)) => Ok(*handshake),
        Ok(First::Refused(refusal)) => Err(match refusal.error.code {
            ErrorCode::Load => Fault::Crash("load_failed"),
            ErrorCode::Bundle => Fault::Down(mismatch("bundle")),
            _ => Fault::Down(mismatch("protocol")),
        }),
        Err(_) if serde_json::from_slice::<IgnoredAny>(frame).is_ok() => {
            Err(Fault::Down(mismatch("protocol")))
        }
        Err(_) => Err(Fault::Crash("malformed_frame")),
    }
}

/// Checks `handshake` names what `expected` pins (§3.3): `Err` names the
/// first field that differs, the reason the worker stays down.
pub(super) fn validate_handshake(
    handshake: &Handshake,
    expected: &Expected,
) -> Result<(), &'static str> {
    let Handshake {
        protocol,
        worker,
        model,
        decode,
        runtime,
        window,
        capabilities,
        ..
    } = handshake;
    let qualified = window.qualified_max_window_tokens;
    let reported = [
        runtime.name.as_str(),
        runtime.device.as_str(),
        runtime.id.as_str(),
        runtime.dtype.as_str(),
    ];
    let checks = [
        ("protocol", protocol == PROTOCOL),
        ("worker_name", worker.name == WORKER_NAME),
        ("worker_version", worker.version == expected.version),
        ("worker_lock", worker.lock_sha256 == expected.lock_sha256),
        ("checkpoint", model.checkpoint_sha16 == expected.checkpoint_sha16),
        ("stack", model.stack_sha16 == expected.stack_sha16),
        ("label_count", model.label_count == expected.label_count),
        ("tokenizer", model.tokenizer_sha256 == expected.tokenizer_sha256),
        (
            "decode",
            decode.revision == ONEIRONER_DECODE_REVISION
                && decode.char_head == expected.char_head
                && decode.refine_k == CHAR_REFINE_K
                && decode.refine_tau.to_bits() == CHAR_REFINE_TAU.to_bits()
                && decode.date_snap == DATE_SNAP,
        ),
        ("runtime", reported == RUNTIME),
        (
            "window",
            window.built_by == BUILT_BY
                && window.max_input_tokens == expected.max_input_tokens
                && qualified == expected.max_window_tokens
                && qualified > 0
                && qualified <= window.max_input_tokens,
        ),
        (
            "capabilities",
            capabilities.max_batch > 0
                && capabilities.max_batch_tokens > 0
                && capabilities.spans == SPANS,
        ),
    ];
    checks
        .into_iter()
        .find(|(_, holds)| !holds)
        .map_or(Ok(()), |(field, _)| Err(field))
}

impl Handshake {
    /// The engine-side card of the worker it names: version
    /// `endpoint::CONTRACT_VERSION`, spans alone (this worker serves no
    /// link or mood head), and the checked stack, checkpoint and labels.
    pub(super) fn card(&self) -> ModelCard {
        ModelCard {
            checkpoint_sha16: self.model.checkpoint_sha16.clone(),
            contract_version: CONTRACT_VERSION,
            label_count: self.model.label_count,
            returns: Returns {
                spans: true,
                links: false,
                mood: false,
            },
            stack_sha16: Some(self.model.stack_sha16.clone()),
        }
    }

    /// Inputs one request of its may hold.
    pub(super) const fn max_batch(&self) -> usize {
        self.capabilities.max_batch
    }

    /// Logs what it reported of its runtime and load: diagnostics only.
    pub(super) fn log_ready(&self) {
        let (runtime, load) = (&self.runtime, &self.load_ms);
        tracing::info!(
            stack_sha16 = self.model.stack_sha16.as_str(),
            version = self.worker.version.as_str(),
            mlx = runtime.mlx.as_str(),
            fused_kernels = runtime.fused_kernels,
            gpu = runtime.gpu.as_deref().unwrap_or("-"),
            max_batch = self.capabilities.max_batch,
            verify_ms = load.verify,
            weights_ms = load.weights,
            warm_ms = load.warm,
            total_ms = load.total,
            "oneironer mlx worker handshake accepted"
        );
    }
}

/// Reads and checks the reply to request `id` of `count` inputs. A success
/// must be `id`'s, one output per input, each checked
/// ([`validate_reply`]). A request error fails the request whole; one with
/// a null id answers a request the worker could not read, ours. Any other
/// frame, or another request's id, is a corrupt stream, and the session is
/// discarded rather than read back into step.
pub(super) fn read_reply(
    frame: &[u8],
    id: u64,
    count: usize,
    stack: &str,
    labels: &BTreeSet<String>,
) -> Result<Answer, Fault> {
    let reply: Reply = serde_json::from_slice(frame).map_err(|_| Fault::Crash("bad_reply"))?;
    match reply {
        Reply::Answered(answered) => {
            validate_reply(&answered, id, count, stack, labels)?;
            Ok(Answer::Outputs(answered.outputs))
        }
        Reply::Refused(refusal) => {
            let ours = refusal.id.is_none_or(|named| named == id);
            if !ours || !refusal.error.code.of_request() {
                return Err(Fault::Crash("bad_reply"));
            }
            Ok(Answer::Failed {
                code: refusal.error.code.as_str(),
                input: refusal.error.input,
            })
        }
    }
}

/// Checks a success reply (§3.2): request `id`'s, `count` outputs in input
/// order, each of `stack` with spans alone, no link, mood, context or
/// speaker link, each span on message 0 with a declared entity label, a
/// nonempty range and a confidence in `[0, 1]`. Byte offsets are checked
/// against each window as it is mapped (`Window::map_window_spans`).
fn validate_reply(
    answered: &Answered,
    id: u64,
    count: usize,
    stack: &str,
    labels: &BTreeSet<String>,
) -> Result<(), Fault> {
    let output_holds = |output: &EncoderOutput| {
        output.stack_sha16.as_deref() == Some(stack)
            && output.links.is_empty()
            && output.vad.is_none()
            && output.context_links.is_empty()
            && output.speaker_links.is_empty()
            && output.spans.iter().all(|span| {
                span.message == 0
                    && span.start < span.end
                    && labels.contains(&span.label)
                    && (0.0..=1.0).contains(&span.confidence)
            })
    };
    let holds = answered.id == id
        && answered.outputs.len() == count
        && answered.outputs.iter().all(output_holds);
    if holds {
        Ok(())
    } else {
        Err(Fault::Crash("bad_reply"))
    }
}
