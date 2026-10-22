//! One call driven through `LlmBackend::stream`, timed with `Instant`.
//!
//! `t0` is taken right before `stream()` is called. The first non-empty
//! reasoning or text delta is `ttft_any_ms`; the first non-empty text delta
//! is `ttft_text_ms`; the last delta is `t_last_ms`; `Done` is `wall_ms`.
//! The engine's own timings come from the usage's raw provider JSON, where
//! the server's OpenAI transport copies a reply's top-level `timings`. The
//! `_e2e` rates are client-side estimates over the whole path (queue,
//! template, transport, thinking) and are named so.

use std::collections::BTreeMap;
use std::time::Instant;

use futures_util::StreamExt as _;
use oneiron::{
    BudgetLease, ContentPart, FinishReason, LlmBackend, LlmRequest, LlmStreamEvent, LlmUsage,
};
use serde::Serialize;
use serde_json::Value as JsonValue;

/// The timing keys llama-server and the house EXL3 server report, each
/// recorded as a number or null; any other numeric key they add is kept too.
const NATIVE_KEYS: [&str; 11] = [
    "cache_n",
    "prompt_n",
    "prompt_ms",
    "prompt_per_token_ms",
    "prompt_per_second",
    "predicted_n",
    "predicted_ms",
    "predicted_per_token_ms",
    "predicted_per_second",
    "draft_n",
    "draft_n_accepted",
];

/// One finished call's measurements, as the row records them. Every field
/// is null on a call that failed, except `wall_ms`.
#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct Timing {
    pub(super) ttft_any_ms: Option<f64>,
    pub(super) ttft_text_ms: Option<f64>,
    pub(super) t_last_ms: Option<f64>,
    pub(super) wall_ms: Option<f64>,
    pub(super) input_tokens: Option<u64>,
    pub(super) output_tokens: Option<u64>,
    pub(super) reasoning_tokens: Option<u64>,
    pub(super) cache_read_tokens: Option<u64>,
    pub(super) finish_reason: Option<String>,
    pub(super) native: Option<BTreeMap<String, Option<f64>>>,
    pub(super) prefill_tps_e2e: Option<f64>,
    pub(super) decode_tps_e2e: Option<f64>,
    pub(super) output_digest: Option<String>,
    pub(super) output_chars: Option<usize>,
    pub(super) reasoning_chars: Option<usize>,
    /// The provider of the rung that answered, from the ladder's receipt.
    pub(super) served_provider: Option<String>,
    /// What the engine called the model in its reply.
    pub(super) reported_model: Option<String>,
}

/// A call that reached `Done`.
pub(super) struct Measured {
    pub(super) timing: Timing,
    /// The reply's text parts, joined; scored and digested, never stored.
    pub(super) text: String,
    pub(super) usage: LlmUsage,
    /// `t0`, the instant every ms field counts from.
    pub(super) started: Instant,
}

/// A call that failed, and when.
pub(super) struct Failed {
    pub(super) error: String,
    pub(super) wall_ms: f64,
    /// `t0`, or the refusal's instant for a call that never started.
    pub(super) started: Instant,
}

fn ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

fn finish_name(reason: &FinishReason) -> String {
    match reason {
        FinishReason::Stop => "stop".to_owned(),
        FinishReason::Length => "length".to_owned(),
        FinishReason::ToolCalls => "tool_calls".to_owned(),
        FinishReason::ContentFiltered => "content_filtered".to_owned(),
        FinishReason::Cancelled => "cancelled".to_owned(),
        FinishReason::Other { name } => name.clone(),
        FinishReason::Incomplete { .. } => "incomplete".to_owned(),
    }
}

/// The provider's own usage object: under a ladder receipt's `usage`, or the
/// raw usage itself when no receipt wraps it.
fn provider_usage(raw: &JsonValue) -> &JsonValue {
    match raw.get("usage") {
        Some(usage) if raw.get("rung").is_some() => usage,
        _ => raw,
    }
}

/// The engine's `timings`, numbers only, as found. `None` when it sent none.
fn native(raw: &JsonValue) -> Option<BTreeMap<String, Option<f64>>> {
    let timings = provider_usage(raw).get("timings")?.as_object()?;
    let mut found: BTreeMap<String, Option<f64>> = NATIVE_KEYS
        .iter()
        .map(|key| ((*key).to_owned(), None))
        .collect();
    for (key, value) in timings {
        if let Some(number) = value.as_f64() {
            found.insert(key.clone(), Some(number));
        }
    }
    Some(found)
}

/// Drives `request` to its end. Errors are kept as text with the time they
/// came at, never retried here.
pub(super) async fn drive(
    backend: &dyn LlmBackend,
    request: LlmRequest,
    lease: &BudgetLease,
) -> Result<Measured, Failed> {
    let failed = |error: String, t0: Instant| Failed {
        error,
        wall_ms: ms(t0),
        started: t0,
    };
    let t0 = Instant::now();
    let mut stream = backend
        .stream(request, lease)
        .map_err(|e| failed(e.to_string(), t0))?;
    let (mut first_any, mut first_text, mut last) = (None, None, None);
    let mut reasoning_chars = 0;
    while let Some(item) = stream.next().await {
        let event = item.map_err(|e| failed(e.to_string(), t0))?;
        let at = ms(t0);
        match event {
            LlmStreamEvent::TextDelta { text, .. } if !text.is_empty() => {
                first_any = first_any.or(Some(at));
                first_text = first_text.or(Some(at));
                last = Some(at);
            }
            LlmStreamEvent::ReasoningDelta { text, .. } if !text.is_empty() => {
                first_any = first_any.or(Some(at));
                last = Some(at);
                reasoning_chars += text.chars().count();
            }
            LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
            } => {
                let text: String = message
                    .content
                    .iter()
                    .filter_map(|part| match part {
                        ContentPart::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                return Ok(finished(
                    Instants {
                        started: t0,
                        first_any,
                        first_text,
                        last,
                        wall: at,
                    },
                    text,
                    reasoning_chars,
                    usage,
                    &finish_reason,
                ));
            }
            _ => {}
        }
    }
    Err(failed("the stream ended without Done".to_owned(), t0))
}

/// The call's timestamps, in ms after `t0`.
struct Instants {
    started: Instant,
    first_any: Option<f64>,
    first_text: Option<f64>,
    last: Option<f64>,
    wall: f64,
}

fn finished(
    at: Instants,
    text: String,
    reasoning_chars: usize,
    usage: LlmUsage,
    finish_reason: &FinishReason,
) -> Measured {
    let input = usage.input.total;
    let output = usage.output.total;
    let prefill_tps_e2e = at
        .first_any
        .filter(|first| *first > 0.0 && input > 0)
        .map(|first| input as f64 / (first / 1000.0));
    let decode_tps_e2e = match (at.first_any, at.last) {
        (Some(first), Some(last)) if output >= 2 && last > first => {
            Some((output - 1) as f64 / ((last - first) / 1000.0))
        }
        _ => None,
    };
    let raw = &usage.raw_provider;
    let reported_model = raw
        .get("reported_model")
        .or_else(|| provider_usage(raw).get("served_model"))
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let timing = Timing {
        ttft_any_ms: at.first_any,
        ttft_text_ms: at.first_text,
        t_last_ms: at.last,
        wall_ms: Some(at.wall),
        input_tokens: Some(input),
        output_tokens: Some(output),
        // Absent counts read as zero on the wire, so zero is not evidence.
        reasoning_tokens: (usage.output.reasoning > 0).then_some(usage.output.reasoning),
        cache_read_tokens: Some(usage.input.cache_read),
        finish_reason: Some(finish_name(finish_reason)),
        native: native(raw),
        prefill_tps_e2e,
        decode_tps_e2e,
        output_digest: Some(blake3::hash(text.as_bytes()).to_hex().to_string()),
        output_chars: Some(text.chars().count()),
        reasoning_chars: Some(reasoning_chars),
        served_provider: usage.served_provider().map(str::to_owned),
        reported_model,
    };
    Measured {
        timing,
        text,
        usage,
        started: at.started,
    }
}
