//! The inference receipt a house backend's reply carries (FIX 6567, INF 2
//! step 1; FIX 8314, INFERENCE R1), written into its usage as typed records
//! under [`INFERENCE_CALLS_KEY`], one per physical request, where the run's
//! settlement reads them.
//!
//! The backend is known from what its reply carries, never from a provider's
//! name, URL or config: the house EXL3 server writes its own record into its
//! usage (`deploy/house-model/cache_usage.py`), and a llama.cpp reply is the
//! one whose top-level `timings` holds `prompt_n` and `cache_n`, or whose
//! own `model` is a house launch alias. Any other reply keeps its standard
//! counters and gets no record. Standard counters are never rewritten here.
//!
//! A llama.cpp record's identity is what the answer's own launch alias names
//! (FIX 7895, `llama_identity.rs`): the launch's epoch, and the digests its
//! verified manifest lists, with the execution mode of what the engine sent
//! on that call (FIX 8329, `llama_identity::execution_mode`). An answer
//! without an alias, or whose manifest did not verify, has those digests
//! absent and its build unknown. A chat record's runtime is then a digest of
//! the build string the reply reports as `system_fingerprint`, which is a
//! build, not an incarnation. A record
//! carries no measurement it was not given: its queue waits, first-token
//! time, end, output count and drafts stay absent, and the engine model it
//! was admitted for is the adapter's to stamp.
use oneiron::llm::{
    CacheCounterSource, CacheDigest, CacheIdentity, CachePassReport, CachePassUsage, CachePhase,
    INFERENCE_CALLS_KEY, InferenceCallReceipt, WorkerBuildEvidence, WorkerDescriptor, WorkerKind,
};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use super::llama_identity::AnsweringIdentity;

/// The usage key a llama.cpp reply's build string is carried under.
const SYSTEM_FINGERPRINT_KEY: &str = "system_fingerprint";

/// Writes llama.cpp's receipt into a chat reply's usage, or a stream
/// chunk's: the pass over the prompt when the reply carries llama.cpp's
/// timings, its standard input and cached counts beside the native computed
/// count (`timings.prompt_n`) and times, and the identity `answering`, the
/// reply's own alias, names. The standard cached count is the read when
/// there is one; when it and `timings.cache_n` disagree the read is unknown,
/// never either guess. `tokens_cached` is never a read: it is the slot's
/// occupancy, which counts generated tokens too. A reply that names its
/// launch alias but carries no timings gets its receipt with no pass. A body
/// with neither, without a usage object, or whose usage already holds
/// records (the EXL3 server's own) is left as it came. `execution` is the
/// execution mode of the request the engine sent for it (FIX 8329).
pub(super) fn carry_chat_evidence(
    body: &mut JsonValue,
    answering: Option<&AnsweringIdentity>,
    execution: Option<&CacheDigest>,
) {
    let native = body.get("timings").and_then(|timings| {
        Some((
            count(timings, "prompt_n")?,
            count(timings, "cache_n")?,
            micros(timings, "prompt_ms"),
            micros(timings, "predicted_ms"),
        ))
    });
    if native.is_none() && answering.is_none() {
        return;
    }
    let fingerprint = body
        .get(SYSTEM_FINGERPRINT_KEY)
        .and_then(JsonValue::as_str)
        .filter(|build| !build.is_empty())
        .map(str::to_owned);
    let Some(JsonValue::Object(usage)) = body.get_mut("usage") else {
        return;
    };
    if usage.contains_key(INFERENCE_CALLS_KEY) {
        return;
    }
    let input = usage.get("prompt_tokens").and_then(JsonValue::as_u64);
    let standard = usage
        .get("prompt_tokens_details")
        .and_then(|details| count(details, "cached_tokens"));
    let pass = native.map(|(computed, cache_n, prefill_us, generate_us)| {
        let (read, counter_source) = match standard {
            Some(standard) if standard == cache_n => {
                (Some(standard), CacheCounterSource::OpenAiUsage)
            }
            Some(_) => (None, CacheCounterSource::OpenAiUsage),
            None => (Some(cache_n), CacheCounterSource::LlamaTimings),
        };
        CachePassUsage::from(CachePassReport {
            phase: CachePhase::Prompt,
            counter_source,
            input_tokens: input,
            cache_read_tokens: read,
            computed_input_tokens: Some(computed),
            cached_pages: None,
            prefill_us,
            generate_us,
        })
    });
    let worker = llama_worker(
        chat_identity(answering, fingerprint.as_deref(), execution),
        answering,
    );
    let call = InferenceCallReceipt {
        logical_prompt_tokens: input,
        passes: pass.into_iter().collect(),
        ..InferenceCallReceipt::unmeasured(None, worker)
    };
    if let Some(fingerprint) = fingerprint {
        usage
            .entry(SYSTEM_FINGERPRINT_KEY)
            .or_insert(JsonValue::String(fingerprint));
    }
    if let Ok(record) = serde_json::to_value(&call) {
        usage.insert(
            INFERENCE_CALLS_KEY.to_owned(),
            JsonValue::Array(vec![record]),
        );
    }
}

/// The llama.cpp worker that answered with `identity`: verified artifacts
/// only by the manifest `answering`'s alias resolved to; a runtime digest
/// with no manifest is the reported version the fingerprint names.
fn llama_worker(
    identity: CacheIdentity,
    answering: Option<&AnsweringIdentity>,
) -> WorkerDescriptor {
    let verified = answering.is_some_and(|answering| {
        answering.build_evidence() == WorkerBuildEvidence::VerifiedArtifacts
    });
    let build_evidence = if verified {
        WorkerBuildEvidence::VerifiedArtifacts
    } else if identity.runtime.is_some() {
        WorkerBuildEvidence::ReportedVersion
    } else {
        WorkerBuildEvidence::Unknown
    };
    WorkerDescriptor {
        kind: WorkerKind::LlamaCpp,
        identity,
        build_evidence,
    }
}

/// A chat record's identity: what the answer's own alias names, with the
/// reported build's digest as its runtime when no manifest names one, and
/// the call's own `execution` mode.
fn chat_identity(
    answering: Option<&AnsweringIdentity>,
    fingerprint: Option<&str>,
    execution: Option<&CacheDigest>,
) -> CacheIdentity {
    let mut identity = answering
        .map(AnsweringIdentity::for_chat)
        .unwrap_or_default();
    if identity.runtime.is_none() {
        identity.runtime = fingerprint.and_then(digest);
    }
    identity.execution_mode = execution.cloned();
    identity
}

/// One native decision-read answer's cache read and raw usage: its `timings`
/// as it came, beside its receipt (`tokens_evaluated` in, `timings.cache_n`
/// read from the cache, `timings.prompt_n` computed). The read is the
/// record's when its counts agree, else 0, as the standard counter always
/// read it; the record keeps the read unknown. The identity is what
/// `answering`, the answer's own alias, names: never a chat template, which
/// a native prompt does not go through; its execution mode is `execution`,
/// that of the completion the engine sent (FIX 8329).
pub(super) fn label_read(
    answer: &JsonValue,
    answering: Option<&AnsweringIdentity>,
    execution: Option<&CacheDigest>,
) -> (u64, JsonValue) {
    let timings = answer.get("timings");
    let native = |key: &str| timings.and_then(|timings| count(timings, key));
    let input = count(answer, "tokens_evaluated");
    let pass = CachePassUsage::from(CachePassReport {
        phase: CachePhase::LabelRead,
        counter_source: CacheCounterSource::LlamaTimings,
        input_tokens: input,
        cache_read_tokens: native("cache_n"),
        computed_input_tokens: native("prompt_n"),
        cached_pages: None,
        prefill_us: timings.and_then(|timings| micros(timings, "prompt_ms")),
        generate_us: timings.and_then(|timings| micros(timings, "predicted_ms")),
    });
    let read = pass.measured_read().unwrap_or(0);
    let identity = CacheIdentity {
        execution_mode: execution.cloned(),
        ..answering
            .map(AnsweringIdentity::for_native)
            .unwrap_or_default()
    };
    let call = InferenceCallReceipt {
        logical_prompt_tokens: input,
        passes: vec![pass],
        ..InferenceCallReceipt::unmeasured(None, llama_worker(identity, answering))
    };
    let mut usage = timings.map_or_else(|| json!({}), |timings| json!({ "timings": timings }));
    put_inference_calls(
        &mut usage,
        serde_json::to_value(&call).into_iter().collect(),
    );
    (read, usage)
}

/// Moves the receipts out of the usage object `usage`, for an aggregate
/// that lists every attempt's receipts once, at its own top.
pub(super) fn take_inference_calls(usage: &mut JsonValue) -> Vec<JsonValue> {
    match usage
        .as_object_mut()
        .and_then(|usage| usage.remove(INFERENCE_CALLS_KEY))
    {
        Some(JsonValue::Array(records)) => records,
        _ => Vec::new(),
    }
}

/// Appends `records` to the list under [`INFERENCE_CALLS_KEY`] in the usage
/// object `usage`. A usage that is not an object is left as it came.
pub(super) fn put_inference_calls(usage: &mut JsonValue, records: Vec<JsonValue>) {
    if records.is_empty() {
        return;
    }
    let Some(usage) = usage.as_object_mut() else {
        return;
    };
    if let JsonValue::Array(list) = usage
        .entry(INFERENCE_CALLS_KEY)
        .or_insert_with(|| JsonValue::Array(Vec::new()))
    {
        list.extend(records);
    }
}

fn count(value: &JsonValue, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

/// A native time in milliseconds as whole microseconds.
fn micros(timings: &JsonValue, key: &str) -> Option<u64> {
    let ms = timings.get(key)?.as_f64()?;
    if ms.is_finite() && ms >= 0.0 {
        Some((ms * 1000.0).round() as u64)
    } else {
        None
    }
}

/// The SHA-256 of a string the backend reported.
fn digest(reported: &str) -> Option<CacheDigest> {
    CacheDigest::new(format!("{:x}", Sha256::digest(reported.as_bytes()))).ok()
}
