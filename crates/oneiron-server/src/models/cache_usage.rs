//! The prompt-cache evidence a house backend's reply carries (FIX 6567, INF 2
//! step 1), written into its usage as typed records under
//! [`CACHE_CALLS_KEY`], where `RunTokenUsage::cache_calls` reads them.
//!
//! The backend is known from what its reply carries, never from a provider's
//! name, URL or config: the house EXL3 server writes its own record into its
//! usage (`deploy/house-model/cache_usage.py`), and a llama.cpp reply is the
//! one whose top-level `timings` holds `prompt_n` and `cache_n`. Any other
//! reply keeps its standard counters and gets no record. Standard counters are
//! never rewritten here.
//!
//! A llama.cpp record's identity is what the answer's own launch alias names
//! (FIX 7895, `llama_identity.rs`): the launch's epoch, and the digests its
//! verified manifest lists. An answer without an alias, or whose manifest did
//! not verify, has those absent. A chat record's runtime is then a digest of
//! the build string the reply reports as `system_fingerprint`, which is a
//! build, not an incarnation.
use oneiron::llm::{
    CACHE_CALLS_KEY, CacheBackend, CacheCallUsage, CacheCounterSource, CacheDigest, CacheIdentity,
    CachePassReport, CachePassUsage, CachePhase,
};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use super::llama_identity::AnsweringIdentity;

/// The usage key a llama.cpp reply's build string is carried under.
const SYSTEM_FINGERPRINT_KEY: &str = "system_fingerprint";

/// Writes llama.cpp's cache record into a chat reply's usage, or a stream
/// chunk's: the pass over the prompt, its standard input and cached counts
/// beside the native computed count (`timings.prompt_n`) and times, and the
/// reported build. The standard cached count is the read when there is one;
/// when it and `timings.cache_n` disagree the read is unknown, never either
/// guess. `tokens_cached` is never a read: it is the slot's occupancy, which
/// counts generated tokens too. The identity is what `answering`, the reply's
/// own alias, names. A body without llama.cpp's timings, without a usage
/// object, or whose usage already holds records (the EXL3 server's own) is
/// left as it came.
pub(super) fn carry_chat_evidence(body: &mut JsonValue, answering: Option<&AnsweringIdentity>) {
    let Some(timings) = body.get("timings") else {
        return;
    };
    let (Some(computed), Some(cache_n)) = (count(timings, "prompt_n"), count(timings, "cache_n"))
    else {
        return;
    };
    let (prefill_us, generate_us) = (
        micros(timings, "prompt_ms"),
        micros(timings, "predicted_ms"),
    );
    let fingerprint = body
        .get(SYSTEM_FINGERPRINT_KEY)
        .and_then(JsonValue::as_str)
        .filter(|build| !build.is_empty())
        .map(str::to_owned);
    let Some(JsonValue::Object(usage)) = body.get_mut("usage") else {
        return;
    };
    if usage.contains_key(CACHE_CALLS_KEY) {
        return;
    }
    let input = usage.get("prompt_tokens").and_then(JsonValue::as_u64);
    let standard = usage
        .get("prompt_tokens_details")
        .and_then(|details| count(details, "cached_tokens"));
    let (read, counter_source) = match standard {
        Some(standard) if standard == cache_n => (Some(standard), CacheCounterSource::OpenAiUsage),
        Some(_) => (None, CacheCounterSource::OpenAiUsage),
        None => (Some(cache_n), CacheCounterSource::LlamaTimings),
    };
    let pass = CachePassUsage::from(CachePassReport {
        phase: CachePhase::Prompt,
        counter_source,
        input_tokens: input,
        cache_read_tokens: read,
        computed_input_tokens: Some(computed),
        cached_pages: None,
        prefill_us,
        generate_us,
    });
    let call = CacheCallUsage {
        backend: CacheBackend::LlamaCpp,
        identity: chat_identity(answering, fingerprint.as_deref()),
        logical_prompt_tokens: input,
        passes: vec![pass],
    };
    if let Some(fingerprint) = fingerprint {
        usage
            .entry(SYSTEM_FINGERPRINT_KEY)
            .or_insert(JsonValue::String(fingerprint));
    }
    if let Ok(record) = serde_json::to_value(&call) {
        usage.insert(CACHE_CALLS_KEY.to_owned(), JsonValue::Array(vec![record]));
    }
}

/// A chat record's identity: what the answer's own alias names, with the
/// reported build's digest as its runtime when no manifest names one.
fn chat_identity(answering: Option<&AnsweringIdentity>, fingerprint: Option<&str>) -> CacheIdentity {
    let mut identity = answering
        .map(AnsweringIdentity::for_chat)
        .unwrap_or_default();
    if identity.runtime.is_none() {
        identity.runtime = fingerprint.and_then(digest);
    }
    identity
}

/// One native decision-read answer's cache read and raw usage: its `timings`
/// as it came, beside its record (`tokens_evaluated` in, `timings.cache_n`
/// read from the cache, `timings.prompt_n` computed). The read is the
/// record's when its counts agree, else 0, as the standard counter always
/// read it; the record keeps the read unknown. The identity is what
/// `answering`, the answer's own alias, names: never a chat template, which
/// a native prompt does not go through.
pub(super) fn label_read(
    answer: &JsonValue,
    answering: Option<&AnsweringIdentity>,
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
    let call = CacheCallUsage {
        backend: CacheBackend::LlamaCpp,
        identity: answering
            .map(AnsweringIdentity::for_native)
            .unwrap_or_default(),
        logical_prompt_tokens: input,
        passes: vec![pass],
    };
    let mut usage = timings.map_or_else(|| json!({}), |timings| json!({ "timings": timings }));
    put_cache_calls(
        &mut usage,
        serde_json::to_value(&call).into_iter().collect(),
    );
    (read, usage)
}

/// Moves the cache records out of the usage object `usage`, for an aggregate
/// that lists every attempt's records once, at its own top.
pub(super) fn take_cache_calls(usage: &mut JsonValue) -> Vec<JsonValue> {
    match usage
        .as_object_mut()
        .and_then(|usage| usage.remove(CACHE_CALLS_KEY))
    {
        Some(JsonValue::Array(records)) => records,
        _ => Vec::new(),
    }
}

/// Appends `records` to the list under [`CACHE_CALLS_KEY`] in the usage
/// object `usage`. A usage that is not an object is left as it came.
pub(super) fn put_cache_calls(usage: &mut JsonValue, records: Vec<JsonValue>) {
    if records.is_empty() {
        return;
    }
    let Some(usage) = usage.as_object_mut() else {
        return;
    };
    if let JsonValue::Array(list) = usage
        .entry(CACHE_CALLS_KEY)
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
