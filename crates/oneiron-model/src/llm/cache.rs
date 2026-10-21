//! What a backend reported about its prompt cache on one physical model call
//! (FIX 6567, INF 2 step 1): for each pass over the input, how many tokens it
//! read, how many of them came from its cache and how many it computed, and
//! the identity of what answered, as digests and the backend's own epoch.
//!
//! A record holds counts, closed enums and fixed-width hex only: never prompt
//! text, a path, a provider's free string or raw provider JSON, so a receipt
//! may log it. A count the backend did not report is absent, never zero, and
//! an identity no backend source names stays absent: nothing here is a guess.
//!
//! A backend's usage object carries these as the identity and passes of its
//! inference receipts (FIX 8314, [`super::InferenceCallReceipt`]), the one
//! carrier; [`LlmUsage::cache_calls`] is their cache-only view.
use serde::{Deserialize, Serialize};

use super::{LlmUsage, WorkerKind};

/// One physical call's cache evidence: one native request the backend ran,
/// its identity and each pass it made over the input, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheCallUsage {
    pub backend: CacheBackend,
    #[serde(default, skip_serializing_if = "CacheIdentity::is_empty")]
    pub identity: CacheIdentity,
    /// The request's own prompt, in tokens, as the backend counted it before
    /// any pass re-encoded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_prompt_tokens: Option<u64>,
    pub passes: Vec<CachePassUsage>,
}

/// The backend that ran a call, named by what its reply carries: the EXL3
/// server's own record, or llama.cpp's native timings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheBackend {
    LlamaCpp,
    Exl3,
}

/// What answered, as the backend reported it. Each digest is of what the
/// backend loaded or ran with (its bytes or its settings), never a label the
/// engine configured: a configured revision or a served model name is not
/// one. A runtime digest of a reported version string is reported identity,
/// not a check of the binaries. A field no backend source names is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheIdentity {
    /// The loaded weights.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<CacheDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer: Option<CacheDigest>,
    /// The backend's implementation and build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<CacheDigest>,
    /// The chat template's bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<CacheDigest>,
    /// The effective template arguments and execution settings of the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_mode: Option<CacheDigest>,
    /// The cache's own settings: its layout, quantization and sizes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_mode: Option<CacheDigest>,
    /// The incarnation of the backend's cache owner that answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_epoch: Option<CacheEpoch>,
}

impl CacheIdentity {
    /// True when the backend named no identity at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A SHA-256 digest as 64 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CacheDigest(String);

impl CacheDigest {
    /// A digest from its hex form.
    pub fn new(hex: impl Into<String>) -> Result<Self, CacheEvidenceError> {
        let hex = hex.into();
        if lower_hex(&hex, 64) {
            Ok(Self(hex))
        } else {
            Err(CacheEvidenceError::Digest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CacheDigest {
    type Error = CacheEvidenceError;

    fn try_from(hex: String) -> Result<Self, Self::Error> {
        Self::new(hex)
    }
}

impl From<CacheDigest> for String {
    fn from(digest: CacheDigest) -> Self {
        digest.0
    }
}

/// One incarnation of a backend's cache owner (EXL3: its Generator), minted
/// once when it is built: 32 lowercase hex digits. It names neither the
/// machine's boot, a run, a model revision nor a request; a restart or a
/// rebuilt cache owner is a new epoch.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CacheEpoch(String);

impl CacheEpoch {
    /// An epoch from its hex form.
    pub fn new(hex: impl Into<String>) -> Result<Self, CacheEvidenceError> {
        let hex = hex.into();
        if lower_hex(&hex, 32) {
            Ok(Self(hex))
        } else {
            Err(CacheEvidenceError::Epoch)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CacheEpoch {
    type Error = CacheEvidenceError;

    fn try_from(hex: String) -> Result<Self, Self::Error> {
        Self::new(hex)
    }
}

impl From<CacheEpoch> for String {
    fn from(epoch: CacheEpoch) -> Self {
        epoch.0
    }
}

/// A digest or epoch that is not the fixed hex form its type names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CacheEvidenceError {
    #[error("a cache digest is 64 lowercase hex digits")]
    Digest,
    #[error("a backend epoch is 32 lowercase hex digits")]
    Epoch,
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Which pass over the input a count is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePhase {
    /// The one pass over the request's own prompt.
    Prompt,
    /// A thinking pass over the request's own prompt.
    Reasoning,
    /// An answer pass over the prompt with its thought closed, re-encoded.
    Answer,
    /// One answer of a native decision read.
    LabelRead,
}

/// Where a pass's cache-read count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CacheCounterSource {
    /// The reply's `usage.prompt_tokens_details.cached_tokens`.
    #[serde(rename = "openai_usage")]
    OpenAiUsage,
    /// llama.cpp's native `timings` (`cache_n`, `prompt_n`).
    #[serde(rename = "llama_timings")]
    LlamaTimings,
    /// An exllamav3 Job's final event.
    #[serde(rename = "exl3_job")]
    Exl3Job,
}

/// What a pass's counts show. `Unknown` when a count is missing or the
/// counts contradict each other: never a guessed hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheOutcome {
    /// Some of the input was read from the cache.
    Hit,
    /// None of it was: the whole input was computed.
    Recompute,
    Unknown,
}

/// One pass over the input, with its outcome read from its counts. Times are
/// whole microseconds of the backend's own per-pass intervals, which contain
/// other requests' work when several run at once: never exclusive GPU time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "CachePassReport")]
pub struct CachePassUsage {
    pub phase: CachePhase,
    /// The tokens the pass took as input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    /// The input tokens it read from the cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<u64>,
    /// The input tokens it computed: logical input work, input less cache
    /// read, not a count of the tensors a kernel saw.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_input_tokens: Option<u64>,
    /// The whole cache pages read, when the backend counts pages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_pages: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefill_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generate_us: Option<u64>,
    pub counter_source: CacheCounterSource,
    pub outcome: CacheOutcome,
}

/// One pass as its backend reports it, before its outcome is read. A record
/// read back from a usage object goes through here too, so an outcome a
/// backend wrote is never taken on its word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct CachePassReport {
    pub phase: CachePhase,
    pub counter_source: CacheCounterSource,
    #[serde(default)]
    pub input_tokens: Option<u64>,
    #[serde(default)]
    pub cache_read_tokens: Option<u64>,
    #[serde(default)]
    pub computed_input_tokens: Option<u64>,
    #[serde(default)]
    pub cached_pages: Option<u64>,
    #[serde(default)]
    pub prefill_us: Option<u64>,
    #[serde(default)]
    pub generate_us: Option<u64>,
}

impl From<CachePassReport> for CachePassUsage {
    /// The outcome is a hit or a recompute only when the input and the cache
    /// read are both reported, the read is no more than the input, and a
    /// reported computed count is the input less the read; the computed count
    /// is that difference when the backend gave none. Anything else is
    /// unknown, with the counts kept as reported.
    fn from(report: CachePassReport) -> Self {
        let (computed, outcome) = match (report.input_tokens, report.cache_read_tokens) {
            (Some(input), Some(read)) if read <= input => {
                let derived = input - read;
                match report.computed_input_tokens {
                    Some(computed) if computed != derived => {
                        (Some(computed), CacheOutcome::Unknown)
                    }
                    _ if read > 0 => (Some(derived), CacheOutcome::Hit),
                    _ => (Some(derived), CacheOutcome::Recompute),
                }
            }
            _ => (report.computed_input_tokens, CacheOutcome::Unknown),
        };
        Self {
            phase: report.phase,
            input_tokens: report.input_tokens,
            cache_read_tokens: report.cache_read_tokens,
            computed_input_tokens: computed,
            cached_pages: report.cached_pages,
            prefill_us: report.prefill_us,
            generate_us: report.generate_us,
            counter_source: report.counter_source,
            outcome,
        }
    }
}

impl CachePassUsage {
    /// The tokens read from the cache, when the counts show them: `None` for
    /// an unknown outcome.
    #[must_use]
    pub fn measured_read(&self) -> Option<u64> {
        match self.outcome {
            CacheOutcome::Hit | CacheOutcome::Recompute => self.cache_read_tokens,
            CacheOutcome::Unknown => None,
        }
    }
}

impl LlmUsage {
    /// The cache records the backend reported for this call: the llama.cpp
    /// and EXL3 receipts of [`LlmUsage::inference_calls`] that hold native
    /// passes, each as its backend, identity, prompt and passes. A receipt
    /// with no pass is no cache evidence and is left out. Empty when the
    /// backend reported none.
    #[must_use]
    pub fn cache_calls(&self) -> Vec<CacheCallUsage> {
        self.inference_calls()
            .into_iter()
            .filter(|call| !call.passes.is_empty())
            .filter_map(|call| {
                let backend = match call.worker.kind {
                    WorkerKind::LlamaCpp => CacheBackend::LlamaCpp,
                    WorkerKind::Exl3 => CacheBackend::Exl3,
                    _ => return None,
                };
                Some(CacheCallUsage {
                    backend,
                    identity: call.worker.identity,
                    logical_prompt_tokens: call.logical_prompt_tokens,
                    passes: call.passes,
                })
            })
            .collect()
    }
}
