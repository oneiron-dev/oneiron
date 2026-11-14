//! Moved from `crates/oneiron/src/llm/run_admission/receipt.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::LlmInputUsage;
use oneiron_model::llm::LlmOutputUsage;
use oneiron_model::llm::ModelId;
use serde::Serialize;
use std::sync::Mutex;

/// One metered stream's audio: the milliseconds it admitted and the bound
/// its permit reserved for. Admitted audio is what the stream sent, not what
/// the provider billed or the person heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RunStreamUsage {
    pub admitted_ms: u64,
    pub bound_ms: u64,
}

/// One answered call's normalized billing counters, which can contain default
/// zeros. Provider measurement presence is recorded separately. Cache passes
/// and identity remain on the settlement's `inference_calls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunTokenUsage {
    pub input: LlmInputUsage,
    pub output: LlmOutputUsage,
    /// Parse-time provider measurements, independent of normalized counters
    /// and budget charges. No complete physical-call or scope coverage implied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_token_measurement: Option<super::super::ProviderTokenMeasurement>,
}

/// What a settled call ran past its reservation (FIX 11481), in the
/// run line's units as `units` is: the settled figure — the provider's
/// report or the host/caller's own count, per `source` — against what the
/// permit reserved. On the settlement only when the settled figure ran
/// past the reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RunUsageOverage {
    /// What the call settled at, as charged.
    pub reported_units: u64,
    /// What the permit reserved.
    pub reserved_units: u64,
    /// `reported_units - reserved_units`.
    pub overage_units: u64,
    /// Where the reported figure came from.
    pub source: RunOverageSource,
}

/// Where a settled overage's reported figure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOverageSource {
    /// The provider's own usage report for the call.
    ProviderReported,
    /// The host/caller's own count for the call (bytes, audio, fixed
    /// units, requested length), at its row's rates.
    Counted,
}

/// The declared teachers next to the teachers called.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TeacherReport {
    pub declared: Vec<ModelId>,
    pub called: Vec<CalledTeacher>,
}

/// One dispatched model call of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CalledTeacher {
    pub model: ModelId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub served_model: Option<String>,
    pub request_digest: String,
    pub lease: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_units: Option<u64>,
}
