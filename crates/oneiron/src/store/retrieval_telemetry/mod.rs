//! Retrieval telemetry: run records, trace fork index, outcome rows, and
//! reward-weighted blend-weight tuning. This file also carries the
//! session-side [`SessionStoreView`] retrieval siblings.

mod blend_tuning;
mod run_store;
mod types;

pub(crate) use self::run_store::RETRIEVAL_RUN_KEY_PREFIX;
pub(in crate::store) use self::run_store::RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT;
// Test-only seam (open_gates/mod.rs precedent): the store test suite names
// these bare through `use super::*`, but no non-test code outside
// `retrieval_telemetry/` reaches them through the seam, so the re-exports
// live under `cfg(test)`.
#[cfg(test)]
pub(in crate::store) use self::blend_tuning::{
    RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, apply_retrieval_blend_weight_update,
};
#[cfg(test)]
pub(in crate::store) use self::run_store::{
    decode_retrieval_run, encode_retrieval_run, retrieval_outcome_key, retrieval_run_key,
    retrieval_trace_fork_key,
};
pub(crate) use self::types::RetrievalRunFinalize;
#[cfg(test)]
pub(in crate::store) use self::types::{
    RETRIEVAL_BLEND_TUNER_ALGORITHM, RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
};
pub use self::types::{
    RetrievalAction, RetrievalBlendSignal, RetrievalBlendTuningConfig,
    RetrievalBlendWeightDataWindow, RetrievalBlendWeightTableEntry, RetrievalBlendWeights,
    RetrievalOutcome, RetrievalOutcomeRecord, RetrievalRunId, RetrievalRunRecord,
    RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal, RetrievalTrace,
    RetrievalTraceChannelRecord, RetrievalTraceForkHash, RetrievalTraceStage,
    RetrievalTraceStageRecord,
};
