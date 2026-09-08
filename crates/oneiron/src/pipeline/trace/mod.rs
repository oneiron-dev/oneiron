//! Retrieval trace recording and deterministic replay fork-hashing.

// `filter_retrieval_trace_scores` below names the sibling through `super::`,
// so the parent re-imports it (same pattern as `execution/mod.rs`).
use super::authority;

mod trace_fork_hash;
mod trace_records;

pub(super) use self::trace_fork_hash::{RetrievalTraceForkEvidence, retrieval_trace_fork_hash};
pub(super) use self::trace_records::{
    add_signal_score_components, filter_retrieval_trace_scores, merge_retrieval_diagnostics,
    record_ppr_cache_outcome, retrieval_trace_candidate_set, retrieval_trace_channel_record,
    retrieval_trace_fused_scores, retrieval_trace_stage_record, retrieval_trace_top_scores,
    telemetry_score_breakdown,
};
