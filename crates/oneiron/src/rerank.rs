//! RET-010 host-injected top-N rerank seam (1186-D1/D2).
//!
//! The reranker implementation lives app-side; the engine owns only the
//! seam: the trait, the per-run knobs, and the pipeline call site
//! ([`crate::pipeline::PipelineBuilder::rerank`]). The engine never runs a
//! model and pins no default reranker (1186-D2 defers the model pin; the
//! multilingual candidate is the OneiroNER bake-off's output).

use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Default candidate-block size handed to the reranker (1186-D2 board
/// example; BEAM sweeps 30 vs 50 via `RerankOptions::top_n`).
pub const RERANK_TOP_N_DEFAULT: usize = 30;

/// One blended candidate offered to a host-injected reranker.
pub struct RerankCandidate<'a> {
    pub id: EntityId,
    /// Engine blended score (post linear-in-log blend, post filters).
    pub score: f32,
    /// 1-based engine rank within the rerank block.
    pub rank: u32,
    /// Decoded claim body when the candidate is a live CLAIM that passed the
    /// D19 gate (borrowed from the pipeline's gate cache). `None` for
    /// non-claim entities.
    pub claim: Option<&'a ClaimBody>,
}

/// Host-injected top-N reranker (1186-D1/D2: impl app-side, seam
/// engine-side).
pub trait Reranker: Send + Sync {
    /// Stable identifier for the underlying scorer (e.g. `org/name@revision`).
    /// Hashed into the RetrievalTrace fork-hash so BEAM forks distinguish
    /// rerank configurations. Free-form; the engine validates nothing here
    /// (the model pin is deferred by design).
    fn id(&self) -> &str;

    /// Returns one score per candidate, same order and length as
    /// `candidates`. Higher = more relevant. Scores are recorded raw in
    /// telemetry/trace; they never leak into
    /// [`crate::pipeline::ScoredEntity::score`] (score-ladder reassignment
    /// keeps engine scale downstream).
    ///
    /// Called under the pipeline's read transaction — the impl must not
    /// block (no network hops, no queued-batch inference waits): host trait
    /// impls invoked under a held txn/lock must be non-blocking cached
    /// lookups; hosts run arbitrary inference in the async phases the
    /// engine exposes for it. A slow impl here pins LMDB free-page
    /// reclamation for the duration of the call.
    fn rerank(&self, query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>>;
}

/// Per-run rerank knobs (the 1186-D2 "N knob").
pub struct RerankOptions {
    /// Blended candidates offered to the reranker, from the top.
    pub top_n: usize,
    /// Query text override. When `None`, the pipeline's `search_text` query
    /// is used; if neither exists the run fails closed with
    /// [`crate::Error::InvalidConfig`].
    pub query: Option<String>,
}

impl Default for RerankOptions {
    fn default() -> Self {
        Self {
            top_n: RERANK_TOP_N_DEFAULT,
            query: None,
        }
    }
}

#[cfg(test)]
mod tests;
