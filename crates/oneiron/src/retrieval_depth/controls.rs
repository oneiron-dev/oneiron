//! Per-request retrieval deadlines: stage boundaries, in-stage checkpoints and
//! the share of the budget the answer keeps.
use crate::rerank::Reranker;
use crate::store::embedding::InputKind;

pub use crate::store::retrieval_deadline::RetrievalDeadline;
#[cfg(any(test, feature = "test-hooks"))]
pub use crate::store::retrieval_deadline::{SlowRetrievalStage, still_deadline_clock_for_test};

/// One query vector in a declared embedding space: recall searches that
/// space's list with it, for every kind of item the space holds (OF-370; on
/// the one-space preset the text query enters the text slot's space here).
#[derive(Debug, Clone, Copy)]
pub struct RecallMediaSeed<'a> {
    pub space: &'a str,
    /// The kind of query the vector encodes.
    pub kind: InputKind,
    pub vector: &'a [f32],
    /// Stored input kinds to keep; empty keeps every kind in this space.
    pub kinds: &'a [InputKind],
}

/// What a recall door's host embedded the query into: the vault's own text
/// index, and declared spaces.
#[derive(Debug, Clone, Default)]
pub struct RecallQueryVectors {
    pub text_index: Option<Vec<f32>>,
    /// Space id, query kind, vector and stored-input-kind narrowing.
    pub media: Vec<(String, InputKind, Vec<f32>, Vec<InputKind>)>,
}

impl RecallQueryVectors {
    /// The declared-space vectors as [`RecallExecution::media`] seeds.
    #[must_use]
    pub fn media_seeds(&self) -> Vec<RecallMediaSeed<'_>> {
        self.media
            .iter()
            .map(|(space, kind, vector, kinds)| RecallMediaSeed {
                space,
                kind: *kind,
                vector,
                kinds,
            })
            .collect()
    }
}

/// Additional execution inputs for the regular memory recall pipeline.
/// No implicit embedding or model is invented when a host supplies neither.
#[derive(Default)]
pub struct RecallExecution<'a> {
    /// Explicit host-injected expansion; free efforts never consume it.
    pub hyde: Option<crate::query_expansion::HydeBinding<'a>>,
    pub deadline: Option<&'a RetrievalDeadline>,
    pub reranker: Option<&'a dyn Reranker>,
    pub embedding: Option<&'a [f32]>,
    /// Query vectors in declared embedding spaces, each searched as its
    /// space's list beside the text index's.
    pub media: &'a [RecallMediaSeed<'a>],
    pub phonetic_codes: &'a [&'a str],
    /// Unix seconds the query's time words resolve against (`yesterday`
    /// is the day before it), and the clock recency ages from. `None` is now.
    pub as_of: Option<u64>,
    /// The affect the query is asked in (OF-423): emotion congruence scales
    /// each candidate's final score by it, as on the context pack. Every
    /// pass of one recall carries the same one, so its passes rank alike.
    pub query_affect: Option<oneiron_contracts::affect::Vad>,
    /// Receives the pack this recall answers with if its door stops waiting
    /// at the deadline during the scope census: the assembled items, marked
    /// partial. The door itself published the empty pack it answers with
    /// before then ([`crate::task_verb::sdk::RecallDoor`]).
    pub on_cut: Option<&'a (dyn Fn(crate::memory::MemoryPack) + Sync)>,
    /// That empty pack. Its door answers with it, or with a later one
    /// `on_cut` received, once the deadline comes; past the deadline the
    /// recall stops at its next check and returns it.
    pub door_fallback: Option<&'a crate::memory::MemoryPack>,
    /// The host serves no reranker: high, xhigh and max run their expansion
    /// without the rerank stage and need no lease, and their door says so in
    /// the pack ([`crate::memory::RecallRerank::Unavailable`]).
    pub rerank_unavailable: bool,
    /// The caller's opt-in stage capture and exact turn linkage.
    pub telemetry: Option<&'a RecallTelemetry>,
    /// The token budget the pack is assembled and rendered under, as its
    /// door resolved it (FIX 9962); `None` is the 4,000-token default.
    pub render_budget: Option<usize>,
}

use crate::store::RetrievalTurn;
use serde::{Deserialize, Serialize};

/// Opt-in stage capture and the actual host turn whose retrieval is being observed.
/// The vault's capture setting remains authoritative; this cannot turn it on.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecallTelemetry {
    #[serde(default)]
    pub capture_trace: bool,
    #[serde(default)]
    pub turn: Option<RetrievalTurn>,
}
