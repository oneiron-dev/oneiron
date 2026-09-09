//! The admit step every channel shares: signal components, the optional trace record, and the ranked-list push.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::trace::{
    add_signal_score_components, filter_retrieval_trace_scores, retrieval_trace_channel_record,
};
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, ScoredEntity,
};
use crate::store::{RetrievalScoreComponent, RetrievalSignal, RetrievalTraceChannelRecord, Store};
use heed::RoTxn;
use std::collections::HashMap;

/// What the channel fan-out accumulates per admitted ranked list: the lists
/// themselves, the per-signal score components, and the trace faces when the
/// run captures a retrieval trace. Holds no store handle and no run cache:
/// the read transaction and the metadata cache are passed to every call.
pub(super) struct ChannelAccumulator {
    pub(super) ranked_lists: Vec<Vec<ScoredEntity>>,
    pub(super) signal_components: HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    pub(super) trace_channels: Vec<RetrievalTraceChannelRecord>,
    pub(super) trace_ranked_lists: Vec<Vec<ScoredEntity>>,
    pub(super) trace_claim_gate: ClaimStatusGateCache,
    pub(super) capture: bool,
    pub(super) trace_candidate_limit: usize,
}

/// The signal a channel's results are recorded under. The score components
/// and the trace record usually share one; the HyDE retry contributes `Text`
/// components while its trace record says `HydeRetry`.
#[derive(Clone, Copy)]
pub(super) struct AdmitSignal {
    pub(super) components: RetrievalSignal,
    pub(super) trace: RetrievalSignal,
}

impl From<RetrievalSignal> for AdmitSignal {
    fn from(signal: RetrievalSignal) -> Self {
        Self {
            components: signal,
            trace: signal,
        }
    }
}

impl ChannelAccumulator {
    pub(super) fn new(capture: bool, trace_candidate_limit: usize, include_stale: bool) -> Self {
        Self {
            ranked_lists: Vec::new(),
            signal_components: HashMap::new(),
            trace_channels: Vec::new(),
            trace_ranked_lists: Vec::new(),
            trace_claim_gate: ClaimStatusGateCache {
                include_stale,
                ..ClaimStatusGateCache::default()
            },
            capture,
            trace_candidate_limit,
        }
    }

    /// Admits one channel's results and returns the index the list took in
    /// `ranked_lists`.
    pub(super) fn admit_channel(
        &mut self,
        signal: impl Into<AdmitSignal>,
        results: Vec<ScoredEntity>,
        store: &Store,
        rtxn: &RoTxn<'_>,
        filter_config: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
    ) -> Result<usize> {
        let signal = signal.into();
        add_signal_score_components(&mut self.signal_components, signal.components, &results);
        if self.capture {
            let trace_results = filter_retrieval_trace_scores(
                &results,
                store,
                rtxn,
                filter_config,
                metadata_cache,
                &mut self.trace_claim_gate,
                self.trace_candidate_limit,
            )?;
            self.trace_channels.push(retrieval_trace_channel_record(
                signal.trace,
                &trace_results,
                self.trace_candidate_limit,
            ));
            self.trace_ranked_lists.push(trace_results);
        }
        let index = self.ranked_lists.len();
        self.ranked_lists.push(results);
        Ok(index)
    }
}
