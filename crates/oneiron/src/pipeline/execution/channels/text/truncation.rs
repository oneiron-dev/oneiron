//! Scope and result limits for widened text searches.

use super::super::turn_fold;
use crate::error::Result;
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::channels::truncate_widened_channel_results_to_scope;
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PER_SCAN_CAP_FACTOR, PipelineFilterConfig,
    ScoredEntity, TurnFold,
};
use heed::RoTxn;

impl PipelineBuilder<'_> {
    /// Keeps the rows of a widened text read that the run's own scope
    /// admits, up to `requested` results. A run that folds each MESSAGE into
    /// its TURN counts results as the fold leaves them, as the unwidened
    /// bound does ([`turn_fold::rows_holding_distinct_turns`]): several
    /// messages of one turn are one result, so they cannot crowd the next
    /// turn out. Like the unwidened read, it looks no further than
    /// `PER_SCAN_CAP_FACTOR` times the bound. The cut takes the call's
    /// `made_by` slice; the fold's turn count judges each TURN by the run's
    /// shared scope, as the fold itself does.
    pub(super) fn truncate_widened_text_results(
        &self,
        rows: &mut Vec<ScoredEntity>,
        rtxn: &RoTxn<'_>,
        requested: usize,
        filter_config: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<()> {
        let kept = if self.turn_fold == TurnFold::Off {
            requested
        } else {
            requested.saturating_mul(PER_SCAN_CAP_FACTOR)
        };
        truncate_widened_channel_results_to_scope(
            rows,
            &self.read,
            rtxn,
            kept,
            self.bounded_result_filters(filter_config),
            metadata_cache,
            claim_gate,
        )?;
        if self.turn_fold != TurnFold::Off
            && let Some(held) = turn_fold::rows_holding_distinct_turns(
                rows,
                requested,
                self.turn_fold,
                &self.read,
                rtxn,
                filter_config,
                metadata_cache,
                claim_gate,
            )?
        {
            rows.truncate(held);
        }
        Ok(())
    }
}
