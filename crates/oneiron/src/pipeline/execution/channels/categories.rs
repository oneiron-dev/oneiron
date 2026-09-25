//! Independent memory, skill and agent budgets on one retrieval snapshot.

use super::super::super::capabilities::{CapabilityLane, PER_KIND_CAPABILITY_LIMIT};
use super::super::types::RetrievalTxnOutput;
use super::{PipelineBuilder, SnapshotInputs};
use crate::Result;

impl PipelineBuilder<'_> {
    pub(super) fn collect_pack_categories(
        &self,
        rtxn: &heed::RoTxn<'_>,
        inputs: SnapshotInputs<'_>,
    ) -> Result<RetrievalTxnOutput> {
        let mut memory = None;
        let mut capabilities = Vec::new();
        for lane in [
            CapabilityLane::Memory,
            CapabilityLane::Skill,
            CapabilityLane::Agent,
        ] {
            let original = self.candidate_filter;
            let predicate =
                |store: &crate::store::Store, txn: &heed::RoTxn<'_>, id: &crate::EntityId| {
                    if let Some(filter) = original
                        && !filter(store, txn, id)?
                    {
                        return Ok(false);
                    }
                    lane.admits(store, txn, id)
                };
            let mut query = self.clone();
            if lane == CapabilityLane::Memory {
                // Do not turn an ordinary memory query into an authority-scoped
                // query. That moves user filters and D19 before fusion, loses
                // suppression counts, and decodes admitted CLAIMs twice.
                query.memory_category = true;
            } else {
                query.candidate_filter = Some(&predicate);
                query.result_limit = PER_KIND_CAPABILITY_LIMIT;
                if let Some((_, limit)) = &mut query.text_search
                    && *limit > 0
                {
                    *limit = PER_KIND_CAPABILITY_LIMIT;
                }
                if let Some((_, limit)) = &mut query.vector_search
                    && *limit > 0
                {
                    *limit = PER_KIND_CAPABILITY_LIMIT;
                }
                if let Some(config) = &mut query.temporal_search
                    && config.limit > 0
                {
                    config.limit = PER_KIND_CAPABILITY_LIMIT;
                }
                // Capability discovery does not seed or spend memory expansion.
                query.ppr_expand = None;
                query.capture_retrieval_trace = false;
            }
            let output = query.run_retrieval_snapshot(rtxn, inputs)?;
            if lane == CapabilityLane::Memory {
                memory = Some(output);
            } else {
                capabilities.extend(output.capabilities);
            }
        }
        let mut output = memory.ok_or(crate::Error::InvariantViolation(
            "memory category not collected",
        ))?;
        output.capabilities = capabilities;
        output.early_empty_no_telemetry &= output.capabilities.is_empty();
        Ok(output)
    }
}
